using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Alerts;
using SapAV.Engine.Pipe;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;
using SapAV.Core.Alerts;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>
/// Section B across steps (B2 + B3 + B4 + B5): a pipe client drives a scan job whose files are parsed by the real scan
/// worker (the real broker and worker exe), judged by the real verdict handler (alert dispatcher into a fake sink,
/// auto-quarantine into the real quarantine manager), and the client reads the results, lists the quarantine and restores.
/// Only the "malware" is synthetic: a marker string that a test YARA rule flags (never EICAR, never a real sample).
/// </summary>
public sealed class PipeEndToEndTests(AppContainerFixture fixture) : IClassFixture<AppContainerFixture>
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static byte[] MarkerContent(int seed) =>
        [.. System.Text.Encoding.ASCII.GetBytes("sapav-b5-marker"), .. new Random(seed).GetItems("abcdefghij"u8.ToArray(), 200)];

    [Fact]
    public async Task Unsandboxed_ClientScans_MaliciousIsQuarantined_ClientListsAndRestoresIt()
    {
        await using var engine = new RealEngine(container: null);
        await RunFullFlowAsync(engine);
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task AppContainer_ClientScans_MaliciousIsQuarantined_ClientListsAndRestoresIt()
    {
        await using var engine = new RealEngine(fixture.Container);
        await RunFullFlowAsync(engine);

        Assert.Equal(SandboxMode.AppContainer, engine.Broker.Status.Mode);
    }

    private static async Task RunFullFlowAsync(RealEngine engine)
    {
        var dropper = engine.Quarantine.WriteFile("dropper.bin", MarkerContent(1));
        var notes = engine.Quarantine.WriteFile("notes.txt", "plain notes"u8.ToArray());
        var before = File.ReadAllBytes(dropper);
        var stamp = File.GetLastWriteTimeUtc(dropper);
        var client = await engine.ConnectAsync(new FakeClientIdentity()); // a standard user with this process's real access

        var created = await client.CreateScanAsync([engine.Quarantine.Files], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        await client.StartScanAsync(created.JobId, Timeout());
        await engine.ReadUntilAsync(client, JobState.Completed);
        Assert.True(engine.Dispatcher.Drain(TimeSpan.FromSeconds(30)));

        var details = await client.GetScanAsync(created.JobId, cancellationToken: Timeout());
        var bad = Assert.Single(details.Results); // clean files are only counted, not listed
        Assert.Equal((Verdict.Malicious, FileAction.Quarantined), (bad.Verdict, bad.Action));
        Assert.Equal(1, details.Progress.Counters.Clean);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(before)), bad.Sha256);
        Assert.False(File.Exists(dropper));
        Assert.True(File.Exists(notes));
        Assert.Equal(1, details.Progress.Counters.Quarantined);

        // The alert dispatcher got exactly one alert for it, tied to the result and to the quarantine item.
        var alert = Assert.Single(engine.Sink.Alerts);
        Assert.Equal((AlertType.MaliciousFile, AlertAction.Quarantined), (alert.Type, alert.Action));
        Assert.Equal(bad.AlertId, alert.AlertId);

        var item = Assert.Single((await client.ListQuarantineAsync(Timeout())).Items);
        Assert.Equal(bad.QuarantineItemId, item.Id);
        Assert.Equal(bad.Sha256, item.Sha256);
        Assert.Equal(bad.AlertId, item.AlertId);
        Assert.Equal(Path.GetFullPath(dropper), Path.GetFullPath(item.OriginalPath!.Value), ignoreCase: true);

        var restored = await client.RestoreAsync(item.Id, Timeout());

        Assert.Equal(RestoreOutcome.Restored, restored.Status);
        Assert.Equal(before, File.ReadAllBytes(dropper));
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(dropper));
    }

    [Fact]
    public async Task PauseResume_ThroughThePipe_StopsAtTheCurrentFile_ThenFinishesTheJob()
    {
        await using var engine = new RealEngine(container: null);
        for (int i = 0; i < 3; i++)
        {
            engine.Quarantine.WriteFile($"mal{i}.bin", MarkerContent(i));
        }

        var client = await engine.ConnectAsync(new FakeClientIdentity());
        var created = await client.CreateScanAsync([engine.Quarantine.Files], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        engine.Gate.Arm();
        await client.StartScanAsync(created.JobId, Timeout());
        await engine.Gate.Reached.WaitAsync(TimeSpan.FromSeconds(60)); // the first file is in flight

        var paused = await client.PauseScanAsync(created.JobId, Timeout());
        engine.Gate.Open();
        await engine.ReadUntilAsync(client, JobState.Paused);
        var whilePaused = await client.GetScanAsync(created.JobId, cancellationToken: Timeout());
        var resumed = await client.ResumeScanAsync(created.JobId, Timeout());
        await engine.ReadUntilAsync(client, JobState.Completed);
        var done = await client.GetScanAsync(created.JobId, cancellationToken: Timeout());

        Assert.Contains(paused.State, new[] { JobState.Pausing, JobState.Paused });
        Assert.Equal(1, whilePaused.Progress.FilesDone); // the in-flight file finished, nothing after it started
        Assert.Single(whilePaused.Results);
        Assert.Contains(resumed.State, new[] { JobState.Running, JobState.Completed });
        Assert.Equal(3, done.Progress.FilesDone);
        Assert.Equal(3, done.Progress.Counters.Quarantined);
        Assert.Equal(3, (await client.ListQuarantineAsync(Timeout())).Items.Count);
    }

    [Fact]
    public async Task Cancel_ThroughThePipe_LeavesUnscannedFilesAlone_AndEveryQuarantineHasItsAlert()
    {
        await using var engine = new RealEngine(container: null);
        var paths = Enumerable.Range(0, 4).Select(i => engine.Quarantine.WriteFile($"mal{i}.bin", MarkerContent(i))).ToArray();
        var client = await engine.ConnectAsync(new FakeClientIdentity());
        var created = await client.CreateScanAsync([engine.Quarantine.Files], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        engine.Gate.Arm();
        await client.StartScanAsync(created.JobId, Timeout());
        await engine.Gate.Reached.WaitAsync(TimeSpan.FromSeconds(60));

        var cancelling = await client.CancelScanAsync(created.JobId, Timeout());
        engine.Gate.Open();
        await engine.ReadUntilAsync(client, JobState.Cancelled);
        Assert.True(engine.Dispatcher.Drain(TimeSpan.FromSeconds(30)));
        var details = await client.GetScanAsync(created.JobId, cancellationToken: Timeout());

        Assert.Contains(cancelling.State, new[] { JobState.Cancelling, JobState.Cancelled });
        Assert.Equal(JobState.Cancelled, details.Summary.State);
        var quarantined = (await client.ListQuarantineAsync(Timeout())).Items.Count;
        Assert.InRange(quarantined, 0, 1); // at most the file that was already in flight
        Assert.Equal(paths.Length - quarantined, paths.Count(File.Exists));
        Assert.Equal(quarantined, engine.Sink.Alerts.Count(a => a.Action == AlertAction.Quarantined));
        var again = await Assert.ThrowsAsync<PipeRequestException>(() => client.CancelScanAsync(created.JobId, Timeout()));
        Assert.Equal(PipeStatus.InvalidState, again.Status);
    }

    [Fact]
    public async Task ClientDisconnectsMidJob_TheJobFinishes_AndANewConnectionSeesTheQuarantineAndAlerts()
    {
        await using var engine = new RealEngine(container: null);
        var paths = Enumerable.Range(0, 3).Select(i => engine.Quarantine.WriteFile($"mal{i}.bin", MarkerContent(i))).ToArray();
        var user = FakeClientIdentity.NewUserSid();
        var first = await engine.ConnectAsync(new FakeClientIdentity(user));
        var created = await first.CreateScanAsync([engine.Quarantine.Files], Timeout());
        await first.SubscribeAsync(created.JobId, Timeout());
        engine.Gate.Arm();
        await first.StartScanAsync(created.JobId, Timeout());
        await engine.Gate.Reached.WaitAsync(TimeSpan.FromSeconds(60));

        await first.DisposeAsync();
        await engine.WaitForNoConnectionsAsync();
        engine.Gate.Open();
        var job = engine.Jobs.Get(created.JobId)!;
        await JobWait.Done(job);
        Assert.True(engine.Dispatcher.Drain(TimeSpan.FromSeconds(30)));

        var second = await engine.ConnectAsync(new FakeClientIdentity(user));
        var details = await second.GetScanAsync(created.JobId, cancellationToken: Timeout());
        var items = (await second.ListQuarantineAsync(Timeout())).Items;

        Assert.Equal(JobState.Completed, details.Summary.State);
        Assert.Equal(3, items.Count);
        Assert.All(paths, p => Assert.False(File.Exists(p)));
        Assert.Equal(3, engine.Sink.Alerts.Count(a => a.Action == AlertAction.Quarantined));
        Assert.Equal(details.Results.Select(r => r.AlertId).Order(), engine.Sink.Alerts.Select(a => (Guid?)a.AlertId).Order());
    }

    /// <summary>Holds the first file that reaches the scanner until <see cref="Open"/> (when armed), then passes everything through.</summary>
    internal sealed class ScanGate(IScanBroker inner) : IScanBroker
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _armed;
        private int _taken;

        public Task Reached => _reachedSource.Task;

        private readonly TaskCompletionSource _reachedSource = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Arm() => Volatile.Write(ref _armed, 1);

        public void Open() => _release.TrySetResult();

        public SandboxStatus Status => inner.Status;

        public Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default) =>
            inner.ScanAsync(item, cancellationToken);

        public async Task<FileScanReport> ScanOpenedAsync(
            ScanItem item, OpenedScanFile file, IReadOnlyList<ScanNote> openNotes, CancellationToken cancellationToken = default)
        {
            if (Volatile.Read(ref _armed) == 1 && Interlocked.Exchange(ref _taken, 1) == 0)
            {
                _reachedSource.TrySetResult();
                await _release.Task.WaitAsync(TimeSpan.FromSeconds(60)).ConfigureAwait(false);
            }

            return await inner.ScanOpenedAsync(item, file, openNotes, cancellationToken).ConfigureAwait(false);
        }

        public Task<RulesLoadSummary?> ReloadRulesAsync(CancellationToken cancellationToken = default) => inner.ReloadRulesAsync(cancellationToken);
    }

    /// <summary>The real broker + worker, verdict handler, quarantine and pipe server, wired as the engine does, with a fake alert sink.</summary>
    internal sealed class RealEngine : IAsyncDisposable
    {
        private readonly List<EnginePipeClient> _clients = [];
        private readonly QueuedIdentityResolver _resolver = new();
        private readonly SandboxedScanBroker _real;
        private readonly PipeServerOptions _options = new() { PipeName = "sap-AV.engine.test." + Guid.NewGuid().ToString("N") };
        private readonly EnginePipeServer _server;

        public RealEngine(TestAppContainer? container)
        {
            Quarantine = new QuarantineTestContext();
            Dispatcher = new AlertDispatcher(Sink, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 64);
            var sandbox = container?.Options(o => o.RequestTimeout = TimeSpan.FromSeconds(60)) ?? new SandboxOptions
            {
                WorkerPath = TestAppContainer.WorkerExe,
                WorkerCount = 1,
                EnableWorkerTestHooks = true,
                Isolation = WorkerIsolation.UnsandboxedForTests,
                RequestTimeout = TimeSpan.FromSeconds(60),
                RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
                RestartBackoffMax = TimeSpan.FromMilliseconds(100),
            };
            _real = new SandboxedScanBroker(sandbox, new FakeRulesSource(ScanBrokerSupervisionTests.MarkerRule), NullLogger.Instance);
            Gate = new ScanGate(_real);
            var handler = new ScanVerdictHandler(Dispatcher, Quarantine.Manager, new AutoQuarantinePolicy([]),
                new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);
            Jobs = new ScanJobService(new ScanJobOptions { ThreadsPerJob = 1, QueueCapacity = 4 }, Gate, new FolderSet([]), handler, null,
                TimeProvider.System, NullLogger.Instance, null);
            _server = new EnginePipeServer(_options, Jobs, Quarantine.Manager, TimeProvider.System, NullLogger.Instance, _resolver,
                EnginePipeSecurity.CurrentAccount(), _ => 3 /* DRIVE_FIXED */);
            _server.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        public QuarantineTestContext Quarantine { get; }

        public RecordingAlertSink Sink { get; } = new();

        public AlertDispatcher Dispatcher { get; }

        public ScanGate Gate { get; }

        public ScanJobService Jobs { get; }

        public IScanBroker Broker => _real;

        public async Task<EnginePipeClient> ConnectAsync(IClientIdentity identity)
        {
            _resolver.Enqueue(() => identity);
            await _server.Listening.WaitAsync(TimeSpan.FromSeconds(10));
            var client = await EnginePipeClient.ConnectAsync(_options.PipeName, requireSystemServer: false, TimeSpan.FromSeconds(10), "test");
            lock (_clients)
            {
                _clients.Add(client);
            }

            return client;
        }

        public async Task ReadUntilAsync(EnginePipeClient client, JobState state)
        {
            while (true)
            {
                var e = await client.Events.ReadAsync(Timeout());
                if (e.Kind == PipeEventKind.JobState && e.Read<JobStateEvent>().To == state)
                {
                    return;
                }
            }
        }

        public async Task WaitForNoConnectionsAsync()
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
            while (_server.ActiveConnections > 0)
            {
                Assert.True(DateTime.UtcNow < deadline, "connections did not end");
                await Task.Delay(20);
            }
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                Gate.Open();
                foreach (var client in _clients)
                {
                    await client.DisposeAsync();
                }

                await _server.StopAsync(CancellationToken.None);
                _server.Dispose();
                Jobs.Dispose();
                foreach (var job in Jobs.List())
                {
                    job.Completion.Wait(TimeSpan.FromSeconds(30));
                }
            }
            finally
            {
                Dispatcher.Dispose();
                _real.Dispose(); // kills the worker
                Quarantine.Dispose();
            }
        }
    }
}
