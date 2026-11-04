using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Core.Yara;
using SapAV.Engine.Persistence;
using SapAV.Engine.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Cache;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>
/// Section C across steps (C1 + C2/C3 + C4 + C5 + C6): a pipe client drives Custom, Quick and Full Scans of one synthetic
/// profile layout through the real pipe server, the real job service, the real SQLite scan cache, the real verdict handler
/// and the real quarantine manager. Only the scan worker is the in-memory fake broker (verdict by file name:
/// <c>mal*</c> = Malicious) and the autostart collection / process list / volume list, which are fed from the test.
/// Everything lives in temp folders; nothing under %ProgramData%.
/// </summary>
public sealed class SectionCCrossStepTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private sealed class SectionCEngine : IAsyncDisposable
    {
        private readonly TempDir _cacheTemp = new();
        private readonly QueuedIdentityResolver _resolver = new();
        private readonly List<EnginePipeClient> _clients = [];
        private readonly string _pipeName = "sap-AV.engine.test." + Guid.NewGuid().ToString("N");
        private EnginePipeServer? _server;

        public SectionCEngine(TimeSpan? scanDelay = null)
        {
            Fingerprints = new FakeFingerprints();
            Cache = ScanCache.TryCreate(new ScanCacheOptions { Folder = Path.Combine(_cacheTemp.Path, "Cache") }, new FakeScanBroker(),
                new FixedKeyProvider(CacheHarness.Key), CacheHarness.Policy, TimeProvider.System, NullLogger.Instance, parentIsDataRoot: false,
                fingerprints: Fingerprints) ?? throw new InvalidOperationException("The test cache wasn't created.");
            Q.Jobs.Cache = Cache;
            Q.Jobs.Handler = new ScanVerdictHandler(Q.Alerts, Quarantine.Manager, new AutoQuarantinePolicy([]),
                new AutoQuarantineLimiter(TimeProvider.System, 50, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);
            Q.Jobs.Broker.OnScan = async (item, file, token) =>
            {
                lock (Q.Scanned)
                {
                    Q.Scanned.Add(item.Path);
                }

                if (scanDelay is { } delay)
                {
                    await Task.Delay(delay, token);
                }

                var report = FakeScanBroker.Judge(item, file, TimeProvider.System);
                return report with { Yara = YaraScanResult.Scanned([], report.Hash.Length ?? 0, FakeFingerprints.DefaultRules) };
            };
        }

        public QuickScanHarness Q { get; } = new();

        public QuarantineTestContext Quarantine { get; } = new();

        public FakeFingerprints Fingerprints { get; }

        public ScanCache Cache { get; }

        public ScanJobService Jobs => Q.Jobs.Service;

        /// <summary>Builds the factories (after the test added its autostart entries) and starts the pipe server.</summary>
        public void Start()
        {
            var quick = Q.Factory();
            var scanner = new PersistenceScanner(Q.Jobs.Broker, Q.Alerts, Q.Jobs.Time, NullLogger.Instance,
                new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" }), () => new AdminOnlyWritability());
            var full = new FullScanFactory(new FullScanOptions(), new FakeProcessSource(), Q.Collector!, scanner,
                new FakeVolumes([new DriveInfoEntry(Q.Jobs.Root, FullScanVolumes.DriveFixed, @"\\?\Volume{test-1}\", 4096)]));
            _server = new EnginePipeServer(new PipeServerOptions { PipeName = _pipeName }, Jobs, Quarantine.Manager, TimeProvider.System,
                NullLogger.Instance, _resolver, EnginePipeSecurity.CurrentAccount(), _ => 3 /* DRIVE_FIXED */, quickScan: quick, fullScan: full);
            _server.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        public async Task<EnginePipeClient> ConnectAsync(bool admin)
        {
            _resolver.Enqueue(() => new FakeClientIdentity(isAdmin: admin));
            await _server!.Listening.WaitAsync(TimeSpan.FromSeconds(10));
            var client = await EnginePipeClient.ConnectAsync(_pipeName, requireSystemServer: false, TimeSpan.FromSeconds(10), "test");
            lock (_clients)
            {
                _clients.Add(client);
            }

            return client;
        }

        public async Task<ScanJob> RunAsync(Task<ScanCreateReply> create, EnginePipeClient client)
        {
            var id = (await create).JobId;
            await client.StartScanAsync(id, Timeout());
            var job = Jobs.Get(id)!;
            await JobWait.Done(job);
            return job;
        }

        public Task<ScanJob> RunCustomAsync(EnginePipeClient client) => RunAsync(client.CreateScanAsync([Q.Profile], Timeout()), client);

        public Task<ScanJob> RunQuickAsync(EnginePipeClient client) => RunAsync(client.CreateQuickScanAsync(Timeout()), client);

        public int StoredRows => (int)Cache.Store.Count();

        public async ValueTask DisposeAsync()
        {
            foreach (var client in _clients)
            {
                await client.DisposeAsync();
            }

            if (_server is not null)
            {
                await _server.StopAsync(CancellationToken.None);
                _server.Dispose();
            }

            Jobs.Dispose();
            foreach (var job in Jobs.List())
            {
                job.Completion.Wait(TimeSpan.FromSeconds(30));
            }

            Q.Dispose();
            Cache.Dispose();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Quarantine.Dispose();
            _cacheTemp.Dispose();
        }
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "timed out waiting for the scan");
            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task QuickScan_ThroughThePipe_QuarantinesTheDownloadsMarker_AndTheRunEntryTarget_AndPagesTheFindings()
    {
        await using var e = new SectionCEngine();
        var download = e.Q.Write(@"Users\alice\Downloads\mal-dropper.exe", "dropper A");
        var clean = e.Q.Write(@"Users\alice\Downloads\setup-helper.exe", "benign");
        var targets = new[]
        {
            e.Q.Write(@"Users\alice\AppData\Roaming\evil\mal-run1.exe", "run 1"),
            e.Q.Write(@"Users\alice\AppData\Roaming\evil\mal-run2.exe", "run 2"),
            e.Q.Write(@"Users\alice\AppData\Roaming\evil\mal-run3.exe", "run 3"),
        };
        for (int i = 0; i < targets.Length; i++)
        {
            e.Q.Entries.Add(QuickScanHarness.Run(targets[i], $"Entry{i}"));
        }

        e.Start();
        var admin = await e.ConnectAsync(admin: true);

        var job = await e.RunQuickAsync(admin);

        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.Equal(ScanJobOrigin.Administrator, job.Request.Origin);
        var details = await admin.GetScanAsync(job.Id, cancellationToken: Timeout());
        Assert.Equal(4, details.Results.Count(r => r.Verdict == Verdict.Malicious && r.Action == FileAction.Quarantined));
        Assert.True(job.GetProgress().Counters.Clean >= 1); // the benign download
        Assert.False(File.Exists(download));
        Assert.All(targets, t => Assert.False(File.Exists(t))); // the autostart targets were moved out too
        Assert.True(File.Exists(clean));
        Assert.Equal(4, (await admin.ListQuarantineAsync(Timeout())).Items.Count);

        // Three 2001 alerts for the persistence entries, one per entry (file alerts for the same targets are separate).
        Assert.Equal(3, e.Q.Alerts.Snapshot().Count(a => a.Type == AlertType.MaliciousPersistence));

        var first = await admin.GetFindingsAsync(job.Id, 0, 2, Timeout());
        var rest = await admin.GetFindingsAsync(job.Id, first.NextOffset!.Value, 2, Timeout());
        Assert.Equal(2, first.Findings.Count);
        Assert.Single(rest.Findings);
        Assert.Null(rest.NextOffset);
        Assert.All(first.Findings.Concat(rest.Findings), f =>
        {
            Assert.Equal(FindingCategory.Persistence, f.Category);
            Assert.Equal(Verdict.Malicious, f.Verdict);
            Assert.NotEmpty(f.TechniqueIds);
        });
        Assert.Equal(3, first.Findings.Concat(rest.Findings).Select(f => f.FindingId).Distinct().Count());
        Assert.True(first.Complete);
    }

    [RequiresFact(Requires.UsnJournal)]
    public async Task Cache_IsFilledByAnAdminsCustomScan_HitByTheQuickScan_AndABlocklistUpdateTurnsTheCachedHashMalicious_WithoutARead()
    {
        await using var e = new SectionCEngine();
        var tool = e.Q.Write(@"Users\alice\Downloads\tool.exe", "a synthetic tool");
        e.Q.Write(@"Users\alice\Downloads\other.exe", "something else");
        e.Start();
        var admin = await e.ConnectAsync(admin: true);

        var custom = await e.RunCustomAsync(admin);
        int callsAfterCustom = e.Q.Jobs.Broker.Calls;
        Assert.Equal(2, custom.GetProgress().Counters.Clean);
        Assert.Equal(2, e.StoredRows); // an admin's Custom Scan fills the cache

        var quick = await e.RunQuickAsync(admin);
        Assert.Equal(2, quick.GetProgress().Counters.Cached); // the Quick Scan is served from it
        Assert.Equal(callsAfterCustom, e.Q.Jobs.Broker.Calls);

        string sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(tool)));
        e.Fingerprints.Blocklist = FakeFingerprints.BlocklistOf(sha);
        var afterUpdate = await e.RunQuickAsync(admin);

        Assert.Equal(callsAfterCustom, e.Q.Jobs.Broker.Calls); // still nothing re-read
        var flagged = Assert.Single(afterUpdate.Results, r => r.Verdict == Verdict.Malicious);
        Assert.True(flagged.FromCache);
        Assert.Equal(tool, flagged.Path, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(flagged.Detections, d => d.Source == DetectionSource.Blocklist);
        Assert.Equal(ScanFileAction.Quarantined, flagged.Action);
        Assert.False(File.Exists(tool));
    }

    [RequiresFact(Requires.UsnJournal)]
    public async Task AStandardUsersCustomScan_NeverReadsOrWritesTheCache_EvenWhenAnAdminHasFilledIt()
    {
        await using var e = new SectionCEngine();
        e.Q.Write(@"Users\alice\Documents\notes.txt", "alpha");
        e.Q.Write(@"Users\alice\Documents\more.txt", "bravo");
        e.Start();
        var user = await e.ConnectAsync(admin: false);
        var admin = await e.ConnectAsync(admin: true);

        var first = await e.RunCustomAsync(user);
        Assert.Equal(ScanJobOrigin.StandardUser, first.Request.Origin);
        Assert.Equal(0, e.StoredRows); // not written

        await e.RunCustomAsync(admin);
        Assert.Equal(2, e.StoredRows);
        long hits = e.Cache.Stats.Hits;
        int calls = e.Q.Jobs.Broker.Calls;

        var second = await e.RunCustomAsync(user);

        Assert.Equal(0, second.GetProgress().Counters.Cached); // not read
        Assert.Equal(hits, e.Cache.Stats.Hits);
        Assert.Equal(calls + 2, e.Q.Jobs.Broker.Calls); // every file went to the worker again
        Assert.Equal(2, e.StoredRows);
    }

    [Fact]
    public async Task FullScan_ThroughThePipe_OverATempVolume_PausesResumesAndCancels_WithoutQuarantiningCleanFiles()
    {
        await using var e = new SectionCEngine(scanDelay: TimeSpan.FromMilliseconds(30));
        for (int i = 0; i < 80; i++)
        {
            e.Q.Write($@"data\file{i}.bin", $"content {i}");
        }

        e.Start();
        var admin = await e.ConnectAsync(admin: true);
        var created = await admin.CreateFullScanAsync(Timeout());
        var job = e.Jobs.Get(created.JobId)!;
        Assert.Equal(ScanTrigger.FullScan, job.Request.Trigger);
        await admin.StartScanAsync(job.Id, Timeout());

        await WaitUntil(() => e.Q.Scanned.Count >= 3);
        await admin.PauseScanAsync(job.Id, Timeout());
        await JobWait.ForState(job, ScanJobState.Paused);
        long done = job.GetProgress().FilesDone;
        await Task.Delay(250);
        Assert.Equal(done, job.GetProgress().FilesDone); // no progress while paused

        await admin.ResumeScanAsync(job.Id, Timeout());
        await WaitUntil(() => job.GetProgress().FilesDone > done);
        await admin.CancelScanAsync(job.Id, Timeout());
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Cancelled, job.State);
        Assert.True(job.GetProgress().FilesDone < 80);
        Assert.Empty((await admin.ListQuarantineAsync(Timeout())).Items);
        Assert.Equal(JobState.Cancelled, (await admin.GetScanAsync(job.Id, cancellationToken: Timeout())).Summary.State);
    }
}
