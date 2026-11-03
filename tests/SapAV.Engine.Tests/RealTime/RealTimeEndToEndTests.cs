using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Engine.Alerts;
using SapAV.Engine.RealTime;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>
/// D1 end to end: the real handle-bound watcher (ReadDirectoryChangesExW), the real scan broker and worker exe, the real
/// verdict handler with auto-quarantine into a test store, alerts into a recording sink. Only the "malware" is synthetic:
/// a marker string a test rule flags, or EICAR (generated now, opt-in, skipped when an antivirus removes it).
/// </summary>
public sealed class RealTimeEndToEndTests : IDisposable
{
    private readonly RealTimeHarness _rt = new() { Watches = NativeDirectoryWatchFactory.Instance };
    private readonly RecordingAlertSink _sink = new();
    private readonly AlertDispatcher _dispatcher;
    private readonly List<IDisposable> _owned = [];

    public RealTimeEndToEndTests()
    {
        _dispatcher = new AlertDispatcher(_sink, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 64);
    }

    public void Dispose()
    {
        _rt.Dispose();
        _dispatcher.Dispose();
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }
    }

    [Fact]
    public void TheRealWatcher_SeesNewAndRenamedFiles_AndTheirFinalNames()
    {
        _rt.Start();
        Assert.True(_rt.Monitor.Roots.Count == 1, string.Join("; ", _rt.Monitor.Problems.Values));
        Assert.True(Assert.IsType<NativeDirectoryWatch>(_rt.Monitor.Roots[0].Watch).Extended); // NTFS: attributes and size come with each event

        File.WriteAllText(Path.Combine(_rt.Watched, "created.exe"), "new file");
        Assert.Equal(RealTimeOutcome.Scanned, _rt.WaitFor("created.exe").Outcome);

        var sub = Directory.CreateDirectory(Path.Combine(_rt.Watched, "sub")).FullName;
        File.WriteAllText(Path.Combine(sub, "setup.tmp"), "renamed when done");
        File.Move(Path.Combine(sub, "setup.tmp"), Path.Combine(sub, "setup.exe"));
        Assert.Equal(RealTimeOutcome.Scanned, _rt.WaitFor("setup.exe").Outcome);

        // An exact name a plain path would lose (trailing dot) keeps its name.
        File.WriteAllText(@"\\?\" + Path.Combine(_rt.Watched, "evil.exe."), "trailing dot");
        var dotted = _rt.WaitFor(r => r.Path.EndsWith("evil.exe.", StringComparison.Ordinal));
        Assert.Equal(RealTimeOutcome.Scanned, dotted.Outcome);
        Assert.Equal(ScanStatus.Scanned, dotted.Scan!.Status);
    }

    [Fact]
    public void EndToEnd_AMarkerFileDroppedInAWatchedFolder_IsQuarantinedByTheSandboxedWorker()
    {
        var context = Use(new QuarantineTestContext());
        _rt.RealBroker = Use(Broker(new FakeRulesSource(ScanBrokerSupervisionTests.MarkerRule)));
        _rt.Handler = Handler(context);
        _rt.Start();

        var path = Path.Combine(_rt.Watched, "dropper.bin");
        File.WriteAllText(path, "xx sapav-b5-marker xx");
        var result = _rt.WaitFor("dropper.bin");

        Assert.Equal((Verdict.Malicious, ScanFileAction.Quarantined), (result.Scan!.Verdict, result.Scan.Action));
        Assert.False(File.Exists(path));
        Assert.True(_dispatcher.Drain(RealTimeHarness.Timeout));
        var alert = Assert.Single(_sink.Snapshot(), a => a.Type == AlertType.MaliciousFile);
        Assert.Equal((ScanTrigger.RealTime, AlertAction.Quarantined), (alert.Trigger, alert.Action));
        Assert.Equal(1, _rt.Monitor.Status.Quarantined);
    }

    [RequiresFact(Requires.EicarFileOnDisk)]
    public void EndToEnd_EicarWrittenToAWatchedTempFolder_IsDetectedAndQuarantined_ShippedRules()
    {
        var context = Use(new QuarantineTestContext());
        _rt.RealBroker = Use(Broker(new DirectoryScanRulesSource(new SandboxOptions()))); // the engine's data\rules + blocklist
        _rt.Handler = Handler(context);
        _rt.Start();

        var path = Path.Combine(_rt.Watched, "eicar.com");
        File.WriteAllBytes(path, SapAV.Core.Tests.TestSupport.Eicar.Bytes()); // generated now, never committed
        var result = _rt.WaitFor("eicar.com");

        Assert.Equal((Verdict.Malicious, ScanFileAction.Quarantined), (result.Scan!.Verdict, result.Scan.Action));
        Assert.Equal(SapAV.Core.Tests.TestSupport.Eicar.KnownSha256, result.Scan.Sha256);
        Assert.False(File.Exists(path));
        Assert.True(_dispatcher.Drain(RealTimeHarness.Timeout));
        Assert.Contains(_sink.Snapshot(), a => a.Type == AlertType.MaliciousFile && a.Trigger == ScanTrigger.RealTime && a.Action == AlertAction.Quarantined);
    }

    [Fact]
    public void WatcherRecords_AreParsedBoundsChecked_StreamsMapToTheirFile_AndATruncatedRecordEndsTheParse()
    {
        var buffer = new List<byte>();
        Record(buffer, 1, "a.exe", FileAttributes.Archive, 10, last: false);
        Record(buffer, 6, @"sub\b.txt:Zone.Identifier:$DATA", FileAttributes.Archive, 3, last: false);
        Record(buffer, 2, "removed.exe", 0, 0, last: false); // REMOVED: not acted on
        Record(buffer, 5, "dir", FileAttributes.Directory, 0, last: false);
        var data = buffer.ToArray().Concat(new byte[40]).ToArray(); // a record header cut short

        var changes = NativeDirectoryWatch.Parse(data, extended: true);

        Assert.Equal(3, changes.Count);
        Assert.Equal((FileChangeKind.Added, "a.exe", 10L), (changes[0].Kind, changes[0].Name, changes[0].Size!.Value));
        Assert.Equal((FileChangeKind.StreamChanged, @"sub\b.txt", true), (changes[1].Kind, changes[1].Name, changes[1].IsMarkOfTheWeb));
        Assert.Equal((FileChangeKind.RenamedTo, true), (changes[2].Kind, changes[2].IsDirectory));
    }

    [Fact]
    public async Task TheEngineHost_RunsRealTimeMonitoring_UnlessItIsTurnedOff()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();
        Assert.Contains(host.Services.GetServices<IHostedService>(), s => s is RealTimeService);

        var services = new ServiceCollection().BuildServiceProvider();
        var off = new RealTimeService(services, Options.Create(new RealTimeOptions { Enabled = false }), NullLogger<RealTimeService>.Instance);
        await off.StartAsync(CancellationToken.None);
        await off.ExecuteTask!;
        Assert.Null(off.Monitor);
        await off.StopAsync(CancellationToken.None);
    }

    private static void Record(List<byte> into, int action, string name, FileAttributes attributes, long size, bool last)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        int length = (84 + nameBytes.Length + 7) & ~7;
        var record = new byte[length];
        BitConverter.GetBytes(last ? 0 : length).CopyTo(record, 0);
        BitConverter.GetBytes(action).CopyTo(record, 4);
        BitConverter.GetBytes(size).CopyTo(record, 48);
        BitConverter.GetBytes((uint)attributes).CopyTo(record, 56);
        BitConverter.GetBytes(nameBytes.Length).CopyTo(record, 80);
        nameBytes.CopyTo(record, 84);
        into.AddRange(record);
    }

    private T Use<T>(T owned)
        where T : IDisposable
    {
        _owned.Add(owned);
        return owned;
    }

    /// <summary>The real broker and worker exe, in the test-only unsandboxed isolation (as the other end-to-end tests).</summary>
    private static SandboxedScanBroker Broker(IScanRulesSource rules) => new(new SandboxOptions
    {
        WorkerPath = TestAppContainer.WorkerExe,
        WorkerCount = 1,
        EnableWorkerTestHooks = true,
        Isolation = WorkerIsolation.UnsandboxedForTests,
        RequestTimeout = TimeSpan.FromSeconds(30),
        RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
        RestartBackoffMax = TimeSpan.FromMilliseconds(100),
    }, rules, NullLogger.Instance);

    private ScanVerdictHandler Handler(QuarantineTestContext context) =>
        new(_dispatcher, context.Manager, new AutoQuarantinePolicy([]), new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)),
            TimeProvider.System, NullLogger.Instance);
}
