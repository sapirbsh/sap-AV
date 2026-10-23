using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>A rule package the test can swap (for reloads).</summary>
internal sealed class FakeRulesSource(string? ruleText = null) : IScanRulesSource
{
    public string? RuleText { get; set; } = ruleText;

    public byte[] Blocklist { get; set; } = [];

    public int Loads { get; private set; }

    public Task<WorkerLoadRules> LoadAsync(CancellationToken cancellationToken = default)
    {
        Loads++;
        return Task.FromResult(new WorkerLoadRules
        {
            RuleFiles = RuleText is null ? [] : [new WorkerRuleFile { Name = "test.yar", Content = Encoding.UTF8.GetBytes(RuleText) }],
            ReadErrors = [],
            Blocklist = Blocklist,
        });
    }
}

/// <summary>
/// B5 supervision through the real broker and the real worker exe, in the test-only unsandboxed isolation (same Job
/// Object, pipes and protocol, no AppContainer), so it runs on every machine: crashes, hangs and broken responses
/// make the file NotScanned, the worker restarts and the engine keeps scanning; repeat offenders become Suspicious.
/// </summary>
public sealed class ScanBrokerSupervisionTests : IDisposable
{
    internal const string MarkerRule = "rule B5_Marker { meta: verdict = \"malicious\" strings: $a = \"sapav-b5-marker\" condition: $a }";

    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"))).FullName;
    private readonly List<SandboxedScanBroker> _brokers = [];

    public void Dispose()
    {
        foreach (var broker in _brokers)
        {
            broker.Dispose(); // kills every worker
        }

        TempDir.DeleteTree(_dir);
    }

    private SandboxedScanBroker Broker(IScanRulesSource? rules = null, Action<SandboxOptions>? configure = null)
    {
        var options = new SandboxOptions
        {
            WorkerPath = TestAppContainer.WorkerExe,
            WorkerCount = 1,
            EnableWorkerTestHooks = true,
            Isolation = WorkerIsolation.UnsandboxedForTests,
            RequestTimeout = TimeSpan.FromSeconds(20),
            RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
            RestartBackoffMax = TimeSpan.FromMilliseconds(100),
        };
        configure?.Invoke(options);
        var broker = new SandboxedScanBroker(options, rules ?? new FakeRulesSource(MarkerRule), NullLogger.Instance);
        broker.FaultInjector = item => Path.GetFileNameWithoutExtension(item.Path) switch
        {
            "crash" => WorkerTestFault.Crash,
            "hang" => WorkerTestFault.Hang,
            var name when Enum.TryParse<WorkerTestFault>(name, out var fault) => fault,
            _ => WorkerTestFault.None,
        };
        _brokers.Add(broker);
        return broker;
    }

    private ScanItem File(string name, string content = "plain text")
    {
        var path = Path.Combine(_dir, name);
        System.IO.File.WriteAllText(path, content);
        return new ScanItem(path, ScanTrigger.CustomScan);
    }

    [Fact]
    public async Task Clean_AndMarkerFiles_GetVerdicts_WithIdentityFromTheBroker()
    {
        using var broker = Broker();
        var clean = File("clean.txt");
        var marked = File("marked.txt", "xx sapav-b5-marker xx");

        var cleanReport = await broker.ScanAsync(clean);
        var markedReport = await broker.ScanAsync(marked);

        Assert.Equal(Verdict.Clean, cleanReport.Result.Verdict);
        Assert.Same(clean, cleanReport.Result.Item);
        Assert.Equal(Verdict.Malicious, markedReport.Result.Verdict);
        Assert.Contains(markedReport.Result.Detections, d => d.Source == DetectionSource.Yara);

        using var handle = System.IO.File.OpenHandle(marked.Path);
        Assert.True(FileIdentity.TryCapture(handle)!.IsSameObject(markedReport.Identity));
    }

    [Fact]
    public async Task Crash_IsNotScanned_WorkerRestarts_AndRepeatOffenderIsSuspicious()
    {
        using var broker = Broker(configure: o => o.MaxFailuresPerFile = 2);
        var crash = File("crash.bin");
        var clean = File("clean.txt");

        var first = await broker.ScanAsync(crash);
        Assert.Equal(ScanStatus.Error, first.Result.Status);
        Assert.Null(first.Result.Verdict); // never Clean
        Assert.NotNull(first.Identity);
        Assert.Contains(first.Notes, n => n.Message.Contains("Crashed", StringComparison.Ordinal));

        Assert.Equal(Verdict.Clean, (await broker.ScanAsync(clean)).Result.Verdict); // restarted, still scanning
        Assert.True(broker.Status.WorkerRestarts >= 1);

        var second = await broker.ScanAsync(crash);
        var detection = Assert.Single(second.Result.Detections);
        Assert.Equal(Verdict.Suspicious, second.Result.Verdict);
        Assert.Equal(MitreTechniqueIds.ExploitationForDefenseEvasion, detection.TechniqueId);
        Assert.Contains("crashed", detection.Reason, StringComparison.OrdinalIgnoreCase);

        int restarts = broker.Status.WorkerRestarts;
        var third = await broker.ScanAsync(crash);
        Assert.Equal(Verdict.Suspicious, third.Result.Verdict);
        Assert.Equal(restarts, broker.Status.WorkerRestarts); // not sent to a worker again
    }

    [Fact]
    public async Task Hang_TimesOut_KillsTheWorker_AndTheNextFileScans()
    {
        // The hang is the explicit test hook, so the timeout is deterministic; 8 s leaves room for the fresh worker that
        // scans the next file (cold JIT of the whole pipeline) on a slow CI runner.
        using var broker = Broker(configure: o => o.RequestTimeout = TimeSpan.FromSeconds(8));
        await broker.ScanAsync(File("warmup.txt"));
        int hungPid = broker.Slots[0].Worker!.ProcessId;

        var watch = Stopwatch.StartNew();
        var report = await broker.ScanAsync(File("hang.bin"));
        watch.Stop();

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Contains(report.Notes, n => n.Message.Contains("TimedOut", StringComparison.Ordinal));
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(7.5), TimeSpan.FromSeconds(60));
        Assert.True(ProcessGone(hungPid), "the hung worker must be killed");

        Assert.Equal(Verdict.Clean, (await broker.ScanAsync(File("after.txt"))).Result.Verdict);
        Assert.NotEqual(hungPid, broker.Slots[0].Worker!.ProcessId);
    }

    [Theory]
    [InlineData(nameof(WorkerTestFault.MalformedResponse))]
    [InlineData(nameof(WorkerTestFault.OversizedResponse))]
    [InlineData(nameof(WorkerTestFault.WrongSchemaResponse))]
    [InlineData(nameof(WorkerTestFault.WrongIdResponse))]
    public async Task BrokenResponses_AreRejected_NotScanned_AndTheWorkerIsReplaced(string fault)
    {
        using var broker = Broker();
        var report = await broker.ScanAsync(File(fault + ".bin"));

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Empty(report.Result.Detections);
        Assert.Contains(report.Notes, n => n.Message.Contains("ProtocolViolation", StringComparison.Ordinal));
        Assert.Equal(1, broker.Status.WorkerRestarts);
        Assert.Equal(Verdict.Clean, (await broker.ScanAsync(File("next.txt"))).Result.Verdict);
    }

    [Fact]
    public async Task WorkerKilledFromOutside_EngineKeepsScanning()
    {
        using var broker = Broker();
        await broker.ScanAsync(File("a.txt"));
        var worker = broker.Slots[0].Worker!;
        worker.Kill();
        Assert.True(worker.WaitForExit(TimeSpan.FromSeconds(10)));

        var report = await broker.ScanAsync(File("b.txt"));

        Assert.Equal(Verdict.Clean, report.Result.Verdict);
    }

    [Fact]
    public async Task Reload_ReachesEveryWorker()
    {
        var rules = new FakeRulesSource(ruleText: null);
        using var broker = Broker(rules, o => o.WorkerCount = 2);
        var first = await broker.ReloadRulesAsync();
        Assert.Equal(0, first!.RuleCount);
        Assert.Equal(ScanStatus.Scanned, (await broker.ScanAsync(File("m1.txt", "sapav-b5-marker"))).Result.Status);
        Assert.Equal(Verdict.Clean, (await broker.ScanAsync(File("m2.txt", "sapav-b5-marker"))).Result.Verdict);

        rules.RuleText = MarkerRule;
        var second = await broker.ReloadRulesAsync();

        Assert.Equal(1, second!.RuleCount);
        Assert.All(broker.Slots, s => Assert.Equal(second.Fingerprint, s.LastRules!.Fingerprint));
        var scans = await Task.WhenAll(broker.ScanAsync(File("m3.txt", "sapav-b5-marker")), broker.ScanAsync(File("m4.txt", "sapav-b5-marker")));
        Assert.All(scans, r => Assert.Equal(Verdict.Malicious, r.Result.Verdict));
    }

    [Fact]
    public async Task Blocklist_FromThePackage_IsApplied()
    {
        var item = File("listed.bin", "listed content");
        var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.IO.File.ReadAllBytes(item.Path)));
        using var broker = Broker(new FakeRulesSource { Blocklist = Encoding.ASCII.GetBytes(sha + "\n") });

        var report = await broker.ScanAsync(item);

        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal(sha, report.Result.Sha256);
        Assert.Contains(report.Result.Detections, d => d.Source == DetectionSource.Blocklist);
    }

    [Fact]
    public async Task UnavailableWorker_IsNotScanned_NeverClean()
    {
        using var broker = Broker(configure: o => o.WorkerPath = Path.Combine(_dir, "missing", "SapAV.ScanWorker.exe"));

        var report = await broker.ScanAsync(File("x.txt"));

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Contains(report.Notes, n => n.Message.Contains("unavailable", StringComparison.Ordinal));
        Assert.NotNull(broker.Status.LastError);
    }

    [Fact]
    public async Task MissingFile_IsReportedByTheBrokersOwnOpen()
    {
        using var broker = Broker();
        var report = await broker.ScanAsync(new ScanItem(Path.Combine(_dir, "nope.bin"), ScanTrigger.RealTime));

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Equal(Core.Hashing.HashFailureReason.NotFound, report.Hash.FailureReason);
        Assert.Equal(0, broker.Status.WorkersRunning); // no worker needed for that
    }

    [Fact]
    public void Options_OutOfRange_AreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SandboxOptions { WorkerCount = 0 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new SandboxOptions { WorkerCount = 9 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new SandboxOptions { MaxFailuresPerFile = 0 }.Validate());
        Assert.Throws<ArgumentOutOfRangeException>(() => new SandboxOptions { WorkerMemoryLimitMegabytes = 1 }.Validate());
        new SandboxOptions().Validate();
    }

    private static bool ProcessGone(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.WaitForExit(5000);
        }
        catch (ArgumentException)
        {
            return true;
        }
    }
}
