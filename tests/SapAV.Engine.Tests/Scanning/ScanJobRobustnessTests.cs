using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Alerts;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>B3 robustness: rules warnings (A M5), store quota (B2 M4), engine folders (B2 follow-up), end to end.</summary>
public sealed class ScanJobRobustnessTests : IDisposable
{
    private readonly ScanJobHarness _jobs = new();
    private readonly RecordingAlertSink _sink = new();
    private readonly AlertDispatcher _dispatcher;
    private readonly List<IDisposable> _owned = [];

    public ScanJobRobustnessTests()
    {
        _dispatcher = new AlertDispatcher(_sink, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 64);
    }

    public void Dispose()
    {
        _jobs.Dispose();
        _dispatcher.Dispose();
        foreach (var owned in _owned)
        {
            owned.Dispose(); // brokers kill their workers; contexts delete their stores
        }
    }

    private async Task<ScanJob> RunAsync()
    {
        var (job, _) = _jobs.Start();
        await JobWait.Done(job);
        Assert.True(_dispatcher.Drain(JobWait.Timeout));
        return job;
    }

    private void UseRulesCheck() => _jobs.Preflight = new RulesPreflight(_jobs.Broker, _dispatcher, @"C:\ProgramData\sap-AV\rules", TimeProvider.System);

    private void UseQuarantine(QuarantineTestContext context) =>
        _jobs.Handler = new ScanVerdictHandler(_dispatcher, context.Manager, new AutoQuarantinePolicy([]),
            new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);

    [Fact]
    public async Task ZeroLoadedRules_IsAJobWarning_AndARulesDegradedAlert()
    {
        UseRulesCheck();
        _jobs.Broker.Rules = new RulesLoadSummary(0, [], 0, "fp", 10, 0);
        _jobs.Write("a.txt");

        var job = await RunAsync();

        Assert.Equal(ScanJobState.Completed, job.State); // still scans (blocklist, heuristics)
        Assert.Contains(job.Warnings, w => w.Message.StartsWith("No YARA rules are loaded", StringComparison.Ordinal));
        var alert = Assert.Single(_sink.Alerts);
        Assert.Equal((AlertType.ScanRulesDegraded, 9003), (alert.Type, AlertEventCatalog.For(alert.Type).EventId));
        Assert.Equal("T1562.001", alert.TechniqueId);
    }

    [Fact]
    public async Task RuleFileErrors_WarnWithNames_ButTheAlertCarriesOnlyCounts()
    {
        UseRulesCheck();
        const string workerText = "bad.yar: syntax error near 'secret file content'";
        _jobs.Broker.Rules = new RulesLoadSummary(7, [workerText], 0, "fp", 10, 0);
        _jobs.Write("a.txt");

        var job = await RunAsync();

        Assert.Contains(job.Warnings, w => w.Message.Contains(workerText, StringComparison.Ordinal));
        var reason = Assert.Single(Assert.Single(_sink.Alerts).Reasons);
        Assert.DoesNotContain("secret", reason, StringComparison.Ordinal); // worker text stays out of the Event Log (X2/B3 M2)
        Assert.StartsWith("1 YARA rule file(s) failed to load; 7 rules are active", reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RulesNeverLoaded_AreLoadedBeforeTheJob_AndAFailedLoadIsAWarning()
    {
        UseRulesCheck();
        _jobs.Broker.Rules = null;
        _jobs.Broker.ReloadResult = null; // no worker could load them
        _jobs.Write("a.txt");

        var job = await RunAsync();

        Assert.Contains(job.Warnings, w => w.Message.StartsWith("The scan rules could not be loaded", StringComparison.Ordinal));
        Assert.Equal(AlertType.ScanRulesDegraded, Assert.Single(_sink.Alerts).Type);
        Assert.Null(RulesPreflight.Judge(new RulesLoadSummary(3, [], 0, "fp", 0, 0)).Warning); // healthy rules: nothing
    }

    [Fact]
    public async Task StoreQuota_IsStoreFull_FileStaysInPlace_WithAnAlert()
    {
        var context = new QuarantineTestContext(configure: o => o.MaxStoreBytes = 64);
        _owned.Add(context);
        UseQuarantine(context);
        var path = _jobs.Write("mal-large.bin", new string('x', 1000));

        var job = await RunAsync();

        Assert.Equal(ScanFileAction.StoreFull, Assert.Single(job.Results).Action);
        Assert.True(File.Exists(path));
        Assert.Empty(context.Manager.List());
        Assert.Contains(_sink.Alerts, a => a.Type == AlertType.QuarantineStoreFull && AlertEventCatalog.For(a.Type).EventId == 9004);
        Assert.Contains(_sink.Alerts, a => a.Type == AlertType.MaliciousFile && a.Action == AlertAction.QuarantineFailed);
    }

    [Fact]
    public async Task FreeSpaceFloor_IsStoreFull()
    {
        using var context = new QuarantineTestContext(configure: o => o.MinFreeSpaceBytes = long.MaxValue / 2);
        var content = QuarantineTestContext.SampleContent();
        var path = context.WriteFile("dropper.bin", content);

        var result = await context.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));

        Assert.Equal(QuarantineStatus.StoreFull, result.Status);
        Assert.Contains("free", result.Reason, StringComparison.Ordinal);
        Assert.True(File.Exists(path));
        Assert.Empty(context.StoreFiles());
    }

    [Fact]
    public async Task Quarantine_RefusesTheEngineFolders_EvenWhenAsked()
    {
        using var context = new QuarantineTestContext();
        var rules = Path.Combine(context.Files, "rules");
        var manager = new QuarantineManager(
            Options.Create(new QuarantineOptions { Root = context.StoreRoot, AdditionalTrustedSids = [QuarantineTestContext.CurrentUser] }),
            context.Alerts, context.Log, context.Time, new FixedKeyProvider(context.Key), ExclusionSet.Always(new FolderSet([rules])));
        context.Manager.Dispose(); // one manager per store
        using (manager)
        {
            manager.Initialize();
            var content = QuarantineTestContext.SampleContent();
            var path = context.WriteFile(@"rules\self-matching.yar", content);

            var result = await manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));

            Assert.Equal(QuarantineStatus.EngineFolder, result.Status);
            Assert.True(File.Exists(path));
        }
    }

    [Fact]
    public void EngineFolders_AreTheStoreSandboxInstallWorkerAndRulesFolders_NeverTheWholeDataRoot()
    {
        var folders = ScanJobService.EngineFolders(new SandboxOptions(), new QuarantineOptions());

        Assert.True(folders.Contains(Path.Combine(EngineDataFolders.ProgramDataRoot, "Quarantine", "x")));
        Assert.True(folders.Contains(Path.Combine(EngineDataFolders.ProgramDataRoot, "Sandbox", "sandbox.id")));
        Assert.True(folders.Contains(Path.Combine(AppContext.BaseDirectory, "ScanWorker", "SapAV.ScanWorker.exe")));
        Assert.True(folders.Contains(Path.Combine(AppContext.BaseDirectory, "data", "rules", "eicar.yar")));
        Assert.False(folders.Contains(EngineDataFolders.ProgramDataRoot)); // review B H1: the root itself is scanned
        Assert.False(folders.Contains(Path.Combine(EngineDataFolders.ProgramDataRoot, "x", "dropped.exe")));
        Assert.False(folders.Contains(Path.Combine(Path.GetTempPath(), "x.exe")));
        Assert.True(ScanJobService.EngineFolders(new SandboxOptions(), new QuarantineOptions { Root = @"E:\Store" }).Contains(@"e:\store\abc"));
    }

    [Fact]
    public void EngineHost_ResolvesTheScanJobService_WithVerifiedEngineFoldersAndConfiguredExtras()
    {
        var builder = Host.CreateApplicationBuilder([]);
        builder.Configuration["ScanJobs:ExcludedFolders:0"] = @"D:\Extra";
        using var host = EngineHost.Configure(builder).Build();

        var service = Assert.IsType<ScanJobService>(host.Services.GetRequiredService<IScanJobService>());
        Assert.Same(host.Services.GetRequiredService<ExclusionSet>(), service.Excluded);
        Assert.False(service.Excluded.Contains(EngineDataFolders.ProgramDataRoot));
        Assert.True(service.Excluded.Contains(@"D:\Extra\x")); // configured by an administrator: honored as is
        Assert.False(service.Excluded.Contains(@"D:\Extra2\x")); // prefix of a name is not "inside"
        Assert.NotNull(host.Services.GetRequiredService<IAlertDispatcher>());
    }

    [Fact]
    public async Task EndToEnd_SandboxedWorker_MarkerFileIsQuarantinedThroughTheScanHandle()
    {
        var context = new QuarantineTestContext();
        _owned.Add(context);
        var broker = SandboxedBroker(new FakeRulesSource(ScanBrokerSupervisionTests.MarkerRule));
        var path = _jobs.Write("download.bin", "xx sapav-b5-marker xx");
        _jobs.Write("clean.txt", "nothing here");

        var job = await RunWithBrokerAsync(broker, context);

        var result = Assert.Single(job.Results);
        Assert.Equal((Verdict.Malicious, ScanFileAction.Quarantined), (result.Verdict, result.Action));
        Assert.False(File.Exists(path));
        Assert.Equal(1, job.GetProgress().Counters.Clean);
    }

    [RequiresFact(Requires.EicarFileOnDisk)]
    public async Task EndToEnd_Eicar_ThroughTheSandboxedWorker_ShippedRules_IsQuarantined()
    {
        var context = new QuarantineTestContext();
        _owned.Add(context);
        var broker = SandboxedBroker(new DirectoryScanRulesSource(new SandboxOptions())); // the engine's data\rules + blocklist
        var path = Path.Combine(_jobs.Root, "eicar.com");
        File.WriteAllBytes(path, SapAV.Core.Tests.TestSupport.Eicar.Bytes()); // generated now, never committed

        var job = await RunWithBrokerAsync(broker, context);

        var result = Assert.Single(job.Results);
        Assert.Equal((Verdict.Malicious, ScanFileAction.Quarantined), (result.Verdict, result.Action));
        Assert.Equal(SapAV.Core.Tests.TestSupport.Eicar.KnownSha256, result.Sha256);
        Assert.False(File.Exists(path));
        Assert.Contains(_sink.Alerts, a => a.Type == AlertType.MaliciousFile && a.Action == AlertAction.Quarantined);
    }

    /// <summary>The real broker and worker exe, in the test-only unsandboxed isolation (same as ScanBrokerSupervisionTests).</summary>
    private SandboxedScanBroker SandboxedBroker(IScanRulesSource rules)
    {
        var broker = new SandboxedScanBroker(new SandboxOptions
        {
            WorkerPath = TestAppContainer.WorkerExe,
            WorkerCount = 1,
            EnableWorkerTestHooks = true,
            Isolation = WorkerIsolation.UnsandboxedForTests,
            RequestTimeout = TimeSpan.FromSeconds(30),
            RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
            RestartBackoffMax = TimeSpan.FromMilliseconds(100),
        }, rules, NullLogger.Instance);
        _owned.Add(broker);
        return broker;
    }

    private async Task<ScanJob> RunWithBrokerAsync(SandboxedScanBroker broker, QuarantineTestContext context)
    {
        var handler = new ScanVerdictHandler(_dispatcher, context.Manager, new AutoQuarantinePolicy([]),
            new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);
        using var service = new ScanJobService(new ScanJobOptions { ThreadsPerJob = 1 }, broker, new FolderSet([]), handler,
            new RulesPreflight(broker, _dispatcher, "rules", TimeProvider.System), TimeProvider.System, NullLogger.Instance);
        var job = service.Create(new ScanJobRequest([_jobs.Root], ScanTrigger.CustomScan));
        Assert.Equal(ScanJobStartResult.Started, service.Start(job.Id));
        await JobWait.Done(job);
        Assert.True(_dispatcher.Drain(JobWait.Timeout));
        Assert.Empty(job.Warnings);
        return job;
    }
}
