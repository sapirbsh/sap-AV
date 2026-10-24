using System.ComponentModel;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SapAV.Core.Alerts;
using SapAV.Core.Pipe;
using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests;

/// <summary>
/// Review B M4 / M5 / L1 / L2 and B6 M2: one component's failure never stops the engine, and each raises its health alert
/// (9005 store, 9006 sandbox, 9007 pipe, 9009 log integrity) through the dispatcher.
/// </summary>
public sealed class EngineResilienceTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(15);

    private static async Task Until(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + Wait;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the condition was not reached in time");
            await Task.Delay(20);
        }
    }

    private static bool Elevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // ---- Host ----

    [Fact]
    public void TheHost_IgnoresBackgroundServiceFailures_RunsTheHealthMonitor_AndHasNoTemplateWorker()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        Assert.Equal(BackgroundServiceExceptionBehavior.Ignore, host.Services.GetRequiredService<IOptions<HostOptions>>().Value.BackgroundServiceExceptionBehavior);
        var hosted = host.Services.GetServices<IHostedService>().Select(s => s.GetType().Name).ToArray();
        Assert.Contains(nameof(EventLogIntegrityMonitor), hosted);
        Assert.Contains(nameof(QuarantineStartupService), hosted);
        Assert.DoesNotContain("Worker", hosted);
        Assert.Null(typeof(EngineHost).Assembly.GetType("SapAV.Engine.Worker"));
    }

    // ---- Quarantine store (9005) ----

    private sealed class FlakyKeyProvider(byte[] key, params Exception[] failures) : IQuarantineKeyProvider
    {
        private int _calls;

        public byte[] GetOrCreateKey(string storeRoot, QuarantineAccessPolicy policy) =>
            _calls++ < failures.Length ? throw failures[_calls - 1] : key;
    }

    [Fact]
    public async Task TheStore_IsRetriedWithBackoff_AfterIoAndWin32Failures_AndEachFailureRaisesTheStoreAlert()
    {
        using var temp = new TempDir();
        var alerts = new RecordingAlertSink();
        var keys = new FlakyKeyProvider(new byte[32], new IOException("recovery could not list the store"), new Win32Exception(5));
        using var manager = new QuarantineManager(
            Options.Create(new QuarantineOptions { Root = Path.Combine(temp.Path, "Quarantine"), AdditionalTrustedSids = [QuarantineTestContext.CurrentUser] }),
            alerts, NullLogger<QuarantineManager>.Instance, TimeProvider.System, keys);
        using var service = new QuarantineStartupService(manager, alerts, TimeProvider.System, NullLogger<QuarantineStartupService>.Instance)
        {
            IsPrivileged = () => true,
            InitialBackoff = TimeSpan.FromMilliseconds(10),
        };

        await service.StartAsync(CancellationToken.None);
        await Until(() => manager.IsAvailable);
        await service.StopAsync(CancellationToken.None);

        var raised = alerts.Snapshot();
        Assert.Equal(2, raised.Length);
        Assert.All(raised, a => Assert.Equal(AlertEventCatalog.QuarantineStoreUnavailableEventId, AlertEventCatalog.For(a.Type).EventId));
        Assert.All(alerts.HealthFlags, Assert.True);
    }

    [Fact]
    public async Task ARefusedStore_StaysUnavailableAndAlerted_UntilItIsFixed()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "Quarantine")).FullName;
        var planted = Path.Combine(root, "planted.bin");
        File.WriteAllText(planted, "x"); // a wider ACL and content: refused
        var alerts = new RecordingAlertSink();
        using var manager = new QuarantineManager(
            Options.Create(new QuarantineOptions { Root = root, AdditionalTrustedSids = [QuarantineTestContext.CurrentUser] }),
            alerts, NullLogger<QuarantineManager>.Instance, TimeProvider.System, new FixedKeyProvider(new byte[32]));
        using var service = new QuarantineStartupService(manager, alerts, TimeProvider.System, NullLogger<QuarantineStartupService>.Instance)
        {
            IsPrivileged = () => true,
            InitialBackoff = TimeSpan.FromMilliseconds(10),
            MaxBackoff = TimeSpan.FromMilliseconds(50),
        };

        await service.StartAsync(CancellationToken.None);
        await Until(() => alerts.Snapshot().Length > 0);
        Assert.False(manager.IsAvailable);
        Assert.Contains("not empty", Assert.Single(alerts.Snapshot().Take(1)).Reasons[0], StringComparison.Ordinal);

        File.Delete(planted); // an administrator removed it
        await Until(() => manager.IsAvailable);
        await service.StopAsync(CancellationToken.None);
    }

    // ---- Sandbox (9006) ----

    [Theory]
    [InlineData(false)] // no worker could load the rules
    [InlineData(true)]  // something unexpected was thrown
    public async Task ASandboxThatCantStart_RaisesTheSandboxAlert_AndTheServiceEndsNormally(bool throws)
    {
        var broker = new FakeScanBroker { ReloadResult = null, ReloadFailure = throws ? new InvalidCastException("boom") : null };
        var alerts = new RecordingAlertSink();
        using var service = new ScanBrokerStartupService(broker, alerts, TimeProvider.System, @"C:\Program Files\sap-AV\ScanWorker\SapAV.ScanWorker.exe",
            NullLogger<ScanBrokerStartupService>.Instance);

        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(Wait);

        var alert = Assert.Single(alerts.Snapshot());
        Assert.Equal(AlertEventCatalog.SandboxUnavailableEventId, AlertEventCatalog.For(alert.Type).EventId);
        Assert.DoesNotContain("boom", alert.Reasons[0], StringComparison.Ordinal); // engine template text only
        Assert.True(service.ExecuteTask.IsCompletedSuccessfully);
    }

    // ---- Event Log integrity (9009, B6 M2) ----

    private static (EventLogIntegrityMonitor Monitor, FakeWindowsEventLog Log, RecordingAlertSink Alerts) Monitor(string? messageFileProblem = null)
    {
        var log = new FakeWindowsEventLog();
        log.Register(AlertEventCatalog.SourceName, AlertEventCatalog.LogName);
        log.Logs[AlertEventCatalog.LogName].Settings = EventLogSettings.Default;
        var alerts = new RecordingAlertSink();
        var monitor = new EventLogIntegrityMonitor(log, new FakeMessageFileCheck(messageFileProblem), alerts, TimeProvider.System,
            NullLogger<EventLogIntegrityMonitor>.Instance);
        return (monitor, log, alerts);
    }

    [Fact]
    public void TheLogAsInstalled_IsNotReported()
    {
        var (monitor, _, alerts) = Monitor();

        Assert.Null(monitor.Check());
        Assert.Empty(alerts.Alerts);
    }

    [Fact]
    public void AWidenedCustomSd_IsReportedAsLogIntegrityDegraded()
    {
        var (monitor, log, alerts) = Monitor();
        log.Logs[AlertEventCatalog.LogName].Settings = EventLogSettings.Default with
        {
            CustomSd = EventLogCustomSd.Sddl + "(A;;0x3;;;AU)", // e.g. wevtutil sl sap-AV /ca:... let users write
        };

        Assert.Contains("CustomSD", monitor.Check(), StringComparison.Ordinal);
        var alert = Assert.Single(alerts.Alerts);
        Assert.Equal(AlertEventCatalog.EventLogIntegrityDegradedEventId, AlertEventCatalog.For(alert.Type).EventId);
        Assert.True(Assert.Single(alerts.HealthFlags));
    }

    [Fact]
    public void AnUnsafeMessageDll_IsReported_AndAMissingLogIsSkipped()
    {
        var (monitor, log, alerts) = Monitor("the folder is writable by Users");

        Assert.Contains("message DLL", monitor.Check(), StringComparison.Ordinal);
        Assert.Single(alerts.Alerts);

        log.Logs.Clear(); // not installed (a dev machine): the sink already warns
        Assert.Null(monitor.Check());
    }

    // ---- Pipe (9007, M5) ----

    [Fact]
    public async Task TheProtectedPrefixPipe_CanBeCreatedOnlyElevated_AndARefusalRaisesThePipeAlert()
    {
        using var jobs = new ScanJobHarness();
        var alerts = new RecordingAlertSink();
        var options = new PipeServerOptions { PipeName = @"ProtectedPrefix\Administrators\sap-AV.engine.test." + Guid.NewGuid().ToString("N") };
        using var server = new EnginePipeServer(options, jobs.Service, null, TimeProvider.System, NullLogger.Instance, new PipeClientIdentityResolver(),
            EnginePipeSecurity.CurrentAccount(), _ => 3, alerts);

        await server.StartAsync(CancellationToken.None);
        try
        {
            if (Elevated())
            {
                await server.Listening.WaitAsync(Wait);
                Assert.Empty(alerts.Alerts);
            }
            else
            {
                await Assert.ThrowsAsync<PipeNameTakenException>(() => server.Listening.WaitAsync(Wait));
                var alert = Assert.Single(alerts.Snapshot());
                Assert.Equal(AlertEventCatalog.PipeUnavailableEventId, AlertEventCatalog.For(alert.Type).EventId);
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [RequiresFact(Requires.RunningElevated)]
    public async Task UnderTheProtectedPrefix_AStandardUserCanStillConnect()
    {
        await using var server = new PipeTestServer(o => o.PipeName = @"ProtectedPrefix\Administrators\sap-AV.engine.test." + Guid.NewGuid().ToString("N"));
        await server.Server.Listening.WaitAsync(Wait);
        using var standardUser = FilteredToken.CreateNonAdmin();
        server.Resolver.Enqueue(() => new FakeClientIdentity());

        await using var client = await WindowsIdentity.RunImpersonatedAsync(standardUser,
            () => EnginePipeClient.ConnectAsync(server.Options.PipeName, requireSystemServer: false, Wait, "test"));

        Assert.NotNull(client.Hello);
    }

    [Fact]
    public void ANonElevatedEngine_UsesTheDebugPipe_AnElevatedOneTheProtectedName()
    {
        Assert.Equal(PipeProtocol.DebugPipeName, EnginePipeServer.ForThisProcess(new PipeServerOptions(), privileged: false).PipeName);
        Assert.Equal(PipeProtocol.PipeName, EnginePipeServer.ForThisProcess(new PipeServerOptions(), privileged: true).PipeName);
        Assert.StartsWith(@"ProtectedPrefix\Administrators\", PipeProtocol.PipeName, StringComparison.Ordinal);
    }

    // ---- Restore alert (L2) ----

    [Fact]
    public async Task TheRestoreAlert_GoesThroughTheDispatcher_AsAHealthAlert()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var quarantined = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(ctx.WriteFile("r.exe", content), content));

        var restored = await ctx.Manager.RestoreAsync(quarantined.Entry!.Id);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        int index = ctx.Alerts.Alerts.FindIndex(a => a.Type == AlertType.QuarantineRestored);
        Assert.True(ctx.Alerts.HealthFlags[index]);
    }
}
