using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;
using Microsoft.Extensions.Options;
using SapAV.Core.Scanning;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;

namespace SapAV.Engine;

/// <summary>The engine's service and logging setup, in one place so tests check the same host that runs.</summary>
public static class EngineHost
{
    public const string ServiceName = "SapAV Engine";

    /// <summary>Registers the engine's services and logging on <paramref name="builder"/>.</summary>
    /// <remarks>
    /// <b>No Event Log logger provider.</b> <c>Host.CreateApplicationBuilder</c> adds <c>EventLogLoggerProvider</c> on
    /// Windows, and <c>AddWindowsService</c> adds it again when running as a service, with source "SapAV.Engine".
    /// That provider writes through <c>EventLog.WriteEvent</c>, which registers a missing source, so as SYSTEM it
    /// would silently create <c>HKLM\...\EventLog\Application\SapAV.Engine</c> that nothing ever removes. So all
    /// providers are cleared <b>after</b> <c>AddWindowsService</c> and only Console and Debug are added back. Engine
    /// diagnostics in the Event Log come later through our own non-registering writer (event IDs 9000-9999).
    /// </remarks>
    public static HostApplicationBuilder Configure(HostApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Logging.AddDebug();

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IWindowsEventLog, WindowsEventLog>();
        builder.Services.AddSingleton<IAlertSink, EventLogAlertSink>();

        // Review B M4: one component failing (an exception escaping a BackgroundService) must never stop the engine. Each
        // service also guards itself, logs, raises a health alert (9005-9009) and retries where that makes sense.
        builder.Services.Configure<HostOptions>(options => options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore);

        // Review B6 M2: the sap-AV log's actual CustomSD and message DLL are re-checked at startup and every 5 minutes.
        builder.Services.AddSingleton<IMessageFileLocationCheck>(MessageFileLocationCheck.Instance);
        builder.Services.AddHostedService<EventLogIntegrityMonitor>();

        // Quarantine (B2): store opened + recovered at startup; the pipe (B4) and scan queue (B3) use IQuarantineService.
        builder.Services.Configure<QuarantineOptions>(builder.Configuration.GetSection(QuarantineOptions.SectionName));
        builder.Services.AddSingleton<IQuarantineKeyProvider, DpapiQuarantineKeyProvider>();
        builder.Services.AddSingleton(sp =>
        {
            var quarantine = sp.GetRequiredService<IOptions<QuarantineOptions>>();
            return new QuarantineManager(quarantine, sp.GetRequiredService<IAlertDispatcher>(), sp.GetRequiredService<ILogger<QuarantineManager>>(),
                sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<IQuarantineKeyProvider>(), sp.GetRequiredService<ExclusionSet>());
        });
        builder.Services.AddSingleton<IQuarantineService>(sp => sp.GetRequiredService<QuarantineManager>());
        builder.Services.AddHostedService<QuarantineStartupService>();

        // Scanning (B5): files are parsed only in sandboxed worker processes; the broker opens them and passes
        // read-only handles. Sandbox:Mode = InProcess is for console debugging only: a warning, and refused as a service.
        builder.Services.Configure<SandboxOptions>(builder.Configuration.GetSection(SandboxOptions.SectionName));
        builder.Services.AddSingleton<IScanRulesSource>(sp => new DirectoryScanRulesSource(sp.GetRequiredService<IOptions<SandboxOptions>>().Value));
        builder.Services.AddSingleton<IScanBroker>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<SandboxOptions>>().Value;
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.Sandbox");
            var source = sp.GetRequiredService<IScanRulesSource>();
            var online = sp.GetService<IOnlineHashLookup>();
            return ScanBrokerFactory.Create(options, source, logger, sp.GetRequiredService<TimeProvider>(), online,
                runningAsService: Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService(),
                runningAsSystem: AppContainerName.IsLocalSystem());
        });
        builder.Services.AddSingleton<IFileScanner>(sp => sp.GetRequiredService<IScanBroker>());
        builder.Services.AddHostedService(sp => new ScanBrokerStartupService(sp.GetRequiredService<IScanBroker>(),
            sp.GetRequiredService<IAlertDispatcher>(), sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<IOptions<SandboxOptions>>().Value.ResolvedWorkerPath, sp.GetRequiredService<ILogger<ScanBrokerStartupService>>()));

        // Scan jobs (B3): bounded queue, dedicated background-mode threads, pause/resume/cancel. The pipe (B4) drives it.
        builder.Services.Configure<ScanJobOptions>(builder.Configuration.GetSection(ScanJobOptions.SectionName));
        builder.Services.AddSingleton<IAlertDispatcher>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<ScanJobOptions>>().Value;
            return new AlertDispatcher(sp.GetRequiredService<IAlertSink>(), sp.GetRequiredService<TimeProvider>(),
                sp.GetRequiredService<ILogger<AlertDispatcher>>(), options.AlertWindow, options.MaxAlertsPerWindow, options.AlertQueueCapacity);
        });
        builder.Services.AddSingleton(ScanJobService.CreateExclusions); // review B H1: engine folders excluded only while verified
        builder.Services.AddSingleton(ScanJobService.Create);
        builder.Services.AddSingleton<IScanJobService>(sp => sp.GetRequiredService<ScanJobService>());

        // Engine <-> GUI pipe (B4): explicit DACL, first-instance only, local clients only; identities come from the pipe.
        builder.Services.Configure<Pipe.PipeServerOptions>(builder.Configuration.GetSection(Pipe.PipeServerOptions.SectionName));
        builder.Services.AddHostedService<Pipe.EnginePipeServer>();
        return builder;
    }
}
