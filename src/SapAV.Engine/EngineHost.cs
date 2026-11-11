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
        // D3 (A2 M5): as a service / SYSTEM / elevated, rules and blocklist load only from the protected %ProgramData%\sap-AV
        // folders (or a configured admin-only folder); the shipped files are only their seed. A non-elevated debug run keeps
        // loading the shipped files directly (it has the user's own rights only).
        bool protectedMode = EngineAccount.IsProtected();
        builder.Services.Configure<SandboxOptions>(builder.Configuration.GetSection(SandboxOptions.SectionName));
        builder.Services.PostConfigure<SandboxOptions>(options => ProtectedRulesSource.Apply(options, protectedMode));
        builder.Services.AddSingleton<IScanRulesSource>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<SandboxOptions>>().Value;
            return protectedMode ? ProtectedRulesSource.Create(options) : new DirectoryScanRulesSource(options);
        });
        // VirusTotal (D3): hash-only lookups in the engine (the worker has no network), after the worker's local verdict. Off
        // until an administrator turns it on and sets a key over the pipe; key, cache and counter live in the protected folder.
        builder.Services.Configure<VirusTotal.VirusTotalOptions>(builder.Configuration.GetSection(VirusTotal.VirusTotalOptions.SectionName));
        builder.Services.AddSingleton<VirusTotal.VirusTotalService>();
        builder.Services.AddSingleton<VirusTotal.IVirusTotalService>(sp => sp.GetRequiredService<VirusTotal.VirusTotalService>());
        builder.Services.AddSingleton<IOnlineHashLookup, VirusTotal.VirusTotalOnlineLookup>();
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
        builder.Services.Configure<Scanning.Cache.ScanCacheOptions>(builder.Configuration.GetSection(Scanning.Cache.ScanCacheOptions.SectionName)); // C5
        builder.Services.AddSingleton<IAlertDispatcher>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<ScanJobOptions>>().Value;
            return new AlertDispatcher(sp.GetRequiredService<IAlertSink>(), sp.GetRequiredService<TimeProvider>(),
                sp.GetRequiredService<ILogger<AlertDispatcher>>(), options.AlertWindow, options.MaxAlertsPerWindow, options.AlertQueueCapacity);
        });
        builder.Services.AddSingleton(ScanJobService.CreateExclusions); // review B H1: engine folders excluded only while verified
        builder.Services.AddSingleton<IScanVerdictHandler>(ScanJobService.CreateVerdictHandler);
        builder.Services.AddSingleton(ScanJobService.Create);
        builder.Services.AddSingleton<IScanJobService>(sp => sp.GetRequiredService<ScanJobService>());

        // Persistence collectors (C2): read-only; Quick Scan (C4) and real-time monitoring (D4) use them.
        builder.Services.AddSingleton<Persistence.IPersistenceCollector>(sp =>
            Persistence.PersistenceCollector.CreateDefault(sp.GetService<ILogger<Persistence.PersistenceCollector>>(),
                sp.GetRequiredService<IScanBroker>() as Persistence.IPersistenceFileParser)); // review C H2: no sandbox = not collected, never parsed here

        // Persistence judgement (C3), registered for C4 / D4: target files go through the sandboxed broker, the shared
        // verdict handler (file alert + auto-quarantine policy) runs on each target, and alerts 2001 / 2002 use the dispatcher.
        builder.Services.AddSingleton<Persistence.IPersistenceScanner>(sp => new Persistence.PersistenceScanner(
            sp.GetRequiredService<IScanBroker>(), sp.GetRequiredService<IAlertDispatcher>(), sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.Persistence"), targetHandler: sp.GetRequiredService<IScanVerdictHandler>()));

        // Quick Scan (C4): a scan job of pluggable checks (processes, persistence, high-risk folders, recent files).
        // The threat pack (E7) adds checks by registering more IScanCheck singletons.
        builder.Services.Configure<Scanning.Checks.QuickScanOptions>(builder.Configuration.GetSection(Scanning.Checks.QuickScanOptions.SectionName));
        builder.Services.AddSingleton(Scanning.Checks.QuickScanFactory.Create);

        // Full Scan (C6): the same checks plus every file on every fixed drive; no time budget, the scan cache skips repeats.
        builder.Services.Configure<Scanning.Checks.FullScanOptions>(builder.Configuration.GetSection(Scanning.Checks.FullScanOptions.SectionName));
        builder.Services.AddSingleton(Scanning.Checks.FullScanFactory.Create);

        // Real-time monitoring (D1): handle-bound folder watches, wait-until-unlocked, a bounded queue, scans through the
        // same pipeline as scan jobs (sandboxed worker, cache, alerts, auto-quarantine) on the engine's real-time budget.
        builder.Services.Configure<RealTime.RealTimeOptions>(builder.Configuration.GetSection(RealTime.RealTimeOptions.SectionName));
        builder.Services.AddHostedService<RealTime.RealTimeService>();

        // Real-time persistence monitoring (D4): registry and folder change watches on every autostart location, re-collecting
        // only what changed, diffed against an HMAC-protected baseline in %ProgramData%\sap-AV\Persistence; new or changed
        // entries are judged by the persistence scanner above (alerts 2001 / 2002). Read-only: nothing is removed (D5).
        builder.Services.Configure<Persistence.Monitoring.PersistenceMonitorOptions>(
            builder.Configuration.GetSection(Persistence.Monitoring.PersistenceMonitorOptions.SectionName));
        builder.Services.AddHostedService<Persistence.Monitoring.PersistenceMonitorService>();

        // Block & remove (D5): only on an explicit user request over the pipe. Backed up first (HMAC'd records in
        // %ProgramData%\sap-AV\PersistenceBackups), restorable; the ledger keeps D4 from re-alerting the user's own changes.
        builder.Services.AddSingleton(sp => new Persistence.Remediation.PersistenceActionLedger(sp.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<Persistence.Remediation.IPersistenceRemediation>(Persistence.Remediation.PersistenceRemediator.CreateDefault);

        // Defender status (E5): read-only WMI snapshot of Defender's state and exclusions, for the Defender-tampering rules (E5)
        // and the Quick Scan check (E7). Never calls a Defender method; every WMI read is time-bounded.
        var defenderSection = builder.Configuration.GetSection(Defender.DefenderStatusOptions.SectionName);
        builder.Services.Configure<Defender.DefenderStatusOptions>(options => Defender.DefenderStatusOptions.Bind(defenderSection, options));
        builder.Services.AddSingleton<Defender.IWmiReader, Defender.ManagementWmiReader>();
        builder.Services.AddSingleton<Defender.IDefenderEnvironment, Defender.WindowsDefenderEnvironment>();
        builder.Services.AddSingleton<Core.Defender.IDefenderStatusSource, Defender.WmiDefenderStatusSource>();

        // Engine <-> GUI pipe (B4): explicit DACL, first-instance only, local clients only; identities come from the pipe.
        builder.Services.Configure<Pipe.PipeServerOptions>(builder.Configuration.GetSection(Pipe.PipeServerOptions.SectionName));
        builder.Services.AddHostedService<Pipe.EnginePipeServer>();
        return builder;
    }
}
