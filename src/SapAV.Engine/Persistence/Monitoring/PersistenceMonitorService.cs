using Microsoft.Extensions.Options;
using SapAV.Engine.Quarantine;
using SapAV.Engine.RealTime;

namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>
/// Hosts <see cref="PersistenceMonitor"/> in the engine (D4): starts it when <see cref="PersistenceMonitorOptions.Enabled"/>, on
/// the engine's own collector (shared with Quick Scan, so both reuse unchanged parse results) and persistence scanner (target
/// scans through the sandboxed broker and the shared verdict handler, alerts through the dispatcher), with the baseline in the
/// protected data folder; stops it with the engine. A failure to start is logged and never stops the engine (review B M4).
/// </summary>
internal sealed class PersistenceMonitorService(IServiceProvider services, IOptions<PersistenceMonitorOptions> options, ILogger<PersistenceMonitorService> logger)
    : BackgroundService
{
    /// <summary>The running monitor (null when off or not started).</summary>
    internal PersistenceMonitor? Monitor { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.Enabled)
        {
            logger.LogWarning("Real-time persistence monitoring is turned off (PersistenceMonitor:Enabled = false).");
            return;
        }

        try
        {
            await Task.Yield(); // never block host start-up
            Monitor = Create(services, settings);
            Monitor.Start();
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError(ex, "Real-time persistence monitoring could not start; autostart changes are found only by scans.");
        }
        finally
        {
            Monitor?.Dispose();
            Monitor = null;
        }
    }

    internal static PersistenceMonitor Create(IServiceProvider services, PersistenceMonitorOptions options)
    {
        var loggers = services.GetRequiredService<ILoggerFactory>();
        var logger = loggers.CreateLogger("SapAV.Engine.PersistenceMonitor");
        var collector = services.GetRequiredService<IPersistenceCollector>() as IScopedPersistenceCollector
            ?? throw new InvalidOperationException("The registered persistence collector can't collect by scope.");
        // Only a protected engine (service, SYSTEM, elevated) keeps the baseline in %ProgramData%\sap-AV: a non-elevated debug run
        // must never create the engine's data folders with the developer as owner (the real engine would then refuse them).
        IPersistenceBaselineStore? file = EngineAccount.IsProtected()
            ? FileBaselineStore.TryCreate(options.ResolvedFolder, services.GetRequiredService<IQuarantineKeyProvider>(), QuarantineAccessPolicy.Default, logger)
            : null;
        if (file is null && !EngineAccount.IsProtected())
        {
            logger.LogWarning("Persistence monitor: not running protected (service, SYSTEM or elevated); the baseline is kept in memory only.");
        }

        IPersistenceBaselineStore store = file ?? new MemoryBaselineStore();
        return new PersistenceMonitor(options, collector, services.GetRequiredService<IPersistenceScanner>(), store, new WindowsRegistryWatchFactory(),
            NativeDirectoryWatchFactory.Instance, services.GetRequiredService<TimeProvider>(), logger,
            alerts: services.GetRequiredService<Alerts.IAlertDispatcher>(),
            reportHidden: EngineAccount.IsProtected(), // review H3: a non-elevated debug run is denied other users' locations by design
            userActions: services.GetService<Remediation.PersistenceActionLedger>()); // D5: the user's own Block & remove / restore isn't re-alerted
    }
}
