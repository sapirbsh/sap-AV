using Microsoft.Extensions.Options;
using SapAV.Engine.Persistence;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;

namespace SapAV.Engine.RealTime;

/// <summary>
/// Hosts <see cref="RealTimeMonitor"/> in the engine (D1): starts it when <see cref="RealTimeOptions.Enabled"/>, on the
/// engine's own scan pipeline (<see cref="ScanJobService.Pipeline"/>: same exclusions, cache and verdict handler as scan
/// jobs), and stops it with the engine. A failure to start is logged and never stops the engine (review B M4).
/// </summary>
internal sealed class RealTimeService(IServiceProvider services, IOptions<RealTimeOptions> options, ILogger<RealTimeService> logger) : BackgroundService
{
    /// <summary>The running monitor (null when off or not started).</summary>
    internal RealTimeMonitor? Monitor { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.Enabled)
        {
            logger.LogWarning("Real-time monitoring is turned off (RealTime:Enabled = false).");
            return;
        }

        try
        {
            await Task.Yield(); // never block host start-up with the folder resolution and the first opens
            Monitor = Create(services, settings);
            Monitor.Start();
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError(ex, "Real-time monitoring could not start; files are scanned only by scan jobs.");
            ReportUnavailable(services, $"it could not start ({ex.GetType().Name}).");
        }
        finally
        {
            Monitor?.Dispose();
            Monitor = null;
        }
    }

    /// <summary>
    /// Section D review M4: health alert 9010 (RealTimeUnavailable) through the dispatcher: as a service the engine's own
    /// ILogger output reaches no event log, so this is how an administrator learns real-time protection is down.
    /// </summary>
    internal static void ReportUnavailable(IServiceProvider services, string problem)
    {
        if (services.GetService<Alerts.IAlertDispatcher>() is { } alerts)
        {
            alerts.Post(Alerts.ScanAlerts.RealTimeUnavailable(problem, services.GetRequiredService<TimeProvider>().GetUtcNow()), health: true);
        }
    }

    internal static RealTimeMonitor Create(IServiceProvider services, RealTimeOptions options)
    {
        var jobs = services.GetRequiredService<ScanJobService>();
        var loggers = services.GetRequiredService<ILoggerFactory>();
        var folders = new ProfileWatchedFolders(new RegistryProfileFolders(new WindowsRegistryView()), options);
        var logger = loggers.CreateLogger("SapAV.Engine.RealTime");
        int workers = services.GetRequiredService<IOptions<Sandbox.SandboxOptions>>().Value.WorkerCount;
        if (options.EffectiveScanThreads(workers) < options.ScanThreads)
        {
            // Review D1 M3: real-time scans at High priority; one worker always stays free for user and administrator jobs.
            logger.LogWarning("RealTime:ScanThreads = {Threads} is more than the {Workers} scan worker(s) allow; {Used} thread(s) are used.",
                options.ScanThreads, workers, options.EffectiveScanThreads(workers));
        }

        return new RealTimeMonitor(options, folders, jobs.Pipeline, jobs.Excluded, services.GetRequiredService<TimeProvider>(), logger,
            workerCount: workers, unavailable: problem => ReportUnavailable(services, problem));
    }
}
