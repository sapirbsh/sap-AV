using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SapAV.Engine.Alerts;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// Loads the rules into the scan workers at startup (starting them), so the first real scan doesn't pay for it and a
/// broken sandbox shows up in the log right away. Failures are logged, never fatal: scans then come back NotScanned.
/// Review B M4: any failure (no worker could start or load the rules, or an unexpected exception) also raises a
/// <see cref="Core.Alerts.AlertType.SandboxUnavailable"/> health alert (event 9006).
/// </summary>
internal sealed class ScanBrokerStartupService(
    IScanBroker broker, IAlertDispatcher alerts, TimeProvider time, string workerPath, ILogger<ScanBrokerStartupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var summary = await broker.ReloadRulesAsync(stoppingToken).ConfigureAwait(false);
            if (summary is null)
            {
                logger.LogError("No scan worker could start or load the rules: {Error}. Files will be reported NotScanned.", broker.Status.LastError);
                alerts.Post(ScanAlerts.SandboxUnavailable(workerPath, time.GetUtcNow()), health: true);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogError(ex, "Loading the scan rules failed.");
            alerts.Post(ScanAlerts.SandboxUnavailable(workerPath, time.GetUtcNow()), health: true);
        }
    }
}
