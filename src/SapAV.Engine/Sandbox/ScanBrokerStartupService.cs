using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// Loads the rules into the scan workers at startup (starting them), so the first real scan doesn't pay for it and a
/// broken sandbox shows up in the log right away. Failures are logged, never fatal: scans then come back NotScanned.
/// </summary>
internal sealed class ScanBrokerStartupService(IScanBroker broker, ILogger<ScanBrokerStartupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var summary = await broker.ReloadRulesAsync(stoppingToken).ConfigureAwait(false);
            if (summary is null)
            {
                logger.LogError("No scan worker could start or load the rules: {Error}. Files will be reported NotScanned.", broker.Status.LastError);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            logger.LogError(ex, "Loading the scan rules failed.");
        }
    }
}
