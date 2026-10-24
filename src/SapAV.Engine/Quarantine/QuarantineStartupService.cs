using System.Security.Principal;
using SapAV.Engine.Alerts;

namespace SapAV.Engine.Quarantine;

/// <summary>
/// Opens the quarantine store and runs crash recovery when the engine starts. Only when the engine runs as SYSTEM or
/// elevated: a non-elevated debug run must not create <c>%ProgramData%\sap-AV\Quarantine</c> owned by a normal user
/// (the service would then refuse it), so the quarantine stays unavailable there.
/// </summary>
/// <remarks>
/// Review B M4: <b>any</b> failure (a refused store, an I/O error while recovery lists the store, a Win32 error while it
/// cleans up a restore) is logged, raises a <see cref="Core.Alerts.AlertType.QuarantineStoreUnavailable"/> health alert
/// (event 9005; the dispatcher keeps it to one per window) and is retried with backoff, doubling from
/// <see cref="InitialBackoff"/> up to <see cref="MaxBackoff"/>. It never stops the engine; until it succeeds, quarantine
/// requests get StoreUnavailable.
/// </remarks>
public sealed class QuarantineStartupService(
    QuarantineManager manager, IAlertDispatcher alerts, TimeProvider time, ILogger<QuarantineStartupService> logger) : BackgroundService
{
    /// <summary>Test seam: overrides the privilege check.</summary>
    internal Func<bool> IsPrivileged { get; init; } = RunningAsSystemOrElevated;

    internal TimeSpan InitialBackoff { get; init; } = TimeSpan.FromSeconds(5);

    internal TimeSpan MaxBackoff { get; init; } = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!IsPrivileged())
        {
            logger.LogWarning("Quarantine disabled: the engine is not running as SYSTEM or elevated.");
            return;
        }

        var delay = InitialBackoff;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                manager.Initialize();
                return;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                logger.LogError(ex, "Quarantine unavailable ({Type}): {Message} Retrying in {Delay}.", ex.GetType().Name, ex.Message, delay);
                string why = ex is QuarantineStoreException ? ex.Message : $"{ex.GetType().Name} while opening or recovering the store.";
                alerts.Post(ScanAlerts.StoreUnavailable(manager.ConfiguredRoot, why, time.GetUtcNow()), health: true);
            }

            try
            {
                await Task.Delay(delay, time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }

            delay = TimeSpan.FromTicks(Math.Min(MaxBackoff.Ticks, delay.Ticks * 2));
        }
    }

    private static bool RunningAsSystemOrElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
