using System.Security.Principal;

namespace SapAV.Engine.Quarantine;

/// <summary>
/// Opens the quarantine store and runs crash recovery when the engine starts. Only when the engine runs as SYSTEM or
/// elevated: a non-elevated debug run must not create <c>%ProgramData%\sap-AV\Quarantine</c> owned by a normal user
/// (the service would then refuse it), so the quarantine stays unavailable there.
/// </summary>
public sealed class QuarantineStartupService(QuarantineManager manager, ILogger<QuarantineStartupService> logger) : IHostedService
{
    /// <summary>Test seam: overrides the privilege check.</summary>
    internal Func<bool> IsPrivileged { get; init; } = RunningAsSystemOrElevated;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (!IsPrivileged())
        {
            logger.LogWarning("Quarantine disabled: the engine is not running as SYSTEM or elevated.");
            return Task.CompletedTask;
        }

        try
        {
            manager.Initialize();
        }
        catch (QuarantineStoreException ex)
        {
            logger.LogError(ex, "Quarantine disabled: {Message}", ex.Message);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static bool RunningAsSystemOrElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
