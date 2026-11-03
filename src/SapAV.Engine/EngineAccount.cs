using System.Security.Principal;

namespace SapAV.Engine;

/// <summary>Which account the engine runs as, for decisions that differ between the service and a debug console run.</summary>
public static class EngineAccount
{
    /// <summary>True as LocalSystem or with an elevated administrator token.</summary>
    public static bool IsSystemOrElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>True when running under the Service Control Manager.</summary>
    public static bool IsWindowsService() => Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService();

    /// <summary>
    /// D3: the engine's data must come from the protected <c>%ProgramData%\sap-AV</c> folder (a service, SYSTEM or elevated). Only a
    /// non-elevated console run (debugging, the user's own rights) may use the shipped files next to the engine directly.
    /// </summary>
    public static bool IsProtected() => IsWindowsService() || IsSystemOrElevated();

    /// <summary>
    /// D3 decision: the development API key from <c>SAPAV_VIRUSTOTAL_APIKEY</c> is read only in a console run, never by the
    /// service or as SYSTEM (an environment variable set for the machine would otherwise silently feed the service a key no
    /// administrator entered).
    /// </summary>
    public static bool AllowsDevelopmentKey()
    {
        if (IsWindowsService())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return !identity.IsSystem;
    }
}
