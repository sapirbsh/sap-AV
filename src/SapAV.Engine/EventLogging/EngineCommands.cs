using System.Security;

namespace SapAV.Engine.EventLogging;

/// <summary>
/// One-shot commands for the service installer path, run before the host starts:
/// <c>--install-eventlog-source</c> and <c>--uninstall-eventlog-source</c>. Both need an elevated prompt.
/// </summary>
public static class EngineCommands
{
    public const string InstallEventLogSource = "--install-eventlog-source";
    public const string UninstallEventLogSource = "--uninstall-eventlog-source";

    public const int ExitSuccess = 0;
    public const int ExitFailed = 1;
    public const int ExitConflict = 2;

    /// <summary>The message DLL is not in an admin-only folder (B1 review M3); nothing was changed.</summary>
    public const int ExitUnprotectedMessageFile = 3;

    public const int ExitNotElevated = 5;

    /// <summary>
    /// Runs the command if <paramref name="args"/> is exactly one known command and returns its exit code.
    /// If any argument looks like a command (any letter case) but the command line isn't exactly that, prints the
    /// usage and returns <see cref="ExitFailed"/>: an installer typo must never start the engine instead.
    /// Otherwise returns null and the engine starts normally.
    /// </summary>
    /// <param name="locationCheck">The message DLL check; the real <see cref="MessageFileLocationCheck"/> unless a test fakes it.</param>
    public static int? TryRun(
        string[] args, IWindowsEventLog eventLog, TextWriter output, TextWriter error,
        IMessageFileLocationCheck? locationCheck = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(error);
        bool mentionsCommand = args.Any(a => a.Equals(InstallEventLogSource, StringComparison.OrdinalIgnoreCase)
                                             || a.Equals(UninstallEventLogSource, StringComparison.OrdinalIgnoreCase));
        if (!mentionsCommand)
        {
            return null;
        }

        if (args.Length != 1 || args[0] is not (InstallEventLogSource or UninstallEventLogSource))
        {
            error.WriteLine($"Usage: SapAV.Engine {InstallEventLogSource} | {UninstallEventLogSource} " +
                            "(exactly one, lowercase, no other arguments; run elevated).");
            return ExitFailed;
        }

        var installer = new EventLogSourceInstaller(eventLog, locationCheck);
        try
        {
            return args[0] == InstallEventLogSource ? Install(installer, output, error) : Uninstall(installer, output, error);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            error.WriteLine($"Access denied: run this from an elevated (administrator) prompt. {ex.Message}");
            return ExitNotElevated;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException
                                       or System.ComponentModel.Win32Exception
                                       or System.Diagnostics.Eventing.Reader.EventLogException)
        {
            error.WriteLine($"Event Log '{installer.LogName}' / source '{installer.Source}' could not be changed: {ex.Message}");
            return ExitFailed;
        }
    }

    private static int Install(EventLogSourceInstaller installer, TextWriter output, TextWriter error)
    {
        var outcome = installer.Install();
        switch (outcome.Result)
        {
            case EventLogSourceInstallResult.Created:
                output.WriteLine($"Event Log '{installer.LogName}' with source '{installer.Source}' created (restricted access).");
                return ExitSuccess;
            case EventLogSourceInstallResult.Migrated:
                output.WriteLine($"Event Log source '{installer.Source}' moved from the {EventLogSourceInstaller.LegacyLogName} log " +
                                 $"to the dedicated '{installer.LogName}' log (restricted access).");
                return ExitSuccess;
            case EventLogSourceInstallResult.AlreadyRegistered:
                output.WriteLine($"Event Log source '{installer.Source}' is already in the '{installer.LogName}' log; settings re-applied.");
                return ExitSuccess;
            case EventLogSourceInstallResult.MessageFileNotProtected:
                error.WriteLine($"Refused: {outcome.Detail}. The message DLL must be in a folder only administrators can " +
                                "change (e.g. under Program Files). Nothing was changed.");
                return ExitUnprotectedMessageFile;
            default:
                error.WriteLine($"Refused: Event Log source '{installer.Source}' is registered in the '{outcome.Detail}' log, " +
                                $"not {installer.LogName} or {EventLogSourceInstaller.LegacyLogName}. Remove it there first.");
                return ExitConflict;
        }
    }

    private static int Uninstall(EventLogSourceInstaller installer, TextWriter output, TextWriter error)
    {
        var outcome = installer.Uninstall();
        switch (outcome.Result)
        {
            case EventLogSourceUninstallResult.Removed:
                output.WriteLine($"Event Log '{installer.LogName}' and source '{installer.Source}' removed.");
                return ExitSuccess;
            case EventLogSourceUninstallResult.NotRegistered:
                output.WriteLine($"Event Log '{installer.LogName}' and source '{installer.Source}' are not registered.");
                return ExitSuccess;
            default:
                error.WriteLine($"Refused: Event Log source '{installer.Source}' belongs to the '{outcome.OtherLog}' log, not {installer.LogName}.");
                return ExitConflict;
        }
    }
}
