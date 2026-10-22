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
    public const int ExitNotElevated = 5;

    /// <summary>
    /// Runs the command if <paramref name="args"/> is exactly one known command and returns its exit code.
    /// If any argument looks like a command (any letter case) but the command line isn't exactly that, prints the
    /// usage and returns <see cref="ExitFailed"/>: an installer typo must never start the engine instead.
    /// Otherwise returns null and the engine starts normally.
    /// </summary>
    public static int? TryRun(string[] args, IWindowsEventLog eventLog, TextWriter output, TextWriter error)
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

        var installer = new EventLogSourceInstaller(eventLog);
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
                                       or System.ComponentModel.Win32Exception)
        {
            error.WriteLine($"Event Log source '{installer.Source}' could not be changed: {ex.Message}");
            return ExitFailed;
        }
    }

    private static int Install(EventLogSourceInstaller installer, TextWriter output, TextWriter error)
    {
        switch (installer.Install(out var log))
        {
            case EventLogSourceInstallResult.Created:
                output.WriteLine($"Event Log source '{installer.Source}' registered in the {log} log.");
                return ExitSuccess;
            case EventLogSourceInstallResult.AlreadyRegistered:
                output.WriteLine($"Event Log source '{installer.Source}' is already registered in the {log} log.");
                return ExitSuccess;
            default:
                error.WriteLine($"Refused: Event Log source '{installer.Source}' is registered in the '{log}' log, " +
                                $"not {installer.LogName}. Remove it there first.");
                return ExitConflict;
        }
    }

    private static int Uninstall(EventLogSourceInstaller installer, TextWriter output, TextWriter error)
    {
        switch (installer.Uninstall(out var log))
        {
            case EventLogSourceUninstallResult.Removed:
                output.WriteLine($"Event Log source '{installer.Source}' removed.");
                return ExitSuccess;
            case EventLogSourceUninstallResult.NotRegistered:
                output.WriteLine($"Event Log source '{installer.Source}' is not registered.");
                return ExitSuccess;
            default:
                error.WriteLine($"Refused: Event Log source '{installer.Source}' belongs to the '{log}' log, not {installer.LogName}.");
                return ExitConflict;
        }
    }
}
