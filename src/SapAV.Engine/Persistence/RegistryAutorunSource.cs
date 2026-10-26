using SapAV.Core.Persistence;

namespace SapAV.Engine.Persistence;

/// <summary>One source of persistence entries; adds to the context, may throw (the collector turns that into an issue).</summary>
internal interface IPersistenceSource
{
    string Name { get; }

    void Collect(PersistenceContext context);
}

/// <summary>
/// Registry autostarts (ROADMAP C2), read-only: Run / RunOnce / <c>Policies\Explorer\Run</c> (HKLM, HKLM WOW6432Node, and
/// each loaded user hive), Winlogon <c>Shell</c> / <c>Userinit</c> (HKLM and per user), and Image File Execution Options
/// (<c>Debugger</c>, filtered IFEO subkeys, and SilentProcessExit <c>MonitorProcess</c> with its <c>GlobalFlag</c>).
/// </summary>
/// <remarks>
/// <para>Users whose hive isn't loaded (not logged on) are reported once as <see cref="PersistenceIssueReason.HiveNotLoaded"/>
/// and skipped. Loading NTUSER.DAT as SYSTEM would need SeBackup/SeRestore, mount a user-writable file into the registry
/// (kernel hive parsing of attacker-controlled data), may write the hive's logs, and holding it can make that user's next
/// logon fail or fall back to a temporary profile. Their Startup folder is still collected (it needs no hive).</para>
/// <para>Run values turned off in Task Manager (<c>Explorer\StartupApproved\Run</c> / <c>Run32</c>, odd first byte) are
/// reported with Enabled false. Winlogon values list several programs separated by commas: one entry each, the value name
/// suffixed <c>[n]</c> from the second one on.</para>
/// </remarks>
internal sealed class RegistryAutorunSource : IPersistenceSource
{
    private const string CurrentVersion = @"Microsoft\Windows\CurrentVersion";
    private const string Approved = CurrentVersion + @"\Explorer\StartupApproved";
    private const string WinlogonKey = @"Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string IfeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string IfeoWowKey = @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SilentExitKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
    private const long MonitorSilentProcessExit = 0x200;

    public string Name => "registry autoruns";

    public void Collect(PersistenceContext context)
    {
        CollectRunKeys(context, RegistryRoot.LocalMachine, "SOFTWARE", null, context.Machine);
        CollectRunKeys(context, RegistryRoot.LocalMachine, @"SOFTWARE\WOW6432Node", null, context.Machine, wow: true);
        CollectWinlogon(context, RegistryRoot.LocalMachine, "SOFTWARE", null, context.Machine);
        foreach (var user in context.Users)
        {
            if (!context.CanContinue)
            {
                return;
            }

            if (!user.HiveLoaded)
            {
                context.AddIssue(null, user.Sid, @"HKU\" + user.Sid, PersistenceIssueReason.HiveNotLoaded,
                    "The user isn't logged on, so their registry hive isn't loaded; their Run, RunOnce and Winlogon values weren't collected.");
                continue;
            }

            CollectRunKeys(context, RegistryRoot.Users, user.Sid + @"\Software", user.Sid, user.Environment);
            CollectWinlogon(context, RegistryRoot.Users, user.Sid + @"\Software", user.Sid, user.Environment);
        }

        CollectIfeo(context, IfeoKey);
        CollectIfeo(context, IfeoWowKey);
        CollectSilentProcessExit(context);
    }

    private static void CollectRunKeys(
        PersistenceContext context, RegistryRoot root, string software, string? sid, EnvironmentBlock environment, bool wow = false)
    {
        string approvedRun = software.Replace(@"\WOW6432Node", string.Empty, StringComparison.OrdinalIgnoreCase) + @"\" + Approved + (wow ? @"\Run32" : @"\Run");
        CollectValues(context, root, $@"{software}\{CurrentVersion}\Run", PersistenceKind.RunKey, sid, environment, (root, approvedRun));
        CollectValues(context, root, $@"{software}\{CurrentVersion}\RunOnce", PersistenceKind.RunOnceKey, sid, environment, null);
        if (!wow)
        {
            CollectValues(context, root, $@"{software}\{CurrentVersion}\Policies\Explorer\Run", PersistenceKind.RunKey, sid, environment, null);
        }
    }

    private static void CollectValues(
        PersistenceContext context, RegistryRoot root, string path, PersistenceKind kind, string? sid, EnvironmentBlock environment,
        (RegistryRoot Root, string Path)? approval)
    {
        using var key = context.TryOpen(root, path, kind, sid, out var display);
        if (key is null)
        {
            return;
        }

        using var approved = approval is { } a ? context.TryOpen(a.Root, a.Path, kind, sid, out _) : null;
        foreach (var name in context.Names(key, subKeys: false, kind, sid, display))
        {
            if (!context.CanContinue)
            {
                return;
            }

            if (name.Length == 0 || PersistenceContext.ReadValue(key, name)?.AsString() is not { } command)
            {
                continue; // the default value and non-string values don't run
            }

            bool enabled = approved is null || IsApproved(PersistenceContext.ReadValue(approved, name));
            context.Add(new PersistenceEntry(kind, sid, display, name, command, context.Resolver.Resolve(command, environment), enabled));
        }
    }

    /// <summary>StartupApproved data: an odd first byte means turned off in Task Manager; missing means on.</summary>
    internal static bool IsApproved(RegistryData? data) => data?.AsBinary() is not { Length: > 0 } bytes || (bytes[0] & 1) == 0;

    private static void CollectWinlogon(PersistenceContext context, RegistryRoot root, string software, string? sid, EnvironmentBlock environment)
    {
        using var key = context.TryOpen(root, $@"{software}\{WinlogonKey}", PersistenceKind.WinlogonShell, sid, out var display);
        if (key is null)
        {
            return;
        }

        foreach (var (valueName, kind) in new[] { ("Shell", PersistenceKind.WinlogonShell), ("Userinit", PersistenceKind.WinlogonUserinit) })
        {
            if (PersistenceContext.ReadValue(key, valueName)?.AsString() is not { } value)
            {
                continue;
            }

            var programs = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < programs.Length && i < 32; i++)
            {
                string name = i == 0 ? valueName : $"{valueName}[{i}]";
                context.Add(new PersistenceEntry(kind, sid, display, name, programs[i], context.Resolver.Resolve(programs[i], environment), true));
            }
        }
    }

    private static void CollectIfeo(PersistenceContext context, string path)
    {
        using var ifeo = context.TryOpen(RegistryRoot.LocalMachine, path, PersistenceKind.IfeoDebugger, null, out var display);
        if (ifeo is null)
        {
            return;
        }

        foreach (var image in context.Names(ifeo, subKeys: true, PersistenceKind.IfeoDebugger, null, display))
        {
            if (!context.CanContinue)
            {
                return;
            }

            using var key = PersistenceContext.OpenSub(ifeo, image);
            if (key is null)
            {
                continue;
            }

            string imageDisplay = $@"{display}\{image}";
            AddDebugger(context, key, imageDisplay);

            // Filtered IFEO: UseFilter=1 and a subkey per full path (FilterFullPath) with its own Debugger.
            if (PersistenceContext.ReadValue(key, "UseFilter")?.AsNumber() is not (null or 0))
            {
                foreach (var filter in context.Names(key, subKeys: true, PersistenceKind.IfeoDebugger, null, imageDisplay).Take(64))
                {
                    using var sub = PersistenceContext.OpenSub(key, filter);
                    if (sub is not null)
                    {
                        AddDebugger(context, sub, $@"{imageDisplay}\{filter}");
                    }
                }
            }
        }
    }

    private static void AddDebugger(PersistenceContext context, IRegistryKeyReader key, string display)
    {
        if (PersistenceContext.ReadValue(key, "Debugger")?.AsString() is { } debugger && !string.IsNullOrWhiteSpace(debugger))
        {
            context.Add(new PersistenceEntry(PersistenceKind.IfeoDebugger, null, display, "Debugger", debugger,
                context.Resolver.Resolve(debugger, context.Machine), true));
        }
    }

    private static void CollectSilentProcessExit(PersistenceContext context)
    {
        using var exits = context.TryOpen(RegistryRoot.LocalMachine, SilentExitKey, PersistenceKind.IfeoSilentProcessExit, null, out var display);
        if (exits is null)
        {
            return;
        }

        foreach (var image in context.Names(exits, subKeys: true, PersistenceKind.IfeoSilentProcessExit, null, display))
        {
            if (!context.CanContinue)
            {
                return;
            }

            using var key = PersistenceContext.OpenSub(exits, image);
            if (key is null || PersistenceContext.ReadValue(key, "MonitorProcess")?.AsString() is not { } monitor || string.IsNullOrWhiteSpace(monitor))
            {
                continue;
            }

            // Windows launches the monitor only when the image's IFEO GlobalFlag has FLG_MONITOR_SILENT_PROCESS_EXIT and
            // ReportingMode has LAUNCH_MONITORPROCESS (1).
            long reporting = PersistenceContext.ReadValue(key, "ReportingMode")?.AsNumber() ?? 0;
            using var ifeo = context.TryOpen(RegistryRoot.LocalMachine, $@"{IfeoKey}\{image}", PersistenceKind.IfeoSilentProcessExit, null, out _);
            long flags = ifeo is null ? 0 : PersistenceContext.ReadValue(ifeo, "GlobalFlag")?.AsNumber() ?? 0;
            bool enabled = (flags & MonitorSilentProcessExit) != 0 && (reporting & 1) != 0;
            context.Add(new PersistenceEntry(PersistenceKind.IfeoSilentProcessExit, null, $@"{display}\{image}", "MonitorProcess", monitor,
                context.Resolver.Resolve(monitor, context.Machine), enabled));
        }
    }
}
