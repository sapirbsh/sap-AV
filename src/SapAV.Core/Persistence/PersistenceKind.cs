using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Serialization;

namespace SapAV.Core.Persistence;

/// <summary>Where an autostart entry lives (ROADMAP C2). Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<PersistenceKind>))]
public enum PersistenceKind
{
    /// <summary>A <c>Run</c> value (also <c>Policies\Explorer\Run</c>), machine (incl. WOW6432Node) or per user.</summary>
    RunKey,

    /// <summary>A <c>RunOnce</c> value, machine (incl. WOW6432Node) or per user.</summary>
    RunOnceKey,

    /// <summary>Winlogon <c>Shell</c> (machine or per user).</summary>
    WinlogonShell,

    /// <summary>Winlogon <c>Userinit</c> (one entry per comma-separated program).</summary>
    WinlogonUserinit,

    /// <summary>Image File Execution Options <c>Debugger</c> (also a filtered IFEO subkey's).</summary>
    IfeoDebugger,

    /// <summary><c>SilentProcessExit\&lt;image&gt;\MonitorProcess</c> (enabled by IFEO <c>GlobalFlag</c> 0x200).</summary>
    IfeoSilentProcessExit,

    /// <summary>A service or driver under <c>HKLM\SYSTEM\CurrentControlSet\Services</c> (ImagePath or ServiceDll).</summary>
    Service,

    /// <summary>A file in a Startup folder (per user or all users); a <c>.lnk</c> is resolved to its target.</summary>
    StartupFolder,

    /// <summary>An action of a scheduled task (Exec, or a COM handler resolved through its CLSID).</summary>
    ScheduledTask,
}

/// <summary>The primary MITRE ATT&amp;CK technique of each kind (ROADMAP X1).</summary>
public static class PersistenceKinds
{
    /// <exception cref="ArgumentOutOfRangeException">Undefined kind.</exception>
    public static string TechniqueId(PersistenceKind kind) => kind switch
    {
        PersistenceKind.RunKey or PersistenceKind.RunOnceKey or PersistenceKind.StartupFolder => MitreTechniqueIds.RegistryRunKeysStartupFolder,
        PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit => MitreTechniqueIds.WinlogonHelperDll,
        PersistenceKind.IfeoDebugger or PersistenceKind.IfeoSilentProcessExit => MitreTechniqueIds.ImageFileExecutionOptionsInjection,
        PersistenceKind.Service => MitreTechniqueIds.WindowsService,
        PersistenceKind.ScheduledTask => MitreTechniqueIds.ScheduledTask,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Undefined persistence kind."),
    };
}
