using System.Text.RegularExpressions;

namespace SapAV.Engine.Processes;

/// <summary>Settings of the process event source (E8), section <c>ProcessEvents</c>.</summary>
public sealed partial class ProcessEventSourceOptions
{
    public const string SectionName = "ProcessEvents";

    /// <summary>The ETW session name the engine uses. Fixed, so a session leaked by a crashed engine is replaced at the next start.</summary>
    public const string DefaultSessionName = "sap-AV-Engine-KernelProcess";

    /// <summary>Every sap-AV ETW session name starts with this.</summary>
    public const string SessionNamePrefix = "sap-AV-";

    /// <summary>Off: the source is registered but never started.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Start the ETW session in a console (debug) run too. Off by default: only the Windows service or a SYSTEM process starts it,
    /// so an elevated test host or a CI runner (which builds and starts hosts) never creates a kernel trace session.
    /// </summary>
    public bool StartInConsole { get; set; }

    /// <summary>The ETW session name; must match <c>sap-AV-[A-Za-z0-9-]+</c> (an invalid name falls back to the default).</summary>
    public string SessionName { get; set; } = DefaultSessionName;

    /// <summary>ETW buffer size per processor in MB (1-64). Process events are rare; the default is plenty.</summary>
    public int BufferSizeMB { get; set; } = 4;

    /// <summary>How long a stop waits for the event thread to finish after the session was stopped.</summary>
    public TimeSpan StopTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>The validated session name: <see cref="SessionName"/> if it is a valid sap-AV name, otherwise the default.</summary>
    public string EffectiveSessionName => IsValidSessionName(SessionName) ? SessionName : DefaultSessionName;

    public static bool IsValidSessionName(string? name) => name is not null && name.Length <= 128 && SessionNameRegex().IsMatch(name);

    [GeneratedRegex(@"^sap-AV-[A-Za-z0-9-]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex SessionNameRegex();
}
