using System.Security.AccessControl;
using System.Security.Principal;

namespace SapAV.Engine.EventLogging;

/// <summary>
/// The security descriptor of the dedicated "sap-AV" event log (registry value <c>CustomSD</c> under
/// <c>HKLM\SYSTEM\CurrentControlSet\Services\EventLog\sap-AV</c>; ROADMAP B6 / X2 M1).
/// </summary>
/// <remarks>
/// <para>
/// Access bits, from Microsoft Learn, "Event Logging Security"
/// (https://learn.microsoft.com/windows/win32/eventlog/event-logging-security): the CustomSD of a log is checked by the
/// Event Log service with these log-specific rights: <c>ELF_LOGFILE_READ</c> = 0x0001 (read the log),
/// <c>ELF_LOGFILE_WRITE</c> = 0x0002 (write events: RegisterEventSource / ReportEvent), <c>ELF_LOGFILE_CLEAR</c> =
/// 0x0004 (clear the log; backing it up needs SeBackupPrivilege, not an ACE). The standard rights are the usual
/// <c>STANDARD_RIGHTS_REQUIRED</c> = 0x000F0000 (DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER). Windows' own default for
/// the Application log grants SYSTEM <c>0xf0007</c> and Administrators <c>0x7</c>; the CustomSD value itself is
/// documented in "Eventlog Key" (https://learn.microsoft.com/windows/win32/eventlog/eventlog-key).
/// </para>
/// <para>
/// The descriptor (<see cref="Sddl"/>):
/// <code>
/// O:BA G:SY                    owner Administrators, group SYSTEM
/// (A;;0xf0007;;;SY)            SYSTEM: read + write + clear + standard rights (the service writes as LocalSystem)
/// (A;;0x7;;;BA)                Administrators: read + write + clear (the elevated installer and console debugging)
/// (A;;0x1;;;S-1-5-32-573)      Event Log Readers: read only
/// </code>
/// No other ACE: Users, Authenticated Users, INTERACTIVE, services and Everyone get nothing, so a normal user can neither
/// forge (write) nor flood alerts, read them or clear them. Compared with the Application log this drops the write grants
/// to INTERACTIVE, SERVICE, BATCH and Authenticated Users. There are no deny ACEs: nothing is allowed that would need one.
/// </para>
/// </remarks>
public static class EventLogCustomSd
{
    public const int LogFileRead = 0x0001;
    public const int LogFileWrite = 0x0002;
    public const int LogFileClear = 0x0004;

    /// <summary>STANDARD_RIGHTS_REQUIRED: DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER.</summary>
    public const int StandardRightsRequired = 0x000F0000;

    /// <summary>Event Log Readers (BUILTIN, S-1-5-32-573).</summary>
    public static readonly SecurityIdentifier EventLogReaders = new("S-1-5-32-573");

    public static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>The exact CustomSD string written by the installer.</summary>
    public static string Sddl { get; } = Build();

    /// <summary>Builds the SDDL from the access bits above.</summary>
    public static string Build()
    {
        int all = LogFileRead | LogFileWrite | LogFileClear;
        return "O:BAG:SYD:" +
               Ace(StandardRightsRequired | all, "SY") +
               Ace(all, "BA") +
               Ace(LogFileRead, EventLogReaders.Value);
    }

    /// <summary>Parses a CustomSD value; null if it isn't valid SDDL.</summary>
    public static RawSecurityDescriptor? TryParse(string? sddl)
    {
        if (string.IsNullOrWhiteSpace(sddl))
        {
            return null;
        }

        try
        {
            return new RawSecurityDescriptor(sddl);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// True if <paramref name="sddl"/> is the same descriptor as <see cref="Sddl"/> (compared in binary form, so
    /// "S-1-5-32-573" and its alias "ER" are equal, but any other ACE, right or owner is a mismatch).
    /// </summary>
    public static bool IsExpected(string? sddl)
    {
        var actual = TryParse(sddl);
        if (actual is null)
        {
            return false;
        }

        return Binary(actual).AsSpan().SequenceEqual(Binary(new RawSecurityDescriptor(Sddl)));
    }

    private static string Ace(int mask, string sid) => $"(A;;0x{mask:x};;;{sid})";

    private static byte[] Binary(RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
}

/// <summary>
/// The classic-log settings written under <c>EventLog\&lt;log&gt;</c>: <c>CustomSD</c>, <c>MaxSize</c> (bytes, a multiple
/// of 64 KB), <c>Retention</c> (0 = overwrite as needed) and <c>AutoBackupLogFiles</c> (0 = off).
/// </summary>
public sealed record EventLogSettings(string CustomSd, int MaxSizeBytes, int RetentionSeconds, bool AutoBackup)
{
    /// <summary>
    /// The sap-AV log: the restricted <see cref="EventLogCustomSd.Sddl"/>, 20 MB, overwrite the oldest events as needed,
    /// no automatic backups. Alerts are capped at <see cref="Alerts.AlertEventMessage.MaxMessageChars"/> and rate-limited
    /// (B3), so 20 MB holds thousands of alerts; overwriting keeps the newest when it is full (a full log that refuses
    /// writes would hide new alerts), and only SYSTEM / Administrators can write, so nobody else can flood it.
    /// </summary>
    public static EventLogSettings Default { get; } = new(EventLogCustomSd.Sddl, 20 * 1024 * 1024, 0, false);
}
