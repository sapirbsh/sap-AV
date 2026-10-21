using System.Diagnostics;
using SapAV.Core.Alerts;

namespace SapAV.Engine.Alerts;

/// <summary>Event ID and entry type of one <see cref="AlertType"/>.</summary>
public readonly record struct AlertEventDefinition(int EventId, EventLogEntryType EntryType);

/// <summary>
/// Fixed Windows Event Log IDs per alert type (ROADMAP X2). SIEM rules key on these: never change or reuse an ID.
/// </summary>
/// <remarks>
/// All alerts go to the <b>Application</b> log with source <b>"sap-AV"</b>; the message is the alert as JSON
/// (<see cref="AlertEventMessage"/>).
/// <code>
/// Event ID | Alert type               | Entry type  | Meaning
/// ---------+--------------------------+-------------+--------------------------------------------------
///   1001   | MaliciousFile            | Error       | File with a Malicious verdict
///   1002   | SuspiciousFile           | Warning     | File with a Suspicious verdict
///   1003   | PotentiallyUnwantedFile  | Warning     | PUP / hack tool (threat pack, section E)
///   3001   | QuarantineRestored       | Information | User restored an item from quarantine (B2)
/// </code>
/// Ranges: 1000-1999 file detections, 2000-2999 system-change detections (persistence, Defender tampering,
/// honeytokens, process chains), 3000-3999 user / remediation actions, 9000-9999 engine health.
/// Entry type: Malicious = Error, Suspicious and PUP = Warning, informational = Information.
/// The engine's own diagnostic logging (ILogger) uses a different source, so these IDs stay alert-only.
/// </remarks>
public static class AlertEventCatalog
{
    public const string SourceName = "sap-AV";
    public const string LogName = "Application";

    public const int MaliciousFileEventId = 1001;
    public const int SuspiciousFileEventId = 1002;
    public const int PotentiallyUnwantedFileEventId = 1003;
    public const int QuarantineRestoredEventId = 3001;

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="type"/> is not a defined value.</exception>
    public static AlertEventDefinition For(AlertType type) => type switch
    {
        AlertType.MaliciousFile => new(MaliciousFileEventId, EventLogEntryType.Error),
        AlertType.SuspiciousFile => new(SuspiciousFileEventId, EventLogEntryType.Warning),
        AlertType.PotentiallyUnwantedFile => new(PotentiallyUnwantedFileEventId, EventLogEntryType.Warning),
        AlertType.QuarantineRestored => new(QuarantineRestoredEventId, EventLogEntryType.Information),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Undefined alert type."),
    };
}
