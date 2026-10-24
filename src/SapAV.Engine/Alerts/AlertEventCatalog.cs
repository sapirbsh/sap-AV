using System.Diagnostics;
using SapAV.Core.Alerts;

namespace SapAV.Engine.Alerts;

/// <summary>Event ID and entry type of one <see cref="AlertType"/>.</summary>
public readonly record struct AlertEventDefinition(int EventId, EventLogEntryType EntryType);

/// <summary>
/// Fixed Windows Event Log IDs per alert type (ROADMAP X2). SIEM rules key on these: never change or reuse an ID.
/// </summary>
/// <remarks>
/// All alerts go to the dedicated <b>"sap-AV"</b> log (B6; only SYSTEM and Administrators may write it) with source
/// <b>"sap-AV"</b>; the message is the alert as JSON
/// (<see cref="AlertEventMessage"/>).
/// <code>
/// Event ID | Alert type               | Entry type  | Meaning
/// ---------+--------------------------+-------------+--------------------------------------------------
///   1001   | MaliciousFile            | Error       | File with a Malicious verdict
///   1002   | SuspiciousFile           | Warning     | File with a Suspicious verdict
///   1003   | PotentiallyUnwantedFile  | Warning     | PUP / hack tool (threat pack, section E)
///   3001   | QuarantineRestored       | Information | User restored an item from quarantine (B2)
///   9001   | AlertsSuppressed         | Warning     | Summary of aggregated / rate-limited / dropped alerts (B3)
///   9002   | AutoQuarantineBurst      | Warning     | Auto-quarantine rate limit hit; the rest need the user (B3)
///   9003   | ScanRulesDegraded        | Warning     | No YARA rules loaded, or rule files failed (B3)
///   9004   | QuarantineStoreFull      | Error       | Quarantine quota or free-space floor reached (B3)
///   9008   | EngineFolderUntrusted    | Warning     | An engine folder isn't admin-only, so it is scanned, not excluded (B review H1)
/// </code>
/// Ranges: 1000-1999 file detections, 2000-2999 system-change detections (persistence, Defender tampering,
/// honeytokens, process chains), 3000-3999 user / remediation actions, 9000-9999 engine health.
/// Entry type: Malicious = Error, Suspicious and PUP = Warning, informational = Information.
/// The engine's own diagnostic logging (ILogger) uses a different source, so these IDs stay alert-only.
/// </remarks>
public static class AlertEventCatalog
{
    public const string SourceName = "sap-AV";
    /// <summary>The dedicated log (B6). Until B6 it was "Application", which any user could write to.</summary>
    public const string LogName = "sap-AV";

    public const int MaliciousFileEventId = 1001;
    public const int SuspiciousFileEventId = 1002;
    public const int PotentiallyUnwantedFileEventId = 1003;
    public const int QuarantineRestoredEventId = 3001;
    public const int AlertsSuppressedEventId = 9001;
    public const int AutoQuarantineBurstEventId = 9002;
    public const int ScanRulesDegradedEventId = 9003;
    public const int QuarantineStoreFullEventId = 9004;
    public const int EngineFolderUntrustedEventId = 9008;

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="type"/> is not a defined value.</exception>
    public static AlertEventDefinition For(AlertType type) => type switch
    {
        AlertType.MaliciousFile => new(MaliciousFileEventId, EventLogEntryType.Error),
        AlertType.SuspiciousFile => new(SuspiciousFileEventId, EventLogEntryType.Warning),
        AlertType.PotentiallyUnwantedFile => new(PotentiallyUnwantedFileEventId, EventLogEntryType.Warning),
        AlertType.QuarantineRestored => new(QuarantineRestoredEventId, EventLogEntryType.Information),
        AlertType.AlertsSuppressed => new(AlertsSuppressedEventId, EventLogEntryType.Warning),
        AlertType.AutoQuarantineBurst => new(AutoQuarantineBurstEventId, EventLogEntryType.Warning),
        AlertType.ScanRulesDegraded => new(ScanRulesDegradedEventId, EventLogEntryType.Warning),
        AlertType.QuarantineStoreFull => new(QuarantineStoreFullEventId, EventLogEntryType.Error),
        AlertType.EngineFolderUntrusted => new(EngineFolderUntrustedEventId, EventLogEntryType.Warning),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Undefined alert type."),
    };
}
