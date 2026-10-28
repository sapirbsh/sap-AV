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
///   2001   | MaliciousPersistence     | Error       | Autostart entry whose target or host is Malicious (C3)
///   2002   | SuspiciousPersistence    | Warning     | Autostart entry judged Suspicious by the persistence rules (C3)
///   3001   | QuarantineRestored       | Information | User restored an item from quarantine (B2)
///   9001   | AlertsSuppressed         | Warning     | Summary of aggregated / rate-limited / dropped alerts (B3)
///   9002   | AutoQuarantineBurst      | Warning     | Auto-quarantine rate limit hit; the rest need the user (B3)
///   9003   | ScanRulesDegraded        | Warning     | No YARA rules loaded, or rule files failed (B3)
///   9004   | QuarantineStoreFull      | Error       | Quarantine quota or free-space floor reached (B3)
///   9005   | QuarantineStoreUnavailable | Error     | The quarantine store / data folder can't be used (retried with backoff)
///   9006   | SandboxUnavailable       | Error       | No scan worker could start or load the rules: files are NotScanned
///   9007   | PipeUnavailable          | Error       | The engine pipe can't be created (name taken or failing): no GUI
///   9008   | EngineFolderUntrusted    | Warning     | An engine folder isn't admin-only, so it is scanned, not excluded (B review H1)
///   9009   | EventLogIntegrityDegraded | Error      | The sap-AV log's CustomSD or message DLL isn't the expected one (B6 M2)
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
    public const int MaliciousPersistenceEventId = 2001;
    public const int SuspiciousPersistenceEventId = 2002;
    public const int QuarantineRestoredEventId = 3001;
    public const int AlertsSuppressedEventId = 9001;
    public const int AutoQuarantineBurstEventId = 9002;
    public const int ScanRulesDegradedEventId = 9003;
    public const int QuarantineStoreFullEventId = 9004;
    public const int QuarantineStoreUnavailableEventId = 9005;
    public const int SandboxUnavailableEventId = 9006;
    public const int PipeUnavailableEventId = 9007;
    public const int EngineFolderUntrustedEventId = 9008;
    public const int EventLogIntegrityDegradedEventId = 9009;

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="type"/> is not a defined value.</exception>
    public static AlertEventDefinition For(AlertType type) => type switch
    {
        AlertType.MaliciousFile => new(MaliciousFileEventId, EventLogEntryType.Error),
        AlertType.SuspiciousFile => new(SuspiciousFileEventId, EventLogEntryType.Warning),
        AlertType.PotentiallyUnwantedFile => new(PotentiallyUnwantedFileEventId, EventLogEntryType.Warning),
        AlertType.MaliciousPersistence => new(MaliciousPersistenceEventId, EventLogEntryType.Error),
        AlertType.SuspiciousPersistence => new(SuspiciousPersistenceEventId, EventLogEntryType.Warning),
        AlertType.QuarantineRestored => new(QuarantineRestoredEventId, EventLogEntryType.Information),
        AlertType.AlertsSuppressed => new(AlertsSuppressedEventId, EventLogEntryType.Warning),
        AlertType.AutoQuarantineBurst => new(AutoQuarantineBurstEventId, EventLogEntryType.Warning),
        AlertType.ScanRulesDegraded => new(ScanRulesDegradedEventId, EventLogEntryType.Warning),
        AlertType.QuarantineStoreFull => new(QuarantineStoreFullEventId, EventLogEntryType.Error),
        AlertType.QuarantineStoreUnavailable => new(QuarantineStoreUnavailableEventId, EventLogEntryType.Error),
        AlertType.SandboxUnavailable => new(SandboxUnavailableEventId, EventLogEntryType.Error),
        AlertType.PipeUnavailable => new(PipeUnavailableEventId, EventLogEntryType.Error),
        AlertType.EngineFolderUntrusted => new(EngineFolderUntrustedEventId, EventLogEntryType.Warning),
        AlertType.EventLogIntegrityDegraded => new(EventLogIntegrityDegradedEventId, EventLogEntryType.Error),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Undefined alert type."),
    };
}
