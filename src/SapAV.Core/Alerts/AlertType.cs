using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Alerts;

/// <summary>
/// What an <see cref="Alert"/> is about. Each type has a fixed Windows Event Log event ID and entry type
/// (table in <c>SapAV.Engine.Alerts.AlertEventCatalog</c>). Serialized to JSON by name; never renumber or rename,
/// SIEM rules key on these.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<AlertType>))]
public enum AlertType
{
    /// <summary>A scanned file with a Malicious verdict.</summary>
    MaliciousFile,

    /// <summary>A scanned file with a Suspicious verdict.</summary>
    SuspiciousFile,

    /// <summary>
    /// A potentially unwanted program or hack tool (ROADMAP feature 11). Verdict Suspicious. Produced once the
    /// threat-pack categories exist (section E); the event ID is fixed now.
    /// </summary>
    PotentiallyUnwantedFile,

    /// <summary>Information: the user restored an item from quarantine (B2). Verdict = the item's verdict.</summary>
    QuarantineRestored,

    // Engine health (B3). FilePath = what the alert is about (a file, the rules folder, the store); Verdict = the worst
    // verdict involved, or Suspicious ("needs attention") when no file verdict applies.

    /// <summary>Summary: alerts that were aggregated, rate-limited or dropped (alert queue full) since the last summary.</summary>
    AlertsSuppressed,

    /// <summary>More Malicious files than the auto-quarantine rate limit allows: the rest wait for the user to confirm.</summary>
    AutoQuarantineBurst,

    /// <summary>No YARA rules are loaded, or rule files failed to load: YARA can't detect (everything) until fixed.</summary>
    ScanRulesDegraded,

    /// <summary>The quarantine store is over its quota or the drive is below the free-space floor: nothing more is quarantined.</summary>
    QuarantineStoreFull,

    /// <summary>
    /// An engine folder (quarantine store, sandbox, install, rules) can't be verified as admin-only (owner, ACL, links), so it
    /// is scanned instead of excluded: someone who controls it could hide files there (review B H1).
    /// </summary>
    EngineFolderUntrusted,
}
