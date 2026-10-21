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
}
