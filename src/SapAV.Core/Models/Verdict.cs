using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Models;

/// <summary>
/// Outcome of judging a scanned item. Values are ordered by severity, so the worst verdict can be picked with a normal
/// comparison (<c>Malicious &gt; PotentiallyUnwanted &gt; Suspicious &gt; Clean</c>). Serialized to JSON by name, never by
/// number (the numbers changed in E1 when PotentiallyUnwanted was inserted; nothing may persist them).
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<Verdict>))]
public enum Verdict
{
    Clean = 0,
    Suspicious = 1,

    /// <summary>
    /// A PUP or hack tool (keygen, crack, activator, adware; E1). Worse than Suspicious because it is known what it is, but
    /// <b>never quarantined automatically</b> (CLAUDE.md): the user decides. Its detection's category is
    /// <see cref="ThreatCategory.Pup"/> or <see cref="ThreatCategory.HackTool"/>.
    /// </summary>
    PotentiallyUnwanted = 2,

    Malicious = 3,
}
