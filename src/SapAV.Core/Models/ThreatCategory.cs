using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Models;

/// <summary>
/// What kind of threat a <see cref="Detection"/> is about (E1, ROADMAP feature 11). Serialized to JSON by name; never
/// renumber or rename (the pipe, the Event Log payload and SIEM rules key on the names).
/// </summary>
/// <remarks>
/// <see cref="Pup"/> and <see cref="HackTool"/> are the "potentially unwanted" categories: their detections are Suspicious or
/// <see cref="Verdict.PotentiallyUnwanted"/>, never Malicious, and a PotentiallyUnwanted detection always has one of them
/// (<see cref="ThreatCategories.IsPotentiallyUnwanted"/>). A file that is both a hack tool and malware (a trojanized keygen)
/// has two detections, and the worse verdict (Malicious) wins.
/// </remarks>
[JsonConverter(typeof(StrictEnumConverter<ThreatCategory>))]
public enum ThreatCategory
{
    /// <summary>General malware or an unclassified finding (the default).</summary>
    Malware,

    /// <summary>Potentially unwanted program: adware, bundlers, "optimizers", cracks and activators.</summary>
    Pup,

    /// <summary>Hack tool: keygens, password crackers, exploit kits, license patchers.</summary>
    HackTool,

    /// <summary>Credential, cookie, token or wallet theft (T1555.003, T1539, T1552.001, T1005).</summary>
    Infostealer,

    /// <summary>Cryptocurrency miner running without the owner's consent (T1496.001).</summary>
    Miner,

    /// <summary>Turning off or weakening Microsoft Defender (exclusions, disabled protection; T1562.001).</summary>
    DefenderTampering,

    /// <summary>Proxy / PAC / hosts changes that redirect the browser or block security sites (T1557, T1562.001).</summary>
    BrowserHijack,
}

/// <summary>Helpers for <see cref="ThreatCategory"/>.</summary>
public static class ThreatCategories
{
    /// <summary>True for <see cref="ThreatCategory.Pup"/> and <see cref="ThreatCategory.HackTool"/>.</summary>
    public static bool IsPotentiallyUnwanted(ThreatCategory category) => category is ThreatCategory.Pup or ThreatCategory.HackTool;
}
