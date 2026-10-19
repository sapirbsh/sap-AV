using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Models;

/// <summary>
/// Which part of the detection pipeline produced a <see cref="Detection"/>. Serialized to JSON by name.
/// </summary>
/// <remarks>
/// There is deliberately no "Signature" source: the Authenticode check only decides which later
/// steps run (ROADMAP.md, feature 2); it never produces a detection by itself.
/// </remarks>
[JsonConverter(typeof(StrictEnumConverter<DetectionSource>))]
public enum DetectionSource
{
    Blocklist,
    Yara,
    Heuristic,
    VirusTotal,
    Persistence,
}
