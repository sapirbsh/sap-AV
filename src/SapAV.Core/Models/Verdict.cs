using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Models;

/// <summary>
/// Outcome of judging a scanned item. Values are ordered by severity, so the worst
/// verdict can be picked with a normal comparison (<c>Malicious &gt; Suspicious &gt; Clean</c>).
/// Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<Verdict>))]
public enum Verdict
{
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
}
