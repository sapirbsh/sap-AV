using System.Text.Json.Serialization;
using SapAV.Core.Mitre;

namespace SapAV.Core.Models;

/// <summary>
/// One finding about a scanned item. A detection is always Suspicious or Malicious;
/// a clean outcome is expressed by a <see cref="ScanResult"/> with no detections.
/// </summary>
/// <remarks>
/// Technique IDs are checked for format (<c>T####</c> or <c>T####.###</c>) but do not have to be in
/// <see cref="MitreCatalog"/>, because YARA rules may carry their own <c>mitre</c> meta value
/// (normalize those with <see cref="MitreTechniqueIdFormat.SelectOrDefault"/> first).
/// Invalid values, including from JSON deserialization, throw <see cref="ArgumentException"/>
/// (or a subclass). In JSON, <c>Verdict</c> and <c>Source</c> are required (<see cref="JsonRequiredAttribute"/>),
/// so a missing or null value, or an enum value that is not an exact name, throws
/// <see cref="System.Text.Json.JsonException"/> instead of defaulting to Clean / Blocklist.
/// </remarks>
public sealed record Detection
{
    private readonly Verdict _verdict;
    private readonly string _reason = string.Empty;
    private readonly string _techniqueId = string.Empty;
    private readonly IReadOnlyList<string> _secondaryTechniqueIds = [];
    private readonly DetectionSource _source;

    public Detection(
        Verdict verdict,
        string reason,
        string techniqueId,
        DetectionSource source,
        IReadOnlyList<string>? secondaryTechniqueIds = null)
    {
        Verdict = verdict;
        Reason = reason;
        TechniqueId = techniqueId;
        Source = source;
        SecondaryTechniqueIds = secondaryTechniqueIds ?? [];
    }

    /// <exception cref="ArgumentOutOfRangeException">The verdict is Clean or not a defined value.</exception>
    [JsonRequired]
    public Verdict Verdict
    {
        get => _verdict;
        init
        {
            if (value is not (Verdict.Suspicious or Verdict.Malicious))
            {
                throw new ArgumentOutOfRangeException(nameof(Verdict), value,
                    "A detection must be Suspicious or Malicious.");
            }

            _verdict = value;
        }
    }

    /// <summary>Human-readable explanation, e.g. "SHA-256 found in local blocklist".</summary>
    public string Reason
    {
        get => _reason;
        init
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(Reason));
            _reason = value;
        }
    }

    /// <summary>Primary MITRE ATT&amp;CK technique ID, e.g. <c>T1547.001</c>.</summary>
    public string TechniqueId
    {
        get => _techniqueId;
        init
        {
            MitreTechniqueIdFormat.EnsureValid(value, nameof(TechniqueId));
            _techniqueId = value;
        }
    }

    /// <summary>Additional MITRE technique IDs (may be empty). Stored as a read-only copy.</summary>
    public IReadOnlyList<string> SecondaryTechniqueIds
    {
        get => _secondaryTechniqueIds;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(SecondaryTechniqueIds));
            var copy = value.ToArray();
            foreach (var id in copy)
            {
                MitreTechniqueIdFormat.EnsureValid(id, nameof(SecondaryTechniqueIds));
            }

            _secondaryTechniqueIds = Array.AsReadOnly(copy);
        }
    }

    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined <see cref="DetectionSource"/>.</exception>
    [JsonRequired]
    public DetectionSource Source
    {
        get => _source;
        init
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(nameof(Source), value, "Undefined detection source.");
            }

            _source = value;
        }
    }

    /// <summary>Value equality, comparing <see cref="SecondaryTechniqueIds"/> element by element (order matters).</summary>
    public bool Equals(Detection? other) =>
        other is not null
        && (ReferenceEquals(this, other)
            || (_verdict == other._verdict
                && _source == other._source
                && string.Equals(_reason, other._reason, StringComparison.Ordinal)
                && string.Equals(_techniqueId, other._techniqueId, StringComparison.Ordinal)
                && _secondaryTechniqueIds.SequenceEqual(other._secondaryTechniqueIds, StringComparer.Ordinal)));

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(_verdict);
        hash.Add(_source);
        hash.Add(_reason, StringComparer.Ordinal);
        hash.Add(_techniqueId, StringComparer.Ordinal);
        foreach (var id in _secondaryTechniqueIds)
        {
            hash.Add(id, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }
}
