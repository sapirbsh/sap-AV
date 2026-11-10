using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Text;

namespace SapAV.Core.Models;

/// <summary>
/// One finding about a scanned item. A detection is always Suspicious, PotentiallyUnwanted or Malicious;
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
/// <para><see cref="Category"/> (E1) is optional in JSON and defaults to <see cref="ThreatCategory.Malware"/>, so older JSON
/// still reads and a sender that leaves it out can never turn a finding into a potentially unwanted one (which is never
/// quarantined automatically). Verdict and category must agree: a PotentiallyUnwanted detection is Pup or HackTool, and a
/// Pup / HackTool detection is never Malicious (<see cref="ArgumentException"/> otherwise). The constructor (also used by
/// JSON) sets the category before the verdict; a <c>with</c> that changes both must go through the constructor instead.</para>
/// </remarks>
public sealed record Detection
{
    private readonly Verdict _verdict;
    private readonly string _reason = string.Empty;
    private readonly string _techniqueId = string.Empty;
    private readonly IReadOnlyList<string> _secondaryTechniqueIds = [];
    private readonly DetectionSource _source;
    private readonly ThreatCategory _category;

    public Detection(
        Verdict verdict,
        string reason,
        string techniqueId,
        DetectionSource source,
        IReadOnlyList<string>? secondaryTechniqueIds = null,
        ThreatCategory category = ThreatCategory.Malware)
    {
        Category = category; // first: the verdict is checked against it (no verdict yet, so this check is the enum only)
        Verdict = verdict;
        Reason = reason;
        TechniqueId = techniqueId;
        Source = source;
        SecondaryTechniqueIds = secondaryTechniqueIds ?? [];
    }

    /// <exception cref="ArgumentOutOfRangeException">The verdict is Clean or not a defined value.</exception>
    /// <exception cref="ArgumentException">The verdict doesn't fit <see cref="Category"/>.</exception>
    [JsonRequired]
    public Verdict Verdict
    {
        get => _verdict;
        init
        {
            if (value is not (Verdict.Suspicious or Verdict.PotentiallyUnwanted or Verdict.Malicious))
            {
                throw new ArgumentOutOfRangeException(nameof(Verdict), value,
                    "A detection must be Suspicious, PotentiallyUnwanted or Malicious.");
            }

            EnsureFits(value, _category, nameof(Verdict));
            _verdict = value;
        }
    }

    /// <summary>What kind of threat this is (E1); <see cref="ThreatCategory.Malware"/> unless a rule says otherwise.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined <see cref="ThreatCategory"/>.</exception>
    /// <exception cref="ArgumentException">The category doesn't fit <see cref="Verdict"/>.</exception>
    public ThreatCategory Category
    {
        get => _category;
        init
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(nameof(Category), value, "Undefined threat category.");
            }

            EnsureFits(_verdict, value, nameof(Category));
            _category = value;
        }
    }

    /// <summary>
    /// PotentiallyUnwanted needs a Pup / HackTool category, and Pup / HackTool is never Malicious. <c>default(Verdict)</c>
    /// (Clean) means "not set yet" while the constructor runs.
    /// </summary>
    private static void EnsureFits(Verdict verdict, ThreatCategory category, string parameter)
    {
        bool unwantedCategory = ThreatCategories.IsPotentiallyUnwanted(category);
        if (verdict == Verdict.PotentiallyUnwanted && !unwantedCategory)
        {
            throw new ArgumentException($"A PotentiallyUnwanted detection must be Pup or HackTool, not {category}.", parameter);
        }

        if (verdict == Verdict.Malicious && unwantedCategory)
        {
            throw new ArgumentException($"A {category} detection can't be Malicious (it is never quarantined automatically).", parameter);
        }
    }

    /// <summary>Longest <see cref="Reason"/> kept, in characters (longer ones are cut and end with an ellipsis).</summary>
    public const int MaxReasonLength = 1024;

    /// <summary>Human-readable explanation, e.g. "SHA-256 found in local blocklist".</summary>
    /// <remarks>
    /// Sanitised on every assignment (constructor, <c>with</c>, JSON) with <see cref="SafeText.SingleLine"/>:
    /// one trimmed line, line breaks and controls become spaces, bidi controls become U+FFFD, capped at
    /// <see cref="MaxReasonLength"/>. Reasons embed untrusted text (file names, YARA rule names), and they go to
    /// the Event Log, SIEMs and the pipe. Sanitising here rather than rejecting keeps a scan from failing just
    /// because a file name contains an odd character.
    /// </remarks>
    /// <exception cref="ArgumentException">The value is null, or empty / whitespace after sanitising.</exception>
    public string Reason
    {
        get => _reason;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(Reason));
            var sanitized = SafeText.SingleLine(value, MaxReasonLength);
            if (sanitized.Length == 0)
            {
                throw new ArgumentException("The reason must not be empty or only whitespace/control characters.", nameof(Reason));
            }

            _reason = sanitized;
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
                && _category == other._category
                && string.Equals(_reason, other._reason, StringComparison.Ordinal)
                && string.Equals(_techniqueId, other._techniqueId, StringComparison.Ordinal)
                && _secondaryTechniqueIds.SequenceEqual(other._secondaryTechniqueIds, StringComparer.Ordinal)));

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(_verdict);
        hash.Add(_source);
        hash.Add(_category);
        hash.Add(_reason, StringComparer.Ordinal);
        hash.Add(_techniqueId, StringComparer.Ordinal);
        foreach (var id in _secondaryTechniqueIds)
        {
            hash.Add(id, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }
}
