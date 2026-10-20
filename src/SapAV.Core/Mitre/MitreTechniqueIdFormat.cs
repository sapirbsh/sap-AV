using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace SapAV.Core.Mitre;

/// <summary>
/// Format validation and lenient parsing of MITRE ATT&amp;CK technique IDs (<c>T####</c> or <c>T####.###</c>).
/// </summary>
public static partial class MitreTechniqueIdFormat
{
    // \A...\z (not ^...$): '$' would also match before a trailing '\n'.
    [GeneratedRegex(@"\AT[0-9]{4}(\.[0-9]{3})?\z", RegexOptions.CultureInvariant)]
    private static partial Regex FormatRegex();

    /// <summary>True if <paramref name="id"/> is a well-formed technique ID (case-sensitive, no whitespace).</summary>
    public static bool IsValid([NotNullWhen(true)] string? id) =>
        id is not null && FormatRegex().IsMatch(id);

    /// <exception cref="ArgumentException">The ID is null, empty or malformed.</exception>
    public static void EnsureValid([NotNull] string? id, string paramName)
    {
        if (!IsValid(id))
        {
            throw new ArgumentException(
                $"Invalid MITRE technique ID '{id}'. Expected T#### or T####.###.", paramName);
        }
    }

    /// <summary>
    /// Parses free-form rule-author input (e.g. a YARA <c>mitre</c> meta value such as
    /// <c>"t1059.001, T1566.001"</c>). Splits on commas, semicolons and whitespace, trims and
    /// upper-cases each token, drops invalid tokens and duplicates, and keeps the original order.
    /// Never throws.
    /// </summary>
    /// <returns>True if at least one valid ID was found.</returns>
    public static bool TryNormalize(string? raw, out IReadOnlyList<string> ids)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var token in Tokenize(raw))
        {
            var upper = token.ToUpperInvariant();
            if (IsValid(upper) && seen.Add(upper))
            {
                result.Add(upper);
            }
        }

        ids = result.AsReadOnly();
        return result.Count > 0;
    }

    /// <summary>
    /// The tokens of <paramref name="raw"/> that <see cref="TryNormalize"/> drops because they are not valid IDs
    /// even after upper-casing (e.g. <c>"001"</c> in <c>"T1059,001"</c>), in their original form and order.
    /// Duplicates of a valid ID are not listed: dropping them keeps the meaning. Never throws.
    /// </summary>
    public static IReadOnlyList<string> InvalidTokens(string? raw) =>
        Tokenize(raw).Where(token => !IsValid(token.ToUpperInvariant())).ToArray();

    /// <summary>Splits on commas, semicolons and whitespace; empty tokens are skipped.</summary>
    private static IEnumerable<string> Tokenize(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            yield break;
        }

        int start = 0;
        for (int i = 0; i <= raw.Length; i++)
        {
            if (i < raw.Length && !IsSeparator(raw[i]))
            {
                continue;
            }

            if (i > start)
            {
                yield return raw[start..i];
            }

            start = i + 1;
        }
    }

    /// <summary>
    /// Like <see cref="TryNormalize"/>, but always returns a usable primary ID: the first valid ID
    /// in <paramref name="raw"/>, or <paramref name="fallbackId"/> if there is none. The remaining
    /// valid IDs become secondaries. Never throws on <paramref name="raw"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="fallbackId"/> is malformed (a programming error).</exception>
    public static MitreTechniqueSelection SelectOrDefault(
        string? raw, string fallbackId = MitreTechniqueIds.MaliciousFile)
    {
        EnsureValid(fallbackId, nameof(fallbackId));

        if (!TryNormalize(raw, out var ids))
        {
            return new MitreTechniqueSelection(fallbackId, Array.Empty<string>());
        }

        return new MitreTechniqueSelection(ids[0], ids.Skip(1).ToArray());
    }

    private static bool IsSeparator(char c) => c is ',' or ';' || char.IsWhiteSpace(c);
}

/// <summary>
/// A primary technique ID plus secondary IDs, ready to pass to a <see cref="Models.Detection"/>.
/// All IDs are validated (<see cref="MitreTechniqueIdFormat.IsValid"/>); secondaries are stored as a
/// read-only copy. Equality compares <see cref="SecondaryIds"/> element by element (order matters).
/// </summary>
public sealed record MitreTechniqueSelection
{
    private readonly string _primaryId = string.Empty;
    private readonly IReadOnlyList<string> _secondaryIds = [];

    /// <exception cref="ArgumentException">An ID is null, empty or malformed, or the list is null.</exception>
    public MitreTechniqueSelection(string primaryId, IReadOnlyList<string> secondaryIds)
    {
        PrimaryId = primaryId;
        SecondaryIds = secondaryIds;
    }

    public string PrimaryId
    {
        get => _primaryId;
        init
        {
            MitreTechniqueIdFormat.EnsureValid(value, nameof(PrimaryId));
            _primaryId = value;
        }
    }

    public IReadOnlyList<string> SecondaryIds
    {
        get => _secondaryIds;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(SecondaryIds));
            var copy = value.ToArray();
            foreach (var id in copy)
            {
                MitreTechniqueIdFormat.EnsureValid(id, nameof(SecondaryIds));
            }

            _secondaryIds = Array.AsReadOnly(copy);
        }
    }

    public bool Equals(MitreTechniqueSelection? other) =>
        other is not null
        && (ReferenceEquals(this, other)
            || (string.Equals(_primaryId, other._primaryId, StringComparison.Ordinal)
                && _secondaryIds.SequenceEqual(other._secondaryIds, StringComparer.Ordinal)));

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(_primaryId, StringComparer.Ordinal);
        foreach (var id in _secondaryIds)
        {
            hash.Add(id, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }
}
