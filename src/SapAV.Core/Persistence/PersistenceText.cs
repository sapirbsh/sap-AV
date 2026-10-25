using SapAV.Core.Hashing;
using SapAV.Core.Text;

namespace SapAV.Core.Persistence;

/// <summary>Caps and sanitizing shared by the persistence models.</summary>
internal static class PersistenceText
{
    /// <summary>
    /// An identifier (key path, value name, file path) with controls and unpaired surrogates mapped to U+FFFD
    /// (<see cref="SafeText.Identifier"/>) and cut at <paramref name="maxLength"/> with an ellipsis.
    /// </summary>
    public static string Identifier(string value, int maxLength)
    {
        var safe = SafeText.Identifier(value);
        if (safe.Length <= maxLength)
        {
            return safe;
        }

        int cut = maxLength - 1;
        if (char.IsLowSurrogate(safe[cut]) && char.IsHighSurrogate(safe[cut - 1]))
        {
            cut--;
        }

        return string.Concat(safe.AsSpan(0, cut), SafeText.Ellipsis.ToString());
    }

    /// <summary>
    /// The normalized form of a fully qualified <b>local drive</b> path (dots resolved, exact names kept, <c>\\?\</c> only
    /// when needed: <see cref="ExactPath.ForOpening"/>), or null for anything else (UNC, device, relative).
    /// </summary>
    public static string? NormalizeLocalPath(string? path)
    {
        if (ExactPath.ToExtended(path) is not { } extended || extended.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return ExactPath.ForOpening(extended);
    }

    /// <summary>True if <paramref name="path"/> is already in <see cref="NormalizeLocalPath"/> form.</summary>
    public static bool IsNormalizedLocalPath(string? path) =>
        path is not null && string.Equals(NormalizeLocalPath(path), path, StringComparison.Ordinal);
}
