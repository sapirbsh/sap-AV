using System.Text;

namespace SapAV.Core.Hashing;

/// <summary>
/// Exact path handling (B3 review H1). Win32 path normalisation (<see cref="Path.GetFullPath(string)"/>, and CreateFileW
/// on a plain path) strips trailing dots and spaces from every component, so <c>evil.exe.</c> opens <c>evil.exe</c> and
/// <c>sap-AV.</c> compares equal to <c>sap-AV</c>. NTFS allows such names (created through <c>\\?\</c>), so malware can use
/// them to hide behind a harmless file or an excluded folder. These helpers keep every name exactly.
/// </summary>
internal static class ExactPath
{
    private const string ExtendedPrefix = @"\\?\";
    private const string ExtendedUncPrefix = @"\\?\UNC\";

    /// <summary>
    /// The exact extended-length form (<c>\\?\C:\...</c> or <c>\\?\UNC\server\share\...</c>) of a fully qualified drive or UNC
    /// path. Only <c>.</c> / <c>..</c> components and repeated separators are resolved (and <c>/</c> mapped to <c>\</c>) for
    /// plain paths; every other component is kept as written, trailing dots and spaces included. Extended input is kept
    /// verbatim (a <c>.</c> or <c>..</c> component there is refused). Null for anything else (relative, drive-relative,
    /// device namespace, <c>\\?\GLOBALROOT</c>, ...).
    /// </summary>
    public static string? ToExtended(string? path)
    {
        if (string.IsNullOrEmpty(path) || path.Contains('\0'))
        {
            return null;
        }

        bool extended = path.StartsWith(ExtendedPrefix, StringComparison.Ordinal);
        string text = extended ? path : path.Replace('/', '\\');
        string root;
        string rest;
        if (extended)
        {
            if (text.StartsWith(ExtendedUncPrefix, StringComparison.OrdinalIgnoreCase))
            {
                if (!SplitUnc(text[ExtendedUncPrefix.Length..], out root, out rest))
                {
                    return null;
                }
            }
            else if (IsDriveRooted(text.AsSpan(ExtendedPrefix.Length)))
            {
                root = ExtendedPrefix + text.Substring(ExtendedPrefix.Length, 2);
                rest = text[(ExtendedPrefix.Length + 2)..];
            }
            else
            {
                return null;
            }
        }
        else if (text.StartsWith(@"\\", StringComparison.Ordinal))
        {
            if (text.Length > 2 && text[2] is '.' or '?' || !SplitUnc(text[2..], out root, out rest))
            {
                return null; // \\.\ device paths, or a server without a share
            }
        }
        else if (IsDriveRooted(text))
        {
            root = ExtendedPrefix + text[..2];
            rest = text[2..];
        }
        else
        {
            return null;
        }

        var parts = new List<string>();
        foreach (var part in rest.Split('\\'))
        {
            if (part.Length == 0)
            {
                continue;
            }

            if (part is "." or "..")
            {
                if (extended)
                {
                    return null;
                }

                if (part == ".." && parts.Count > 0)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                continue;
            }

            parts.Add(part);
        }

        var result = new StringBuilder(root).Append('\\');
        result.AppendJoin('\\', parts);
        return result.ToString();
    }

    /// <summary>True if a component ends in a dot or space (it can't be named exactly without <c>\\?\</c>).</summary>
    public static bool NeedsExtended(string path) =>
        path.Split('\\', '/').Any(p => p.Length > 0 && p is not ("." or "..") && p[^1] is '.' or ' ');

    /// <summary>
    /// The usual form for display and comparison: drive (<c>C:\...</c>) or UNC (<c>\\server\...</c>), without the
    /// <c>\\?\</c> prefix. Only for strings that are compared, never for opening a name that <see cref="NeedsExtended"/>.
    /// </summary>
    public static string StripPrefix(string extended) =>
        extended.StartsWith(ExtendedUncPrefix, StringComparison.OrdinalIgnoreCase) ? @"\\" + extended[ExtendedUncPrefix.Length..]
        : extended.StartsWith(ExtendedPrefix, StringComparison.Ordinal) ? extended[ExtendedPrefix.Length..]
        : extended;

    /// <summary>The path in the form that opens exactly this name: plain when that is lossless, otherwise <c>\\?\</c>.</summary>
    public static string ForOpening(string extended) => NeedsExtended(StripPrefix(extended)) ? extended : StripPrefix(extended);

    private static bool IsDriveRooted(ReadOnlySpan<char> text) =>
        text.Length >= 3 && char.IsAsciiLetter(text[0]) && text[1] == ':' && text[2] == '\\';

    private static bool SplitUnc(string afterSlashes, out string root, out string rest)
    {
        var pieces = afterSlashes.Split('\\', 3);
        if (pieces.Length < 2 || pieces[0].Length == 0 || pieces[1].Length == 0)
        {
            root = rest = string.Empty;
            return false;
        }

        root = ExtendedUncPrefix + pieces[0] + "\\" + pieces[1];
        rest = pieces.Length == 3 ? pieces[2] : string.Empty;
        return true;
    }
}
