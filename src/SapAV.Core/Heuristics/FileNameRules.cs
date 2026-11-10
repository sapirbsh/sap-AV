using System.Collections.Frozen;

namespace SapAV.Core.Heuristics;

/// <summary>Where a file sits, for the risky-folder heuristic.</summary>
public enum RiskyFolder
{
    None,
    Temp,
    Downloads,
    AppData,
}

/// <summary>Name and path rules (no file I/O).</summary>
public static class FileNameRules
{
    /// <summary>Extensions Windows runs directly (programs, installers, scripts, shortcuts).</summary>
    public static readonly FrozenSet<string> ExecutableExtensions = new[]
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".reg",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Scripts and other non-PE executables (the risky-folder rule uses these by name; PE files by content).</summary>
    public static readonly FrozenSet<string> ScriptExtensions = new[]
    {
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".reg",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Extensions a user trusts to be "just a document or picture", used as the decoy in a double extension.</summary>
    public static readonly FrozenSet<string> DecoyExtensions = new[]
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".rtf", ".txt", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
        ".zip", ".rar", ".7z", ".htm", ".html",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private const char RightToLeftOverrideChar = '\u202E';

    /// <summary>
    /// Returns the double extension (e.g. <c>.pdf.exe</c>) if <paramref name="fileName"/> ends in an executable
    /// extension directly after a decoy one. Spaces padding the decoy (<c>invoice.pdf      .exe</c>) count too.
    /// </summary>
    public static string? DoubleExtension(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        var name = Path.GetFileName(fileName).TrimEnd(' ', '.');
        var last = Path.GetExtension(name);
        if (!ExecutableExtensions.Contains(last))
        {
            return null;
        }

        var stem = name[..^last.Length].TrimEnd(' ');
        var decoy = Path.GetExtension(stem);
        return decoy.Length > 1 && DecoyExtensions.Contains(decoy) && stem.Length > decoy.Length
            ? (decoy + last).ToLowerInvariant()
            : null;
    }

    /// <summary>True if the name contains a right-to-left override character (U+202E).</summary>
    public static bool HasRightToLeftOverride(string fileName) =>
        Path.GetFileName(fileName).Contains(RightToLeftOverrideChar);

    /// <summary>
    /// Classifies a full path: inside a user's Downloads, the Temp folders (user, <c>%SystemRoot%\Temp</c>,
    /// <c>SystemTemp</c>, and this process's temp path), or a user's AppData. Matched by path segments
    /// (<c>\Users\&lt;name&gt;\Downloads\…</c>), so it works for every profile when the engine runs as SYSTEM.
    /// </summary>
    public static RiskyFolder ClassifyFolder(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string full;
        try
        {
            full = Path.GetFullPath(StripExtendedPrefix(path));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return RiskyFolder.None;
        }

        var tempRoot = Path.TrimEndingDirectorySeparator(Path.GetTempPath());
        if (IsInside(full, tempRoot))
        {
            return RiskyFolder.Temp;
        }

        var parts = full.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        // parts[0] is the drive ("C:"); the last part is the file name itself.
        int dirs = parts.Length - 1;
        if (dirs >= 3 && Is(parts[1], "Windows") && (Is(parts[2], "Temp") || Is(parts[2], "SystemTemp")))
        {
            return RiskyFolder.Temp;
        }

        // Directory parts are parts[1 .. dirs - 1]; "Users\<name>\X" needs X at index i + 2 <= dirs - 1.
        for (int i = 1; i + 3 <= dirs; i++)
        {
            if (!Is(parts[i], "Users"))
            {
                continue;
            }

            // parts[i + 1] is the user name.
            if (Is(parts[i + 2], "Downloads"))
            {
                return RiskyFolder.Downloads;
            }

            if (Is(parts[i + 2], "AppData"))
            {
                return i + 5 <= dirs && Is(parts[i + 3], "Local") && Is(parts[i + 4], "Temp")
                    ? RiskyFolder.Temp
                    : RiskyFolder.AppData;
            }
        }

        return RiskyFolder.None;

        static bool Is(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// E3: whether a file name looks machine-generated (what droppers and infostealers name their copies in AppData), and
    /// why; null when it doesn't. Deliberately narrow, so real program names don't match: the name without its extension must
    /// be 6-64 characters and either a GUID, or only letters and digits with no separators and one of: a hex string of 12+
    /// characters with letters and digits; letters and digits switching back and forth (3+ times, 8+ characters); or a run of
    /// 5+ consonants with under a quarter vowels (8+ characters, no pronounceable syllables). Words, separators
    /// (<c>ms-teams</c>, <c>chrome_proxy</c>), version suffixes (<c>python3</c>, <c>unins000</c>) don't match.
    /// </summary>
    public static string? RandomNameReason(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        string name = Path.GetFileName(fileName).TrimEnd(' ', '.');
        string ext = Path.GetExtension(name);
        string stem = ext.Length > 1 && ext.Length < name.Length ? name[..^ext.Length] : name;
        if (stem.Length is < 6 or > 64)
        {
            return null;
        }

        if (Guid.TryParseExact(stem, "D", out _) || Guid.TryParseExact(stem, "B", out _) || Guid.TryParseExact(stem, "N", out _))
        {
            return "its name is a GUID";
        }

        if (!stem.All(char.IsAsciiLetterOrDigit))
        {
            return null;
        }

        string lower = stem.ToLowerInvariant();
        int digits = lower.Count(char.IsAsciiDigit);
        int letters = lower.Length - digits;
        if (letters == 0)
        {
            return null; // all digits: a date or a build number as often as random
        }

        if (lower.Length >= 12 && digits >= 2 && letters >= 2 && lower.All(char.IsAsciiHexDigit))
        {
            return "its name is a random-looking hex string";
        }

        if (lower.Length < 8)
        {
            return null;
        }

        int switches = 0;
        for (int i = 1; i < lower.Length; i++)
        {
            switches += char.IsAsciiDigit(lower[i]) != char.IsAsciiDigit(lower[i - 1]) ? 1 : 0;
        }

        if (switches >= 3 && digits >= 2)
        {
            return "its name mixes letters and digits at random";
        }

        int vowels = 0, run = 0, longestRun = 0;
        foreach (char c in lower.Where(char.IsAsciiLetter))
        {
            bool vowel = c is 'a' or 'e' or 'i' or 'o' or 'u' or 'y';
            vowels += vowel ? 1 : 0;
            run = vowel ? 0 : run + 1;
            longestRun = Math.Max(longestRun, run);
        }

        return longestRun >= 5 && vowels * 4 < letters ? "its name has no pronounceable syllables" : null;
    }

    private static bool IsInside(string full, string root) =>
        root.Length > 3
        && full.Length > root.Length + 1
        && full.StartsWith(root, StringComparison.OrdinalIgnoreCase)
        && full[root.Length] == Path.DirectorySeparatorChar;

    private static string StripExtendedPrefix(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[8..];
        }

        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
    }
}
