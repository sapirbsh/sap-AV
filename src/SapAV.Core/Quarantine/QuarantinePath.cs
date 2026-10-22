namespace SapAV.Core.Quarantine;

/// <summary>Path rules for quarantine metadata and restore targets (pure string checks, no file system access).</summary>
public static class QuarantinePath
{
    /// <summary>Longest original path accepted (NTFS limit is 32,767 UTF-16 units).</summary>
    public const int MaxPathLength = 32_000;

    /// <summary>Highest N tried for <c>name (restored N).ext</c>.</summary>
    public const int MaxRestoreSuffix = 99;

    private const string RestoreTempPrefix = "~sapav-restore-";
    private const string RestoreTempSuffix = ".tmp";

    /// <summary>
    /// True if <paramref name="path"/> is a usable original path: drive-letter form <c>X:\dir\...\name</c> (no UNC,
    /// no <c>\\?\</c> / device prefix), at least one directory level below the root or a file in the root, no empty,
    /// <c>.</c> or <c>..</c> components, no alternate-stream colon, no wildcard/illegal characters or controls.
    /// Trailing dots and spaces are allowed (they are real NTFS names and the restore uses native names).
    /// </summary>
    public static bool TryValidateOriginalPath(string? path, out string reason)
    {
        if (string.IsNullOrEmpty(path) || path.Length > MaxPathLength)
        {
            reason = "empty or too long";
            return false;
        }

        if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
        {
            reason = "not a drive-letter path (X:\\...)";
            return false;
        }

        var components = path[3..].Split('\\');
        foreach (var component in components)
        {
            if (!IsValidComponent(component))
            {
                reason = $"invalid path component '{component}'";
                return false;
            }
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>The directory components below the drive root of a validated path, and the file name.</summary>
    /// <exception cref="ArgumentException">The path doesn't pass <see cref="TryValidateOriginalPath"/>.</exception>
    public static (string Drive, IReadOnlyList<string> Directories, string FileName) Split(string path)
    {
        if (!TryValidateOriginalPath(path, out var reason))
        {
            throw new ArgumentException($"Invalid original path: {reason}", nameof(path));
        }

        var components = path[3..].Split('\\');
        return (path[..3], components[..^1], components[^1]);
    }

    /// <summary>A new random temp name for a file being restored (only this code creates such names).</summary>
    public static string NewRestoreTempName() => RestoreTempPrefix + QuarantineItemId.New() + RestoreTempSuffix;

    /// <summary>True for a name made by <see cref="NewRestoreTempName"/>.</summary>
    public static bool IsRestoreTempName(string? name) =>
        name is not null
        && name.Length == RestoreTempPrefix.Length + 32 + RestoreTempSuffix.Length
        && name.StartsWith(RestoreTempPrefix, StringComparison.Ordinal)
        && name.EndsWith(RestoreTempSuffix, StringComparison.Ordinal)
        && QuarantineItemId.IsValid(name.Substring(RestoreTempPrefix.Length, 32));

    /// <summary>
    /// The name to restore as when <paramref name="fileName"/> is taken: <c>name (restored N).ext</c>; N = 0 gives the
    /// original name. The extension is the part after the last dot (none for names without a dot or starting with one).
    /// </summary>
    public static string RestoredName(string fileName, int n)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        ArgumentOutOfRangeException.ThrowIfNegative(n);
        if (n == 0)
        {
            return fileName;
        }

        int dot = fileName.LastIndexOf('.');
        return dot <= 0
            ? $"{fileName} (restored {n})"
            : $"{fileName[..dot]} (restored {n}){fileName[dot..]}";
    }

    private static bool IsValidComponent(string component)
    {
        if (component.Length is 0 or > 255 || component is "." or "..")
        {
            return false;
        }

        foreach (char c in component)
        {
            if (c < 0x20 || c is ':' or '/' or '*' or '?' or '"' or '<' or '>' or '|')
            {
                return false;
            }
        }

        return true;
    }
}
