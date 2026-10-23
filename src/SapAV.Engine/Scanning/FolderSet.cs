namespace SapAV.Engine.Scanning;

/// <summary>
/// A set of folders compared by exact full path (only "." / ".." resolved; trailing dots and spaces kept; trailing separator;
/// case-insensitive). <see cref="Contains"/> is true for the folder itself and everything below it.
/// </summary>
/// <remarks>
/// The check is by path string, so callers check the <b>final</b> path of an opened handle (long names, no 8.3 aliases,
/// no links) as well as the requested one; a short-name or junction spelling can't slip past the final-path check.
/// </remarks>
public sealed class FolderSet
{
    private readonly string[] _folders;

    public FolderSet(IEnumerable<string?> folders)
    {
        ArgumentNullException.ThrowIfNull(folders);
        _folders = folders.Select(Normalize).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public IReadOnlyList<string> Folders => _folders;

    /// <summary>True if <paramref name="path"/> is one of the folders or inside one.</summary>
    public bool Contains(string? path)
    {
        var normalized = Normalize(path);
        return normalized is not null && _folders.Any(f => normalized.StartsWith(f, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The exact full path with one trailing separator, or null if it isn't a fully qualified drive or UNC path.</summary>
    internal static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        // B3 review H1: never Path.GetFullPath here; it strips trailing dots/spaces, so C:\ProgramData\sap-AV.\ (a different
        // folder an attacker can create through \\?\) would compare equal to the excluded C:\ProgramData\sap-AV\. Only "." /
        // ".." components and separators are resolved; names are compared exactly (case-insensitively). \\?\C:\x and C:\x
        // are the same string here (comparison only; nothing is opened by this form).
        var exact = Core.Hashing.ExactPath.ToExtended(path);
        if (exact is null)
        {
            return null;
        }

        var plain = Core.Hashing.ExactPath.StripPrefix(exact);
        return plain.EndsWith('\\') ? plain : plain + '\\';
    }
}

/// <summary>
/// Folders that scan jobs never scan and never auto-quarantine from (review B2 follow-up Medium): the engine's own data
/// (<c>%ProgramData%\sap-AV</c>: settings, caches, sandbox, quarantine store), the engine and scan-worker install folders,
/// the rules and blocklist folders (YARA rule files match themselves), plus configured extras.
/// </summary>
public static class EngineDataFolders
{
    /// <summary><c>%ProgramData%\sap-AV</c>.</summary>
    public static string ProgramDataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "sap-AV");

    /// <summary>The default set: ProgramData root and the engine's install folder.</summary>
    public static IEnumerable<string> Defaults() => [ProgramDataRoot, AppContext.BaseDirectory];
}
