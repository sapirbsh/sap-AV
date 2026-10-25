using System.Text;

namespace SapAV.Core.Persistence;

/// <summary>
/// The environment a persistence entry's command line is expanded with (ROADMAP C2): the machine environment (from
/// HKLM) for machine entries, or one user's environment (machine + their hive) for that user's entries. Built from the
/// registry by the engine, <b>never</b> from the engine's own process environment (SYSTEM's would give wrong, and
/// user-misleading, paths). Names are case-insensitive, as in Windows.
/// </summary>
public sealed class EnvironmentBlock
{
    /// <summary>The longest expanded text (a command line's limit); longer expansions fail.</summary>
    public const int MaxExpandedLength = 32767;

    /// <summary>Most variables kept, and the cap of each value.</summary>
    public const int MaxVariables = 1024;

    /// <summary>Most search directories (System32, Windows, then PATH entries).</summary>
    public const int MaxSearchDirectories = 64;

    private readonly Dictionary<string, string> _variables;

    /// <param name="variables">Already expanded values (see <see cref="Build"/> for registry values that still have <c>%NAME%</c>).</param>
    /// <param name="userSid">The user this environment belongs to; null for the machine environment.</param>
    public EnvironmentBlock(IEnumerable<KeyValuePair<string, string>> variables, string? userSid = null)
    {
        ArgumentNullException.ThrowIfNull(variables);
        if (userSid is not null && !PersistenceEntry.IsSid(userSid))
        {
            throw new ArgumentException("The user must be a SID.", nameof(userSid));
        }

        _variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in variables)
        {
            if (_variables.Count >= MaxVariables)
            {
                break;
            }

            if (IsValidName(name) && value is not null)
            {
                _variables[name] = value.Length > MaxExpandedLength ? value[..MaxExpandedLength] : value;
            }
        }

        UserSid = userSid;
        SearchDirectories = BuildSearchDirectories();
    }

    /// <summary>An empty machine environment (every <c>%NAME%</c> unknown, no search directories).</summary>
    public static EnvironmentBlock Empty { get; } = new([]);

    public string? UserSid { get; }

    public bool IsUser => UserSid is not null;

    /// <summary>
    /// Where a bare program or DLL name is looked up, in order: <c>%SystemRoot%\System32</c>, <c>%SystemRoot%</c>, then
    /// each PATH entry. Only fully qualified local drive folders (a UNC or relative PATH entry is skipped, so resolving a
    /// name never makes the engine contact a server). Normalized, without duplicates, at most <see cref="MaxSearchDirectories"/>.
    /// </summary>
    public IReadOnlyList<string> SearchDirectories { get; }

    public string? SystemRoot => Get("SystemRoot");

    public string? Get(string name) => _variables.TryGetValue(name, out var value) ? value : null;

    public IReadOnlyDictionary<string, string> Variables => _variables;

    /// <summary>A copy with <paramref name="overrides"/> set on top (e.g. a user's variables on the machine environment).</summary>
    public EnvironmentBlock With(IEnumerable<KeyValuePair<string, string>> overrides, string? userSid)
    {
        var merged = new Dictionary<string, string>(_variables, StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in overrides)
        {
            if (IsValidName(name) && value is not null)
            {
                merged[name] = value;
            }
        }

        return new EnvironmentBlock(merged, userSid);
    }

    /// <summary>
    /// Builds an environment from raw values (registry <c>REG_EXPAND_SZ</c> values may refer to each other, e.g.
    /// <c>windir=%SystemRoot%</c>). Each value is expanded against <paramref name="baseEnvironment"/> plus the values
    /// already expanded, a few rounds deep (no recursion, no loops).
    /// </summary>
    public static EnvironmentBlock Build(
        IEnumerable<KeyValuePair<string, string>> raw, EnvironmentBlock? baseEnvironment = null, string? userSid = null)
    {
        var current = baseEnvironment?.With(raw, userSid) ?? new EnvironmentBlock(raw, userSid);
        for (int round = 0; round < 4; round++)
        {
            bool changed = false;
            var next = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, value) in current._variables)
            {
                var expanded = value.Contains('%') ? current.Expand(value, out _) ?? value : value;
                changed |= !string.Equals(expanded, value, StringComparison.Ordinal);
                next[name] = expanded;
            }

            current = new EnvironmentBlock(next, userSid);
            if (!changed)
            {
                break;
            }
        }

        return current;
    }

    /// <summary>
    /// Expands <c>%NAME%</c> like ExpandEnvironmentStrings: a defined name is replaced, an undefined one is kept as written
    /// (and <paramref name="unknown"/> set). Null if the result would be longer than <see cref="MaxExpandedLength"/>.
    /// </summary>
    public string? Expand(string text, out bool unknown)
    {
        ArgumentNullException.ThrowIfNull(text);
        unknown = false;
        if (!text.Contains('%'))
        {
            return text.Length > MaxExpandedLength ? null : text;
        }

        var sb = new StringBuilder(text.Length);
        int i = 0;
        while (i < text.Length)
        {
            int open = text.IndexOf('%', i);
            if (open < 0)
            {
                sb.Append(text, i, text.Length - i);
                break;
            }

            sb.Append(text, i, open - i);
            int close = text.IndexOf('%', open + 1);
            if (close < 0)
            {
                sb.Append(text, open, text.Length - open);
                break;
            }

            string name = text[(open + 1)..close];
            if (name.Length > 0 && _variables.TryGetValue(name, out var value))
            {
                sb.Append(value);
                i = close + 1;
            }
            else
            {
                if (name.Length > 0 && IsValidName(name))
                {
                    unknown = true;
                }

                sb.Append('%');
                i = open + 1; // the closing '%' may open the next name, as in Windows
            }

            if (sb.Length > MaxExpandedLength)
            {
                return null;
            }
        }

        return sb.Length > MaxExpandedLength ? null : sb.ToString();
    }

    private static bool IsValidName(string? name) =>
        !string.IsNullOrEmpty(name) && name.Length <= 255 && !name.Contains('=') && !name.Contains('%')
        && !name.Any(c => char.IsControl(c));

    private string[] BuildSearchDirectories()
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? folder)
        {
            if (result.Count >= MaxSearchDirectories || string.IsNullOrWhiteSpace(folder))
            {
                return;
            }

            var trimmed = folder.Trim().Trim('"');
            if (trimmed.Contains('%') || PersistenceText.NormalizeLocalPath(trimmed) is not { } normalized)
            {
                return;
            }

            normalized = normalized.TrimEnd('\\');
            if (normalized.Length == 2)
            {
                normalized += "\\"; // keep a drive root rooted
            }

            if (seen.Add(normalized))
            {
                result.Add(normalized);
            }
        }

        if (SystemRoot is { } root)
        {
            Add(Path.Join(root, "System32"));
            Add(root);
        }

        foreach (var entry in (Get("Path") ?? string.Empty).Split(';'))
        {
            Add(entry);
        }

        return [.. result];
    }
}

/// <summary>
/// Does a file exist? Used only where the CreateProcess / LoadLibrary search order needs it (a bare name, an unquoted
/// path with spaces). Implementations must never follow a link, never contact a server and never read content (the
/// engine's opens only attributes, component by component, without reparsing).
/// </summary>
public interface IPathProbe
{
    /// <param name="path">A normalized, fully qualified local path.</param>
    bool FileExists(string path);
}
