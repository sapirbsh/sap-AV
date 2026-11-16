using System.Globalization;
using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.BrowserHijack;

/// <summary>
/// The group a domain on the <see cref="SecurityDomainList"/> belongs to. Ordered by severity: a name in more than one group
/// takes the highest. Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<SecurityDomainGroup>))]
public enum SecurityDomainGroup
{
    /// <summary>Major sign-in, banking, payment and crypto sites: a redirect is Malicious, a block is nothing.</summary>
    Accounts = 1,

    /// <summary>Antivirus vendors and online scanners: a redirect or a block is Malicious.</summary>
    Security = 2,

    /// <summary>Windows Update, Microsoft Defender and SmartScreen: a redirect is Malicious, a block is Defender tampering.</summary>
    Defender = 3,
}

/// <summary>One suffix on the list.</summary>
public sealed record SecurityDomain(string Suffix, SecurityDomainGroup Group);

/// <summary>
/// The browser-hijack domain list (ROADMAP E6): domain suffixes whose hosts entries matter, by group. The shipped list is
/// <c>data/browser-hijack/security-domains.txt</c>, embedded in SapAV.Core at build time (<see cref="Default"/>), so the engine and
/// the scan worker can't be pointed at a different copy. Immutable and thread-safe.
/// </summary>
/// <remarks>
/// File format: <c>[group]</c> lines (<c>defender</c>, <c>security</c>, <c>accounts</c>) start a group; every other non-blank line is
/// one lower-case ASCII suffix; <c>#</c> starts a comment. The whole list must fit <see cref="HostsNameFilter"/>'s caps, because it is
/// also the collector's keep filter (<see cref="HostsNameFilter.DefaultSecurityDomains"/>).
/// </remarks>
public sealed class SecurityDomainList
{
    /// <summary>The file name in <c>data/browser-hijack/</c>.</summary>
    public const string FileName = "security-domains.txt";

    /// <summary>A list file larger than this isn't read (the caps allow far less).</summary>
    public const int MaxFileBytes = 64 * 1024;

    private const string ResourceName = "SapAV.Core.BrowserHijack.security-domains.txt";

    private static readonly Lazy<SecurityDomainList> LazyDefault = new(LoadEmbedded, LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly SecurityDomain[] _domains;

    private SecurityDomainList(SecurityDomain[] domains)
    {
        _domains = domains;
        Domains = Array.AsReadOnly(domains);
        KeepSuffixes = Array.AsReadOnly(domains.Select(d => d.Suffix).ToArray());
    }

    /// <summary>The shipped list (<c>data/browser-hijack/security-domains.txt</c>, embedded).</summary>
    /// <exception cref="InvalidOperationException">The embedded list is missing or invalid (a build error; a test guards it).</exception>
    public static SecurityDomainList Default => LazyDefault.Value;

    /// <summary>Every suffix with its group, in file order.</summary>
    public IReadOnlyList<SecurityDomain> Domains { get; }

    /// <summary>Every suffix, in file order: the collector's keep filter (within <see cref="HostsNameFilter"/>'s caps).</summary>
    public IReadOnlyList<string> KeepSuffixes { get; }

    /// <summary>Parses list text.</summary>
    /// <exception cref="FormatException">A line is invalid, a suffix repeats, or the list is outside the caps.</exception>
    public static SecurityDomainList Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return TryParse(text, out var list, out var error) ? list : throw new FormatException(error);
    }

    /// <summary>Parses list text. Never throws for bad content.</summary>
    public static bool TryParse(string text, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out SecurityDomainList? list, out string? error)
    {
        ArgumentNullException.ThrowIfNull(text);
        list = null;
        error = null;
        var domains = new List<SecurityDomain>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        SecurityDomainGroup? group = null;
        int lineNumber = 0;
        foreach (var rawLine in text.Split('\n'))
        {
            lineNumber++;
            int hash = rawLine.IndexOf('#');
            var line = (hash >= 0 ? rawLine[..hash] : rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                group = line[1..^1].Trim() switch
                {
                    "defender" => SecurityDomainGroup.Defender,
                    "security" => SecurityDomainGroup.Security,
                    "accounts" => SecurityDomainGroup.Accounts,
                    _ => null,
                };
                if (group is null)
                {
                    error = $"Line {lineNumber}: unknown group.";
                    return false;
                }

                continue;
            }

            if (group is not { } g)
            {
                error = $"Line {lineNumber}: a domain before the first [group].";
                return false;
            }

            if (line.Length > HostsNameFilter.MaxSuffixLength || line.Any(c => c is >= 'A' and <= 'Z') || !HostsNameFilter.IsValid([line]))
            {
                error = $"Line {lineNumber}: not a lower-case ASCII domain suffix.";
                return false;
            }

            if (!seen.Add(line))
            {
                error = $"Line {lineNumber}: the suffix is listed twice.";
                return false;
            }

            domains.Add(new SecurityDomain(line, g));
        }

        var suffixes = domains.Select(d => d.Suffix).ToArray();
        if (suffixes.Length == 0 || !HostsNameFilter.IsValid(suffixes))
        {
            error = suffixes.Length == 0 ? "The list is empty." : "The list is outside the hosts name filter's caps.";
            return false;
        }

        list = new SecurityDomainList([.. domains]);
        return true;
    }

    /// <summary>Loads a list file (for an override or a test).</summary>
    /// <exception cref="IOException">The file can't be read or is larger than <see cref="MaxFileBytes"/>.</exception>
    /// <exception cref="FormatException">The content is invalid.</exception>
    public static SecurityDomainList Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxFileBytes)
        {
            throw new IOException($"The domain list is larger than {MaxFileBytes} bytes.");
        }

        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return Parse(reader.ReadToEnd());
    }

    /// <summary>
    /// The most severe group a host name belongs to, or null. The name matches a suffix when it equals it or ends with
    /// <c>"." + suffix</c>, case-insensitively and ignoring trailing dots. A non-ASCII name is matched by its IDNA (UTS #46) ASCII
    /// form, so a full-width or upper-case Unicode spelling of a listed domain still matches, while a homograph (a Cyrillic
    /// "о", a punycode <c>xn--</c> label) is a different domain and doesn't.
    /// </summary>
    public SecurityDomainGroup? Classify(string hostName, out string? matchedSuffix)
    {
        matchedSuffix = null;
        if (Normalize(hostName) is not { } name)
        {
            return null;
        }

        SecurityDomainGroup? best = null;
        foreach (var domain in _domains)
        {
            if (domain.Group > best.GetValueOrDefault() && HostsNameFilter.Matches(name, [domain.Suffix]))
            {
                best = domain.Group;
                matchedSuffix = domain.Suffix;
            }
        }

        return best;
    }

    /// <summary>The ASCII, lower-case, trailing-dot-free form of a host name; null when it has no usable form.</summary>
    internal static string? Normalize(string hostName)
    {
        if (string.IsNullOrEmpty(hostName))
        {
            return null;
        }

        var name = hostName.TrimEnd('.');
        if (name.Length == 0)
        {
            return null;
        }

        if (!System.Text.Ascii.IsValid(name))
        {
            try
            {
                name = new IdnMapping { UseStd3AsciiRules = false, AllowUnassigned = true }.GetAscii(name).TrimEnd('.');
            }
            catch (ArgumentException)
            {
                return null; // not a valid IDN: the resolver can't map it to a listed domain either
            }
        }

        return name.ToLowerInvariant();
    }

    private static SecurityDomainList LoadEmbedded()
    {
        using var stream = typeof(SecurityDomainList).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"The embedded domain list '{ResourceName}' is missing.");
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return TryParse(reader.ReadToEnd(), out var list, out var error)
            ? list
            : throw new InvalidOperationException("The embedded domain list is invalid: " + error);
    }
}
