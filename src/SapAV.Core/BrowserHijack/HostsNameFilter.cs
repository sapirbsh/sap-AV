namespace SapAV.Core.BrowserHijack;

/// <summary>
/// The domains whose hosts entries are always kept, even past the entry cap (ROADMAP E6), as a list of domain suffixes that can
/// travel to the scan worker. A name matches a suffix when it equals it or ends with <c>"." + suffix</c> (case-insensitive).
/// </summary>
/// <remarks>
/// <see cref="DefaultSecurityDomains"/> is the shipped domain list from <c>data/browser-hijack/security-domains.txt</c> (Windows
/// Update / Defender, antivirus vendors and scanners, major sign-in and banking sites), the same list the E6 rules judge entries
/// against. The caps here bound the request size.
/// </remarks>
public static class HostsNameFilter
{
    public const int MaxSuffixes = 128;
    public const int MaxSuffixLength = 253;

    /// <summary>All suffixes together (keeps the worker request far below its size cap).</summary>
    public const int MaxTotalCharacters = 8192;

    /// <summary>
    /// Every suffix of the shipped domain list (<c>data/browser-hijack/security-domains.txt</c>, see
    /// <see cref="SecurityDomainList.Default"/>): the same instance on every call. A computed property, not a static field, so
    /// this class has no static initializer that could cycle with <see cref="SecurityDomainList"/>'s validation.
    /// </summary>
    public static IReadOnlyList<string> DefaultSecurityDomains => SecurityDomainList.Default.KeepSuffixes;

    /// <summary>True when the list is within the caps and every suffix is a plausible DNS name (ASCII letters, digits, '-' and inner dots).</summary>
    public static bool IsValid(IReadOnlyList<string>? suffixes)
    {
        if (suffixes is null)
        {
            return true;
        }

        if (suffixes.Count > MaxSuffixes)
        {
            return false;
        }

        int total = 0;
        foreach (var suffix in suffixes)
        {
            if (string.IsNullOrEmpty(suffix) || suffix.Length > MaxSuffixLength || suffix.StartsWith('.') || suffix.EndsWith('.')
                || !suffix.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.'))
            {
                return false;
            }

            total += suffix.Length;
        }

        return total <= MaxTotalCharacters;
    }

    /// <summary>A predicate for <see cref="HostsFileParser.Parse"/>, or null for an empty / null list.</summary>
    /// <exception cref="ArgumentException">The list isn't <see cref="IsValid"/>.</exception>
    public static Func<string, bool>? ToPredicate(IReadOnlyList<string>? suffixes)
    {
        if (!IsValid(suffixes))
        {
            throw new ArgumentException("The hosts name filter is outside its caps or has an invalid suffix.", nameof(suffixes));
        }

        if (suffixes is null or { Count: 0 })
        {
            return null;
        }

        var list = suffixes.ToArray();
        return name => Matches(name, list);
    }

    public static bool Matches(string name, IReadOnlyList<string> suffixes)
    {
        var trimmed = name.TrimEnd('.');
        foreach (var suffix in suffixes)
        {
            if (trimmed.Equals(suffix, StringComparison.OrdinalIgnoreCase)
                || (trimmed.Length > suffix.Length && trimmed[^(suffix.Length + 1)] == '.' && trimmed.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }
}
