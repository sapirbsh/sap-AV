namespace SapAV.Core.BrowserHijack;

/// <summary>
/// The domains whose hosts entries are always kept, even past the entry cap (ROADMAP E6), as a list of domain suffixes that can
/// travel to the scan worker. A name matches a suffix when it equals it or ends with <c>"." + suffix</c> (case-insensitive).
/// </summary>
/// <remarks>
/// <see cref="DefaultSecurityDomains"/> is a fixed starter list (Microsoft / Defender / Windows Update, major antivirus vendors,
/// VirusTotal). Detection-dev's E6 rules will replace it with the list from <c>data/</c>; the caps here bound the request size.
/// </remarks>
public static class HostsNameFilter
{
    public const int MaxSuffixes = 128;
    public const int MaxSuffixLength = 253;

    /// <summary>All suffixes together (keeps the worker request far below its size cap).</summary>
    public const int MaxTotalCharacters = 8192;

    public static IReadOnlyList<string> DefaultSecurityDomains { get; } =
    [
        // Microsoft, Defender, Windows Update
        "microsoft.com", "windowsupdate.com", "update.microsoft.com", "windows.com", "msftncsi.com", "live.com", "microsoftonline.com",
        "wdcp.microsoft.com", "smartscreen.microsoft.com", "mp.microsoft.com", "delivery.mp.microsoft.com", "windowsdefender.com",
        // Online scanners
        "virustotal.com", "hybrid-analysis.com", "any.run", "malwarebytes.com",
        // Antivirus vendors
        "avast.com", "avg.com", "avira.com", "bitdefender.com", "bitdefender.net", "eset.com", "f-secure.com", "withsecure.com",
        "kaspersky.com", "kaspersky-labs.com", "mcafee.com", "norton.com", "nortonlifelock.com", "gendigital.com", "sophos.com",
        "trendmicro.com", "drweb.com", "emsisoft.com", "gdata.de", "pandasecurity.com", "webroot.com", "zonealarm.com",
        "comodo.com", "crowdstrike.com", "sentinelone.com",
    ];

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
