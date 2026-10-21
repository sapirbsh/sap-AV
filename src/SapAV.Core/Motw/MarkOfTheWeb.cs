using System.Globalization;
using System.Text;
using SapAV.Core.Hashing;
using SapAV.Core.Text;

namespace SapAV.Core.Motw;

/// <summary>URL security zones as written in <c>ZoneId</c> (URLZONE values).</summary>
public enum SecurityZone
{
    LocalMachine = 0,
    LocalIntranet = 1,
    Trusted = 2,
    Internet = 3,
    Restricted = 4,
}

/// <summary>
/// The parsed <c>Zone.Identifier</c> stream (Mark-of-the-Web): where a file came from.
/// </summary>
/// <remarks>
/// URLs come from the downloading program and are untrusted text: control characters are removed, user
/// info (<c>user:password@</c>) is redacted, and they are cut to <see cref="MaxUrlLength"/> characters, so they
/// are safe to show and log.
/// </remarks>
public sealed record MarkOfTheWeb
{
    /// <summary>Longest URL kept, in characters.</summary>
    public const int MaxUrlLength = 2048;

    /// <summary>Largest stream that is read, in bytes. Real ones are a few hundred bytes.</summary>
    public const int MaxStreamBytes = 64 * 1024;

    internal MarkOfTheWeb(SecurityZone? zone, int? rawZoneId, string? hostUrl, string? referrerUrl)
    {
        Zone = zone;
        RawZoneId = rawZoneId;
        HostUrl = hostUrl;
        ReferrerUrl = referrerUrl;
    }

    /// <summary>The zone, or null if <c>ZoneId</c> is missing or not 0-4.</summary>
    public SecurityZone? Zone { get; }

    /// <summary>The <c>ZoneId</c> number as written (may be outside 0-4), or null if missing / not a number.</summary>
    public int? RawZoneId { get; }

    /// <summary>The download URL (<c>HostUrl</c>), sanitized; null if missing.</summary>
    public string? HostUrl { get; }

    /// <summary>The page that linked to the download (<c>ReferrerUrl</c>), sanitized; null if missing.</summary>
    public string? ReferrerUrl { get; }

    /// <summary>
    /// True for the Internet and Restricted zones (3, 4): these files are prioritized in the scan queue and count
    /// as a heuristic signal (ROADMAP feature 4). An unknown or missing zone is not counted.
    /// </summary>
    public bool IsFromInternet => Zone is SecurityZone.Internet or SecurityZone.Restricted;

    /// <summary>
    /// Parses stream content (UTF-8 / ANSI, or UTF-16 with a BOM): the <c>[ZoneTransfer]</c> section's
    /// <c>ZoneId</c>, <c>HostUrl</c> and <c>ReferrerUrl</c>, case-insensitive. Other sections and keys are ignored.
    /// Never throws; content with no <c>[ZoneTransfer]</c> section gives a mark with every value null.
    /// </summary>
    public static MarkOfTheWeb Parse(ReadOnlySpan<byte> content)
    {
        string text = Decode(content.Length > MaxStreamBytes ? content[..MaxStreamBytes] : content);
        bool inZoneTransfer = false;
        int? rawZone = null;
        string? host = null, referrer = null;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
            {
                continue;
            }

            if (line[0] == '[')
            {
                inZoneTransfer = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            int eq = line.IndexOf('=');
            if (!inZoneTransfer || eq <= 0)
            {
                continue;
            }

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase))
            {
                rawZone ??= int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int z) ? z : null;
            }
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
            {
                host ??= SanitizeUrl(value);
            }
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
            {
                referrer ??= SanitizeUrl(value);
            }
        }

        SecurityZone? zone = rawZone is >= 0 and <= 4 ? (SecurityZone)rawZone.Value : null;
        return new MarkOfTheWeb(zone, rawZone, host, referrer);
    }

    private static string Decode(ReadOnlySpan<byte> content)
    {
        if (content.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]))
        {
            return Encoding.Unicode.GetString(content[2..]);
        }

        if (content.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            content = content[3..];
        }

        return Encoding.UTF8.GetString(content);
    }

    /// <summary>
    /// The display form: control characters, U+2028/U+2029 and bidi controls removed, user info redacted, capped
    /// at <see cref="MaxUrlLength"/>; null if nothing is left. Idempotent.
    /// </summary>
    /// <remarks>
    /// The authority ends at the first <c>/</c>, <c>\</c>, <c>?</c> or <c>#</c>, as in browsers (WHATWG URL): for
    /// http(s) a backslash is a path separator, so in <c>https://evil\@good/</c> the host is <c>evil</c> and the
    /// <c>@</c> is in the path. Looking for <c>@</c> past the backslash would redact the real host and leave
    /// <c>https://***@good/</c>, which reads like a download from <c>good</c>.
    /// </remarks>
    internal static string? SanitizeUrl(string value)
    {
        var sb = new StringBuilder(Math.Min(value.Length, MaxUrlLength));
        foreach (char c in value)
        {
            if (sb.Length >= MaxUrlLength)
            {
                break;
            }

            if (!SafeText.IsLineBreakOrControl(c) && !SafeText.IsBidiControl(c))
            {
                sb.Append(c);
            }
        }

        var url = sb.ToString();
        if (url.Length == 0)
        {
            return null;
        }

        // Redact user info: scheme://user:password@host/... -> scheme://***@host/...
        int scheme = url.IndexOf("://", StringComparison.Ordinal);
        if (scheme > 0)
        {
            int authorityStart = scheme + 3;
            int authorityEnd = url.IndexOfAny(['/', '\\', '?', '#'], authorityStart);
            if (authorityEnd < 0)
            {
                authorityEnd = url.Length;
            }

            int at = authorityEnd > authorityStart
                ? url.LastIndexOf('@', authorityEnd - 1, authorityEnd - authorityStart)
                : -1;
            if (at >= authorityStart)
            {
                url = string.Concat(url.AsSpan(0, authorityStart), "***", url.AsSpan(at));
            }
        }

        return url;
    }

    /// <summary>
    /// The form written to the Event Log / SIEM (ROADMAP X2): the display form (same rules as <see cref="HostUrl"/>)
    /// without the query string and fragment, which often carry presigned download tokens or session IDs.
    /// Null for null, or when nothing is left. Idempotent, so it is safe on an already sanitised URL.
    /// </summary>
    public static string? SanitizeUrlForLog(string? url)
    {
        if (url is null || SanitizeUrl(url) is not { } display)
        {
            return null;
        }

        int cut = display.IndexOfAny(['?', '#']);
        return cut switch
        {
            < 0 => display,
            0 => null,
            _ => display[..cut],
        };
    }
}

/// <summary>Whether a Mark-of-the-Web was found.</summary>
public enum MarkOfTheWebStatus
{
    /// <summary>The file has a <c>Zone.Identifier</c> stream; see <see cref="MarkOfTheWebResult.Mark"/>.</summary>
    Present,

    /// <summary>The file has no <c>Zone.Identifier</c> stream (or the file system has no streams).</summary>
    Absent,

    /// <summary>The file or its stream could not be read; see <see cref="MarkOfTheWebResult.NotReadReason"/>.</summary>
    NotRead,
}

/// <summary>Outcome of <see cref="IMarkOfTheWebReader.Read"/>. <see cref="Mark"/> is non-null exactly when Present.</summary>
public sealed record MarkOfTheWebResult
{
    private MarkOfTheWebResult(MarkOfTheWebStatus status, MarkOfTheWeb? mark, HashFailureReason notReadReason, string? message)
    {
        Status = status;
        Mark = mark;
        NotReadReason = notReadReason;
        Message = message;
    }

    public MarkOfTheWebStatus Status { get; }

    public MarkOfTheWeb? Mark { get; }

    /// <summary>
    /// Why it was not read (the hasher's reasons: NotRegularFile, Directory, NotFound, AccessDenied, ...;
    /// ChangedDuringHashing if the file was replaced between opening it and opening its stream). None otherwise.
    /// </summary>
    public HashFailureReason NotReadReason { get; }

    public string? Message { get; }

    public static MarkOfTheWebResult Present(MarkOfTheWeb mark) =>
        new(MarkOfTheWebStatus.Present, mark ?? throw new ArgumentNullException(nameof(mark)), HashFailureReason.None, null);

    public static MarkOfTheWebResult Absent(string? message = null) =>
        new(MarkOfTheWebStatus.Absent, null, HashFailureReason.None, message);

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None or undefined.</exception>
    public static MarkOfTheWebResult NotRead(HashFailureReason reason, string? message = null)
    {
        if (!Enum.IsDefined(reason) || reason == HashFailureReason.None)
        {
            throw new ArgumentOutOfRangeException(nameof(reason), reason, "A not-read result needs a reason.");
        }

        return new(MarkOfTheWebStatus.NotRead, null, reason, message);
    }
}
