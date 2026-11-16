using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SapAV.Core.BrowserHijack;

/// <summary>The address family of a hosts entry.</summary>
public enum HostsAddressFamily
{
    IPv4,
    IPv6,
}

/// <summary>The byte order mark a hosts file starts with (the resolver ignores it and reads bytes as ANSI / UTF-8).</summary>
public enum HostsTextEncoding
{
    /// <summary>No byte order mark.</summary>
    Utf8,

    /// <summary>A UTF-8 BOM: the resolver sees its bytes as part of line 1 (which is then malformed).</summary>
    Utf8Bom,

    /// <summary>A UTF-16 LE BOM: editors show the file as UTF-16, the resolver reads its bytes as ANSI / UTF-8.</summary>
    Utf16LittleEndian,

    /// <summary>A UTF-16 BE BOM (same as <see cref="Utf16LittleEndian"/>).</summary>
    Utf16BigEndian,
}

/// <summary>One hosts line that maps an address to names.</summary>
/// <param name="Address">The address in canonical form (<see cref="IPAddress.ToString"/>); see <see cref="RawAddress"/> for what was written.</param>
/// <param name="IsBlocking">True for a loopback or unspecified address (0.0.0.0, 127.x, ::, ::1): the names are blocked, not redirected.</param>
/// <param name="Names">The host names, raw (<see cref="Text.SafeText.Identifier"/>), each capped at <see cref="HostsParseResult.MaxNameLength"/>.</param>
/// <param name="Line">The 1-based line number.</param>
/// <param name="NamesTruncated">True when names were left out (<see cref="HostsParseResult.MaxNamesPerLine"/>) or a name was cut.</param>
public sealed record HostsEntry(string Address, HostsAddressFamily Family, bool IsBlocking, IReadOnlyList<string> Names, int Line, bool NamesTruncated)
{
    /// <summary>
    /// The IPv4 address as written when it isn't canonical dotted-decimal (octal <c>0177.0.0.1</c>, hex <c>0x7f.1</c>, a single
    /// integer, short forms): resolvers that use <c>inet_aton</c> rules read it as <see cref="Address"/>, others don't. Null otherwise.
    /// </summary>
    public string? RawAddress { get; init; }

    /// <summary>True when the address wasn't written in canonical form. Evasion-shaped, so worth reporting.</summary>
    public bool NonCanonicalAddress => RawAddress is not null;

    /// <summary>Parser-internal: a name matched the keep filter (the worker spends its answer budget on these first).</summary>
    internal bool Kept { get; init; }
}

/// <summary>A non-comment line that isn't a valid entry, kept raw (<see cref="Text.SafeText.Identifier"/>) and capped.</summary>
public sealed record HostsMalformedLine(int Line, string Text, string Reason);

/// <summary>The parsed content of a hosts file.</summary>
/// <remarks>
/// At most <see cref="MaxEntries"/> entries are kept: the first and the last half, plus up to <see cref="MaxKeptExtra"/> entries
/// from the middle that the caller asked to keep (e.g. names on the security-domain list). <see cref="TotalEntries"/> holds the
/// real count; <see cref="EntriesTruncated"/> is a signal (a padded file can push a bad entry out of view). Malformed lines keep
/// the first and last <see cref="MaxMalformedLines"/>/2 plus up to <see cref="MaxKeptMalformedLines"/> that name a kept domain.
/// </remarks>
public sealed record HostsParseResult
{
    public const int MaxEntries = 8192;
    public const int MaxKeptExtra = 4096;
    public const int MaxNamesPerLine = 64;
    public const int MaxNameLength = 255;
    public const int MaxMalformedLines = 64;
    public const int MaxKeptMalformedLines = 32;
    public const int MaxMalformedLineLength = 256;
    public const int MaxReasonLength = 128;

    /// <summary>The byte order mark found (the primary parse ignores it, as the resolver does).</summary>
    public required HostsTextEncoding Encoding { get; init; }

    /// <summary>The entries the resolver sees: the bytes read as UTF-8 / ANSI, whatever the byte order mark says.</summary>
    public required IReadOnlyList<HostsEntry> Entries { get; init; }

    /// <summary>How many valid entries the content had (more than <see cref="Entries"/> when truncated).</summary>
    public required int TotalEntries { get; init; }

    public required bool EntriesTruncated { get; init; }

    /// <summary>The kept malformed lines (first, last and filter matches), in line order.</summary>
    public required IReadOnlyList<HostsMalformedLine> MalformedLines { get; init; }

    public required int MalformedCount { get; init; }

    /// <summary>True when the input was cut (the file is over the read cap) and its last, partial line was dropped.</summary>
    public required bool PartialLastLineDropped { get; init; }

    /// <summary>True when the parsed bytes were only the start of the file (over the read cap). Suspicious in itself.</summary>
    public bool InputTruncated { get; init; }

    /// <summary>
    /// With a UTF-16 byte order mark: the same bytes decoded as UTF-16 (what an editor shows). Its entries are a union candidate
    /// for rules; null without a UTF-16 BOM. Never nested further.
    /// </summary>
    public HostsParseResult? Utf16Decoding { get; init; }

    /// <summary>True when the file has a UTF-16 byte order mark.</summary>
    public bool Utf16Bom => Encoding is HostsTextEncoding.Utf16LittleEndian or HostsTextEncoding.Utf16BigEndian;

    /// <summary>
    /// True when a UTF-16 BOM makes an editor show different entries from what the resolver reads (a way to hide entries from
    /// someone who opens the file). Suspicious.
    /// </summary>
    public bool EncodingMismatch => Utf16Decoding is { } other && !Pairs(this).SetEquals(Pairs(other));

    /// <summary>The entries of both decodings (for rules that check every possible reading).</summary>
    public IEnumerable<HostsEntry> AllEntries => Utf16Decoding is null ? Entries : Entries.Concat(Utf16Decoding.Entries);

    private static HashSet<(string, string)> Pairs(HostsParseResult result) =>
        result.Entries.SelectMany(e => e.Names.Select(n => (e.Address, n.ToUpperInvariant()))).ToHashSet();
}

/// <summary>
/// Parses hosts file content line by line, the way Windows' resolver reads it: bytes as UTF-8 / ANSI (a byte order mark is part
/// of line 1), <c>#</c> starts a comment anywhere, fields are separated by spaces or tabs, the first field is the address and the
/// rest are names. Never throws for any input.
/// </summary>
/// <remarks>
/// A pure function with no I/O; only the sandboxed scan worker calls it (B5 rule). IPv4 in canonical dotted-decimal is a plain
/// entry; other <c>inet_aton</c> forms (octal, hex, a single integer, short forms) are entries with
/// <see cref="HostsEntry.RawAddress"/> set. IPv6 with a zone ID or brackets is malformed.
/// </remarks>
public static class HostsFileParser
{
    private const int MaxAddressText = 64;

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    /// <param name="content">The bytes read (at most the read cap).</param>
    /// <param name="inputTruncated">True when the file is longer than <paramref name="content"/>: the last partial line is dropped.</param>
    /// <param name="keep">Optional: entries (and malformed lines) naming a domain this accepts are kept past the caps.</param>
    public static HostsParseResult Parse(ReadOnlySpan<byte> content, bool inputTruncated, Func<string, bool>? keep = null)
    {
        var encoding = DetectBom(content);
        var primary = ParseText(Utf8.GetString(content), encoding, inputTruncated, keep);
        if (encoding is HostsTextEncoding.Utf16LittleEndian or HostsTextEncoding.Utf16BigEndian)
        {
            var decoder = encoding == HostsTextEncoding.Utf16LittleEndian ? System.Text.Encoding.Unicode : System.Text.Encoding.BigEndianUnicode;
            primary = primary with { Utf16Decoding = ParseText(decoder.GetString(content[2..]), encoding, inputTruncated, keep) };
        }

        return primary;
    }

    /// <summary>True for strict dotted-decimal IPv4 (four parts, 0-255, no leading zeros) or an IPv6 address without zone or brackets.</summary>
    public static bool TryParseAddress(string text, out IPAddress? address, out HostsAddressFamily family)
    {
        address = null;
        family = HostsAddressFamily.IPv4;
        if (text.Contains(':'))
        {
            family = HostsAddressFamily.IPv6;
            return text.IndexOfAny(['%', '[', ']']) < 0 && IPAddress.TryParse(text, out address) && address.AddressFamily == AddressFamily.InterNetworkV6;
        }

        var parts = text.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3 || (part.Length > 1 && part[0] == '0') || !part.All(char.IsAsciiDigit) || int.Parse(part) > 255)
            {
                return false;
            }
        }

        address = IPAddress.Parse(text);
        return true;
    }

    /// <summary>
    /// <c>inet_aton</c> rules: 1 to 4 parts, each decimal, octal (leading 0) or hex (0x); the last part fills the remaining bytes.
    /// </summary>
    public static bool TryParseLooseIPv4(string text, out IPAddress? address)
    {
        address = null;
        if (text.Length is 0 or > MaxAddressText || text.Contains(':'))
        {
            return false;
        }

        var parts = text.Split('.');
        if (parts.Length > 4)
        {
            return false;
        }

        var values = new ulong[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!TryParsePart(parts[i], out values[i]))
            {
                return false;
            }
        }

        ulong result = 0;
        for (int i = 0; i < parts.Length - 1; i++)
        {
            if (values[i] > 255)
            {
                return false;
            }

            result |= values[i] << (8 * (3 - i));
        }

        ulong lastMax = parts.Length switch { 1 => 0xFFFFFFFF, 2 => 0xFFFFFF, 3 => 0xFFFF, _ => 0xFF };
        if (values[^1] > lastMax)
        {
            return false;
        }

        result |= values[^1];
        address = new IPAddress([(byte)(result >> 24), (byte)(result >> 16), (byte)(result >> 8), (byte)result]);
        return true;
    }

    private static bool TryParsePart(string part, out ulong value)
    {
        value = 0;
        int radix = 10;
        var digits = part.AsSpan();
        if (digits.Length > 2 && digits[0] == '0' && digits[1] is 'x' or 'X')
        {
            radix = 16;
            digits = digits[2..];
        }
        else if (digits.Length > 1 && digits[0] == '0')
        {
            radix = 8;
            digits = digits[1..];
        }

        if (digits.IsEmpty || digits.Length > 11)
        {
            return false;
        }

        foreach (char c in digits)
        {
            int d = char.IsAsciiDigit(c) ? c - '0' : char.IsAsciiHexDigitLower(c) ? c - 'a' + 10 : char.IsAsciiHexDigitUpper(c) ? c - 'A' + 10 : 99;
            if (d >= radix)
            {
                return false;
            }

            value = (value * (ulong)radix) + (ulong)d;
        }

        return value <= 0xFFFFFFFF;
    }

    /// <summary>The canonical address of a field, and the raw text when it was a non-canonical IPv4 form.</summary>
    internal static bool TryReadAddress(string field, out IPAddress? address, out HostsAddressFamily family, out string? raw)
    {
        raw = null;
        if (TryParseAddress(field, out address, out family))
        {
            return true;
        }

        if (family == HostsAddressFamily.IPv4 && TryParseLooseIPv4(field, out address))
        {
            raw = field;
            return true;
        }

        return false;
    }

    private static HostsTextEncoding DetectBom(ReadOnlySpan<byte> content) =>
        content.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]) ? HostsTextEncoding.Utf16LittleEndian
        : content.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xFF]) ? HostsTextEncoding.Utf16BigEndian
        : content.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) ? HostsTextEncoding.Utf8Bom
        : HostsTextEncoding.Utf8;

    private static HostsParseResult ParseText(string text, HostsTextEncoding encoding, bool inputTruncated, Func<string, bool>? keep)
    {
        bool dropped = false;
        if (inputTruncated)
        {
            int lastBreak = text.AsSpan().LastIndexOfAny('\n', '\r');
            dropped = lastBreak < text.Length - 1;
            text = lastBreak < 0 ? string.Empty : text[..(lastBreak + 1)];
        }

        var collector = new Collector(keep);
        int lineNumber = 0;
        foreach (var range in text.AsSpan().Split('\n'))
        {
            var line = text.AsSpan(range);
            // A lone CR is a line break too.
            foreach (var part in line.Split('\r'))
            {
                lineNumber++;
                ParseLine(line[part], lineNumber, collector);
            }

            // A CRLF pair splits into "text" and "": the empty piece isn't a line of its own.
            if (line.EndsWith("\r"))
            {
                lineNumber--;
            }
        }

        return collector.Result(encoding, dropped) with { InputTruncated = inputTruncated };
    }

    private static void ParseLine(ReadOnlySpan<char> line, int lineNumber, Collector collector)
    {
        int hash = line.IndexOf('#');
        var content = hash >= 0 ? line[..hash] : line;
        var fields = new List<string>();
        foreach (var range in content.SplitAny(' ', '\t'))
        {
            if (!content[range].IsEmpty)
            {
                fields.Add(content[range].ToString());
            }
        }

        if (fields.Count == 0)
        {
            return;
        }

        if (fields[0].Length > MaxAddressText || !TryReadAddress(fields[0], out var address, out var family, out var raw))
        {
            collector.Malformed(lineNumber, line, fields, "The first field isn't a valid IPv4 or IPv6 address.");
            return;
        }

        if (fields.Count == 1)
        {
            collector.Malformed(lineNumber, line, fields, "An address without a host name.");
            return;
        }

        bool cut = fields.Count - 1 > HostsParseResult.MaxNamesPerLine;
        var names = new List<string>(Math.Min(fields.Count - 1, HostsParseResult.MaxNamesPerLine));
        foreach (var name in fields.Skip(1).Take(HostsParseResult.MaxNamesPerLine))
        {
            names.Add(Raw(name, HostsParseResult.MaxNameLength, ref cut));
        }

        bool blocking = IPAddress.IsLoopback(address!) || address!.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
        collector.Add(new HostsEntry(address!.ToString(), family, blocking, names.AsReadOnly(), lineNumber, cut)
        {
            RawAddress = raw is null ? null : Text.SafeText.Identifier(raw),
        });
    }

    private static string Raw(string value, int max, ref bool cut)
    {
        if (value.Length > max)
        {
            cut = true;
            value = value[..(char.IsHighSurrogate(value[max - 1]) ? max - 1 : max)];
        }

        return Text.SafeText.Identifier(value);
    }

    /// <summary>Keeps the first and the last half of the entries plus asked-for ones from the middle; the same for malformed lines.</summary>
    private sealed class Collector(Func<string, bool>? keep)
    {
        private const int Half = HostsParseResult.MaxEntries / 2;
        private const int MalformedHalf = HostsParseResult.MaxMalformedLines / 2;
        private readonly List<HostsEntry> _head = new(256);
        private readonly Queue<HostsEntry> _tail = new();
        private readonly List<HostsEntry> _kept = [];
        private readonly List<HostsMalformedLine> _malformedHead = [];
        private readonly Queue<(HostsMalformedLine Line, bool Kept)> _malformedTail = new();
        private readonly List<HostsMalformedLine> _malformedKept = [];
        private int _total;
        private int _malformedCount;
        private bool _keptOverflow;

        public void Add(HostsEntry entry)
        {
            _total++;
            if (keep is not null && entry.Names.Any(Wanted))
            {
                entry = entry with { Kept = true };
            }

            if (_head.Count < Half)
            {
                _head.Add(entry);
                return;
            }

            _tail.Enqueue(entry);
            if (_tail.Count > Half)
            {
                var leaving = _tail.Dequeue();
                if (leaving.Kept)
                {
                    if (_kept.Count < HostsParseResult.MaxKeptExtra)
                    {
                        _kept.Add(leaving);
                    }
                    else
                    {
                        _keptOverflow = true;
                    }
                }
            }
        }

        public void Malformed(int line, ReadOnlySpan<char> text, List<string> fields, string reason)
        {
            _malformedCount++;
            bool ignored = false;
            var item = new HostsMalformedLine(line, Raw(text.ToString(), HostsParseResult.MaxMalformedLineLength, ref ignored), reason);
            if (_malformedHead.Count < MalformedHalf)
            {
                _malformedHead.Add(item);
                return;
            }

            _malformedTail.Enqueue((item, keep is not null && fields.Any(Wanted)));
            if (_malformedTail.Count > MalformedHalf)
            {
                var leaving = _malformedTail.Dequeue();
                if (leaving.Kept && _malformedKept.Count < HostsParseResult.MaxKeptMalformedLines)
                {
                    _malformedKept.Add(leaving.Line);
                }
            }
        }

        public HostsParseResult Result(HostsTextEncoding encoding, bool dropped)
        {
            var entries = new List<HostsEntry>(_head.Count + _kept.Count + _tail.Count);
            entries.AddRange(_head);
            entries.AddRange(_kept);
            entries.AddRange(_tail);
            var malformed = new List<HostsMalformedLine>(_malformedHead);
            malformed.AddRange(_malformedKept);
            malformed.AddRange(_malformedTail.Select(t => t.Line));
            return new HostsParseResult
            {
                Encoding = encoding,
                Entries = entries.AsReadOnly(),
                TotalEntries = _total,
                EntriesTruncated = _total > entries.Count || _keptOverflow,
                MalformedLines = malformed.AsReadOnly(),
                MalformedCount = _malformedCount,
                PartialLastLineDropped = dropped,
            };
        }

        private bool Wanted(string name)
        {
            try
            {
                return keep!(name);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return true; // a failing filter must not hide an entry
            }
        }
    }
}
