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

/// <summary>The text encoding a hosts file was decoded with.</summary>
public enum HostsTextEncoding
{
    /// <summary>No byte order mark: decoded as UTF-8 (invalid bytes become U+FFFD).</summary>
    Utf8,

    Utf8Bom,

    Utf16LittleEndian,

    Utf16BigEndian,
}

/// <summary>One hosts line that maps an address to names.</summary>
/// <param name="Address">The address as written (validated: strict dotted-decimal IPv4, or IPv6).</param>
/// <param name="IsBlocking">True for a loopback or unspecified address (0.0.0.0, 127.x, ::, ::1): the names are blocked, not redirected.</param>
/// <param name="Names">The host names, raw (<see cref="Text.SafeText.Identifier"/>), each capped at <see cref="HostsParseResult.MaxNameLength"/>.</param>
/// <param name="Line">The 1-based line number.</param>
/// <param name="NamesTruncated">True when names were left out (<see cref="HostsParseResult.MaxNamesPerLine"/>) or a name was cut.</param>
public sealed record HostsEntry(string Address, HostsAddressFamily Family, bool IsBlocking, IReadOnlyList<string> Names, int Line, bool NamesTruncated);

/// <summary>A non-comment line that isn't a valid entry, kept raw (<see cref="Text.SafeText.Identifier"/>) and capped.</summary>
public sealed record HostsMalformedLine(int Line, string Text, string Reason);

/// <summary>The parsed content of a hosts file.</summary>
/// <remarks>
/// At most <see cref="MaxEntries"/> entries are kept: the first and the last half, plus up to <see cref="MaxKeptExtra"/> entries
/// from the middle that the caller asked to keep (e.g. names on the security-domain list). <see cref="TotalEntries"/> holds the
/// real count; <see cref="EntriesTruncated"/> is a signal (a padded file can push a bad entry out of view).
/// </remarks>
public sealed record HostsParseResult
{
    public const int MaxEntries = 8192;
    public const int MaxKeptExtra = 4096;
    public const int MaxNamesPerLine = 64;
    public const int MaxNameLength = 255;
    public const int MaxMalformedLines = 64;
    public const int MaxMalformedLineLength = 256;

    public required HostsTextEncoding Encoding { get; init; }

    public required IReadOnlyList<HostsEntry> Entries { get; init; }

    /// <summary>How many valid entries the content had (more than <see cref="Entries"/> when truncated).</summary>
    public required int TotalEntries { get; init; }

    public required bool EntriesTruncated { get; init; }

    /// <summary>The first <see cref="MaxMalformedLines"/> malformed lines.</summary>
    public required IReadOnlyList<HostsMalformedLine> MalformedLines { get; init; }

    public required int MalformedCount { get; init; }

    /// <summary>True when the input was cut (the file is over the read cap) and its last, partial line was dropped.</summary>
    public required bool PartialLastLineDropped { get; init; }
}

/// <summary>
/// Parses hosts file content line by line, the way Windows' resolver reads it: <c>#</c> starts a comment anywhere, fields are
/// separated by spaces or tabs, the first field is the address and the rest are names. Never throws for any input.
/// </summary>
/// <remarks>
/// A pure function with no I/O, so it can move into the sandboxed scan worker unchanged (B5 rule). IPv4 must be strict
/// dotted-decimal: forms like <c>0177.0.0.1</c>, <c>1</c> or <c>0x7f.1</c> are malformed, because resolvers disagree on them.
/// </remarks>
public static class HostsFileParser
{
    /// <param name="content">The bytes read (at most the read cap).</param>
    /// <param name="inputTruncated">True when the file is longer than <paramref name="content"/>: the last partial line is dropped.</param>
    /// <param name="keep">Optional: entries with a name this returns true for are kept even beyond the cap (up to <see cref="HostsParseResult.MaxKeptExtra"/>).</param>
    public static HostsParseResult Parse(ReadOnlySpan<byte> content, bool inputTruncated, Func<string, bool>? keep = null)
    {
        var text = Decode(content, out var encoding);
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

        return collector.Result(encoding, dropped);
    }

    /// <summary>True for strict dotted-decimal IPv4 (four parts, 0-255, no leading zeros) or an IPv6 address.</summary>
    public static bool TryParseAddress(string text, out IPAddress? address, out HostsAddressFamily family)
    {
        address = null;
        family = HostsAddressFamily.IPv4;
        if (text.Contains(':'))
        {
            family = HostsAddressFamily.IPv6;
            return IPAddress.TryParse(text, out address) && address.AddressFamily == AddressFamily.InterNetworkV6;
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

    private static string Decode(ReadOnlySpan<byte> content, out HostsTextEncoding encoding)
    {
        if (content.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]))
        {
            encoding = HostsTextEncoding.Utf16LittleEndian;
            return System.Text.Encoding.Unicode.GetString(content[2..]);
        }

        if (content.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xFF]))
        {
            encoding = HostsTextEncoding.Utf16BigEndian;
            return System.Text.Encoding.BigEndianUnicode.GetString(content[2..]);
        }

        if (content.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            encoding = HostsTextEncoding.Utf8Bom;
            return Utf8.GetString(content[3..]);
        }

        encoding = HostsTextEncoding.Utf8;
        return Utf8.GetString(content);
    }

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

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

        if (!TryParseAddress(fields[0], out var address, out var family))
        {
            collector.Malformed(lineNumber, line, "The first field isn't a valid IPv4 or IPv6 address.");
            return;
        }

        if (fields.Count == 1)
        {
            collector.Malformed(lineNumber, line, "An address without a host name.");
            return;
        }

        bool cut = fields.Count - 1 > HostsParseResult.MaxNamesPerLine;
        var names = new List<string>(Math.Min(fields.Count - 1, HostsParseResult.MaxNamesPerLine));
        foreach (var name in fields.Skip(1).Take(HostsParseResult.MaxNamesPerLine))
        {
            names.Add(Raw(name, HostsParseResult.MaxNameLength, ref cut));
        }

        bool blocking = IPAddress.IsLoopback(address!) || address!.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
        collector.Add(new HostsEntry(Text.SafeText.Identifier(fields[0]), family, blocking, names.AsReadOnly(), lineNumber, cut));
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

    /// <summary>Keeps the first and the last half of the entries plus asked-for ones from the middle.</summary>
    private sealed class Collector(Func<string, bool>? keep)
    {
        private const int Half = HostsParseResult.MaxEntries / 2;
        private readonly List<HostsEntry> _head = new(256);
        private readonly Queue<HostsEntry> _tail = new();
        private readonly List<HostsEntry> _kept = [];
        private readonly List<HostsMalformedLine> _malformed = [];
        private int _total;
        private int _malformedCount;
        private bool _keptOverflow;

        public void Add(HostsEntry entry)
        {
            _total++;
            if (_head.Count < Half)
            {
                _head.Add(entry);
                return;
            }

            _tail.Enqueue(entry);
            if (_tail.Count > Half)
            {
                var leaving = _tail.Dequeue();
                if (keep is not null && leaving.Names.Any(Wanted))
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

        public void Malformed(int line, ReadOnlySpan<char> text, string reason)
        {
            _malformedCount++;
            if (_malformed.Count < HostsParseResult.MaxMalformedLines)
            {
                bool ignored = false;
                _malformed.Add(new HostsMalformedLine(line, Raw(text.ToString(), HostsParseResult.MaxMalformedLineLength, ref ignored), reason));
            }
        }

        public HostsParseResult Result(HostsTextEncoding encoding, bool dropped)
        {
            var entries = new List<HostsEntry>(_head.Count + _kept.Count + _tail.Count);
            entries.AddRange(_head);
            entries.AddRange(_kept);
            entries.AddRange(_tail);
            return new HostsParseResult
            {
                Encoding = encoding,
                Entries = entries.AsReadOnly(),
                TotalEntries = _total,
                EntriesTruncated = _total > entries.Count || _keptOverflow,
                MalformedLines = _malformed.AsReadOnly(),
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
