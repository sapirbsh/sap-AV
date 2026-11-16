using System.Net;
using System.Text.Json.Serialization;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.Scanning.Isolation;

/// <summary>A parsed hosts file, worker to engine (E6 / B5). <b>Untrusted</b>: rebuilt by <see cref="WireHostsCodec.FromWire"/>.</summary>
public sealed record WireHostsFile
{
    [JsonConverter(typeof(StrictEnumConverter<HostsTextEncoding>))]
    public required HostsTextEncoding Encoding { get; init; }

    public required IReadOnlyList<WireHostsEntry> Entries { get; init; }

    public required int TotalEntries { get; init; }

    public required bool EntriesTruncated { get; init; }

    public required IReadOnlyList<WireHostsMalformedLine> MalformedLines { get; init; }

    public required int MalformedCount { get; init; }

    public required bool PartialLastLineDropped { get; init; }

    public required bool InputTruncated { get; init; }

    /// <summary>The UTF-16 decoding (only with a UTF-16 BOM, and never nested further).</summary>
    public required WireHostsFile? Utf16Decoding { get; init; }
}

public sealed record WireHostsEntry
{
    /// <summary>Canonical (<see cref="IPAddress.ToString"/>).</summary>
    public required string Address { get; init; }

    /// <summary>The non-canonical IPv4 text as written, or null.</summary>
    public required string? RawAddress { get; init; }

    public required IReadOnlyList<string> Names { get; init; }

    public required int Line { get; init; }

    public required bool NamesTruncated { get; init; }
}

public sealed record WireHostsMalformedLine
{
    public required int Line { get; init; }

    public required string Text { get; init; }

    public required string Reason { get; init; }
}

/// <summary>
/// The hosts part of the worker protocol (E6, B5 rule: the SYSTEM engine never parses the hosts file).
/// <see cref="ToWire"/> runs in the worker and fits the answer into <see cref="MaxCharacters"/>, spending the budget in priority
/// order (entries naming a kept domain first, then head and tail alternately), which sets
/// <see cref="WireHostsFile.EntriesTruncated"/> when anything is left out. <see cref="FromWire"/> runs in the engine and checks
/// every count, length, address, name and line order, recomputing what it can (address family, blocking) instead of trusting it.
/// </summary>
public static class WireHostsCodec
{
    /// <summary>
    /// Most address + name characters in one answer (both decodings together). Fully escaped (6 bytes each, plus 3 bytes per
    /// one-character name) plus per-entry JSON overhead, it fits <see cref="WorkerLimits.MaxHostsResponseBytes"/>.
    /// </summary>
    public const int MaxCharacters = 500_000;

    /// <summary>Longest address text.</summary>
    public const int MaxAddressLength = 64;

    /// <summary>Most entries per decoding: the head + tail cap plus the kept extras.</summary>
    public const int MaxEntries = HostsParseResult.MaxEntries + HostsParseResult.MaxKeptExtra;

    /// <summary>Most malformed lines per decoding: first and last half plus the kept ones.</summary>
    public const int MaxMalformedLines = HostsParseResult.MaxMalformedLines + HostsParseResult.MaxKeptMalformedLines;

    /// <summary>Highest possible line number for a file read up to the hosts cap.</summary>
    public const int MaxLine = HostsFileSnapshot.MaxBytes + 1;

    /// <summary>Worker side: the parse result as a wire answer within the caps.</summary>
    public static WireHostsFile ToWire(HostsParseResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var utf16 = result.Utf16Decoding;
        var lists = utf16 is null ? new[] { result.Entries } : [result.Entries, utf16.Entries];
        var chosen = lists.Select(l => new bool[l.Count]).ToArray();
        int left = MaxCharacters;
        bool[] cut = new bool[lists.Length];
        int[] counts = new int[lists.Length];
        foreach (var (list, index) in Priority(lists))
        {
            var entry = lists[list][index];
            int size = Size(entry);
            if (size > left || counts[list] >= MaxEntries)
            {
                cut[list] = true;
                continue; // a smaller, later entry may still fit
            }

            left -= size;
            chosen[list][index] = true;
            counts[list]++;
        }

        WireHostsFile Build(HostsParseResult part, int list, WireHostsFile? nested) => new()
        {
            Encoding = part.Encoding,
            Entries = part.Entries.Where((_, i) => chosen[list][i]).Select(e => new WireHostsEntry
            {
                Address = e.Address, RawAddress = e.RawAddress, Names = e.Names.ToArray(), Line = e.Line, NamesTruncated = e.NamesTruncated,
            }).ToArray(),
            TotalEntries = part.TotalEntries,
            EntriesTruncated = part.EntriesTruncated || cut[list],
            MalformedLines = part.MalformedLines.Take(MaxMalformedLines)
                .Select(m => new WireHostsMalformedLine { Line = m.Line, Text = m.Text, Reason = SafeText.SingleLine(m.Reason, HostsParseResult.MaxReasonLength) })
                .ToArray(),
            MalformedCount = part.MalformedCount,
            PartialLastLineDropped = part.PartialLastLineDropped,
            InputTruncated = part.InputTruncated,
            Utf16Decoding = nested,
        };

        return Build(result, 0, utf16 is null ? null : Build(utf16, 1, null));
    }

    /// <summary>Budget order: kept entries of every list, then each list's head and tail alternately (the primary decoding first).</summary>
    private static IEnumerable<(int List, int Index)> Priority(IReadOnlyList<HostsEntry>[] lists)
    {
        for (int l = 0; l < lists.Length; l++)
        {
            for (int i = 0; i < lists[l].Count; i++)
            {
                if (lists[l][i].Kept)
                {
                    yield return (l, i);
                }
            }
        }

        for (int l = 0; l < lists.Length; l++)
        {
            for (int low = 0, high = lists[l].Count - 1; low <= high; low++, high--)
            {
                if (!lists[l][low].Kept)
                {
                    yield return (l, low);
                }

                if (high != low && !lists[l][high].Kept)
                {
                    yield return (l, high);
                }
            }
        }
    }

    private static int Size(HostsEntry entry) => entry.Address.Length + (entry.RawAddress?.Length ?? 0) + entry.Names.Sum(n => n.Length);

    /// <summary>Engine side: rebuilds and checks a worker's hosts answer.</summary>
    /// <exception cref="WorkerProtocolException">The answer breaks the protocol.</exception>
    public static HostsParseResult FromWire(WireHostsFile wire)
    {
        ArgumentNullException.ThrowIfNull(wire);
        int total = 0;
        var result = FromWire(wire, nested: false, ref total);
        if (wire.Utf16Decoding is { } utf16)
        {
            Require(result.Utf16Bom, "a UTF-16 decoding without a UTF-16 byte order mark");
            Require(utf16.Encoding == wire.Encoding, "a UTF-16 decoding with another encoding");
            result = result with { Utf16Decoding = FromWire(utf16, nested: true, ref total) };
        }

        return result;
    }

    private static HostsParseResult FromWire(WireHostsFile wire, bool nested, ref int total)
    {
        Require(Enum.IsDefined(wire.Encoding), "an unknown encoding");
        Require(!nested || wire.Utf16Decoding is null, "a nested decoding inside a decoding");
        if (wire.Entries is null || wire.MalformedLines is null)
        {
            throw new WorkerProtocolException("The parsed hosts file has a null list.");
        }

        Require(wire.Entries.Count <= MaxEntries, $"{wire.Entries.Count} entries");
        Require(wire.TotalEntries >= wire.Entries.Count && wire.TotalEntries <= MaxLine, "a total entry count outside its range");
        Require(wire.EntriesTruncated || wire.TotalEntries == wire.Entries.Count, "missing entries without the truncated flag");
        Require(wire.MalformedLines.Count <= MaxMalformedLines && wire.MalformedCount >= wire.MalformedLines.Count && wire.MalformedCount <= MaxLine,
            "a malformed-line count outside its caps");
        Require((long)wire.TotalEntries + wire.MalformedCount <= MaxLine, "more entries and malformed lines than lines");

        int previousLine = 0;
        var entries = new List<HostsEntry>(wire.Entries.Count);
        foreach (var e in wire.Entries)
        {
            if (e?.Address is null || e.Names is null)
            {
                throw new WorkerProtocolException("The parsed hosts file has a null entry.");
            }

            Require(e.Line > previousLine && e.Line <= MaxLine, "entries out of line order");
            previousLine = e.Line;
            var (address, family) = CanonicalAddress(e.Address, e.RawAddress);
            Require(e.Names.Count is > 0 and <= HostsParseResult.MaxNamesPerLine, "a name count outside its caps");
            total += e.Address.Length + (e.RawAddress?.Length ?? 0);
            foreach (var name in e.Names)
            {
                Require(IsName(name), "an invalid host name");
                total += name.Length;
            }

            Require(total <= MaxCharacters, "too much hosts text");
            bool blocking = IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
            entries.Add(new HostsEntry(e.Address, family, blocking, e.Names.ToArray(), e.Line, e.NamesTruncated) { RawAddress = e.RawAddress });
        }

        previousLine = 0;
        var malformed = new List<HostsMalformedLine>(wire.MalformedLines.Count);
        foreach (var m in wire.MalformedLines)
        {
            if (m?.Text is null || m.Reason is null)
            {
                throw new WorkerProtocolException("The parsed hosts file has a null malformed line.");
            }

            Require(m.Line > previousLine && m.Line <= MaxLine, "malformed lines out of line order");
            previousLine = m.Line;
            Require(m.Text.Length <= HostsParseResult.MaxMalformedLineLength && SafeText.Identifier(m.Text) == m.Text, "a malformed line outside its caps");
            Require(m.Reason.Length is > 0 and <= HostsParseResult.MaxReasonLength && SafeText.SingleLine(m.Reason, HostsParseResult.MaxReasonLength) == m.Reason,
                "a malformed-line reason outside its caps");
            malformed.Add(new HostsMalformedLine(m.Line, m.Text, m.Reason));
        }

        return new HostsParseResult
        {
            Encoding = wire.Encoding,
            Entries = entries.AsReadOnly(),
            TotalEntries = wire.TotalEntries,
            EntriesTruncated = wire.EntriesTruncated,
            MalformedLines = malformed.AsReadOnly(),
            MalformedCount = wire.MalformedCount,
            PartialLastLineDropped = wire.PartialLastLineDropped,
            InputTruncated = wire.InputTruncated,
        };
    }

    /// <summary>
    /// The address must be canonical (equal to its own <see cref="IPAddress.ToString"/>, no brackets or zone); a raw address must be
    /// a non-canonical IPv4 form that reads as that address.
    /// </summary>
    private static (IPAddress Address, HostsAddressFamily Family) CanonicalAddress(string text, string? raw)
    {
        IPAddress? address = null;
        var family = HostsAddressFamily.IPv4;
        Require(text.Length <= MaxAddressLength && text.IndexOfAny(['[', ']', '%']) < 0
            && HostsFileParser.TryParseAddress(text, out address, out family) && address!.ToString() == text, "a non-canonical or invalid address");
        if (raw is not null)
        {
            Require(family == HostsAddressFamily.IPv4 && raw.Length <= MaxAddressLength && raw != text
                && !HostsFileParser.TryParseAddress(raw, out _, out _) && HostsFileParser.TryParseLooseIPv4(raw, out var loose) && loose!.Equals(address),
                "a raw address that doesn't read as its address");
        }

        return (address!, family);
    }

    /// <summary>What the parser can produce as a name: non-empty, capped, no field separator or comment, already sanitized.</summary>
    private static bool IsName(string? name) =>
        name is { Length: > 0 and <= HostsParseResult.MaxNameLength }
        && name.IndexOfAny([' ', '\t', '#', '\r', '\n']) < 0
        && SafeText.Identifier(name) == name;

    private static void Require(bool condition, string what)
    {
        if (!condition)
        {
            throw new WorkerProtocolException($"The parsed hosts file has {what}.");
        }
    }
}
