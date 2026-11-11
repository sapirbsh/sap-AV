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
}

public sealed record WireHostsEntry
{
    public required string Address { get; init; }

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
/// <see cref="ToWire"/> runs in the worker and fits the answer into <see cref="MaxCharacters"/> (dropping entries from the end,
/// which sets <see cref="WireHostsFile.EntriesTruncated"/>); <see cref="FromWire"/> runs in the engine and checks every count,
/// length, address, name and line order, recomputing what it can (address family, blocking) instead of trusting it.
/// </summary>
public static class WireHostsCodec
{
    /// <summary>Most address + name characters in one answer. Fully escaped (6 bytes each) plus per-entry JSON overhead, it fits <see cref="WorkerLimits.MaxHostsResponseBytes"/>.</summary>
    public const int MaxCharacters = 600_000;

    /// <summary>Longest address text (IPv6 with a zone ID).</summary>
    public const int MaxAddressLength = 64;

    /// <summary>Most entries in one answer: the head + tail cap plus the kept extras.</summary>
    public const int MaxEntries = HostsParseResult.MaxEntries + HostsParseResult.MaxKeptExtra;

    /// <summary>Highest possible line number for a file read up to the hosts cap.</summary>
    public const int MaxLine = HostsFileSnapshot.MaxBytes + 1;

    /// <summary>Worker side: the parse result as a wire answer within the caps.</summary>
    public static WireHostsFile ToWire(HostsParseResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        int left = MaxCharacters;
        var entries = new List<WireHostsEntry>(Math.Min(result.Entries.Count, MaxEntries));
        bool cut = false;
        foreach (var entry in result.Entries)
        {
            int size = entry.Address.Length + entry.Names.Sum(n => n.Length);
            if (entries.Count == MaxEntries || size > left)
            {
                cut = true;
                break;
            }

            left -= size;
            entries.Add(new WireHostsEntry { Address = entry.Address, Names = entry.Names.ToArray(), Line = entry.Line, NamesTruncated = entry.NamesTruncated });
        }

        return new WireHostsFile
        {
            Encoding = result.Encoding,
            Entries = entries,
            TotalEntries = result.TotalEntries,
            EntriesTruncated = result.EntriesTruncated || cut,
            MalformedLines = result.MalformedLines.Take(HostsParseResult.MaxMalformedLines)
                .Select(m => new WireHostsMalformedLine { Line = m.Line, Text = m.Text, Reason = SafeText.SingleLine(m.Reason, WorkerLimits.MaxTextLength) })
                .ToArray(),
            MalformedCount = result.MalformedCount,
            PartialLastLineDropped = result.PartialLastLineDropped,
            InputTruncated = result.InputTruncated,
        };
    }

    /// <summary>Engine side: rebuilds and checks a worker's hosts answer.</summary>
    /// <exception cref="WorkerProtocolException">The answer breaks the protocol.</exception>
    public static HostsParseResult FromWire(WireHostsFile wire)
    {
        ArgumentNullException.ThrowIfNull(wire);
        Require(Enum.IsDefined(wire.Encoding), "an unknown encoding");
        Require(wire.Entries is not null && wire.MalformedLines is not null, "a null list");
        Require(wire.Entries!.Count <= MaxEntries, $"{wire.Entries.Count} entries");
        Require(wire.TotalEntries >= wire.Entries.Count, "fewer total entries than listed");
        Require(wire.EntriesTruncated || wire.TotalEntries == wire.Entries.Count, "missing entries without the truncated flag");
        Require(wire.MalformedLines!.Count <= HostsParseResult.MaxMalformedLines && wire.MalformedCount >= wire.MalformedLines.Count && wire.MalformedCount <= MaxLine,
            "a malformed-line count outside its caps");

        int total = 0, previousLine = 0;
        var entries = new List<HostsEntry>(wire.Entries.Count);
        foreach (var e in wire.Entries)
        {
            if (e?.Address is null || e.Names is null)
            {
                throw new WorkerProtocolException("The parsed hosts file has a null entry.");
            }

            Require(e.Line > previousLine && e.Line <= MaxLine, "entries out of line order");
            previousLine = e.Line;
            System.Net.IPAddress? address = null;
            var family = HostsAddressFamily.IPv4;
            Require(e.Address.Length <= MaxAddressLength && HostsFileParser.TryParseAddress(e.Address, out address, out family),
                "an invalid address");
            Require(e.Names.Count is > 0 and <= HostsParseResult.MaxNamesPerLine, "a name count outside its caps");
            total += e.Address.Length;
            foreach (var name in e.Names)
            {
                Require(IsName(name), "an invalid host name");
                total += name.Length;
            }

            Require(total <= MaxCharacters, "too much hosts text");
            bool blocking = System.Net.IPAddress.IsLoopback(address!) || address!.Equals(System.Net.IPAddress.Any) || address.Equals(System.Net.IPAddress.IPv6Any);
            entries.Add(new HostsEntry(e.Address, family, blocking, e.Names.ToArray(), e.Line, e.NamesTruncated));
        }

        var malformed = new List<HostsMalformedLine>(wire.MalformedLines.Count);
        foreach (var m in wire.MalformedLines)
        {
            if (m?.Text is null || m.Reason is null)
            {
                throw new WorkerProtocolException("The parsed hosts file has a null malformed line.");
            }

            Require(m.Line is > 0 and <= MaxLine && m.Text.Length <= HostsParseResult.MaxMalformedLineLength && SafeText.Identifier(m.Text) == m.Text,
                "a malformed line outside its caps");
            Require(m.Reason.Length is > 0 and <= WorkerLimits.MaxTextLength && SafeText.SingleLine(m.Reason, WorkerLimits.MaxTextLength) == m.Reason,
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
