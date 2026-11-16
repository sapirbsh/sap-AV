using System.Text;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.Core.Tests.BrowserHijack;

/// <summary>E6 / B5: the hosts answer of the scan worker, and the engine's checks of it (untrusted input).</summary>
public sealed class WireHostsCodecTests
{
    private static WireParsedFile Parse(string text, IReadOnlyList<string>? keep = null) =>
        WireParsedFileCodec.ParseHostsInWorker(Encoding.UTF8.GetBytes(text), inputTruncated: false, keep);

    private static WireHostsEntry Entry(string address, int line, params string[] names) =>
        new() { Address = address, RawAddress = null, Names = names, Line = line, NamesTruncated = false };

    private static WireHostsFile Hosts(params WireHostsEntry[] entries) => new()
    {
        Encoding = HostsTextEncoding.Utf8,
        Entries = entries,
        TotalEntries = entries.Length,
        EntriesTruncated = false,
        MalformedLines = [],
        MalformedCount = 0,
        PartialLastLineDropped = false,
        InputTruncated = false,
        Utf16Decoding = null,
    };

    private static WireHostsMalformedLine Bad(int line) => new() { Line = line, Text = "x", Reason = "r" };

    private static WireParsedFile Answer(WireHostsFile hosts) =>
        new() { Kind = WorkerParseKind.HostsFile, Error = null, Task = null, Link = null, Hosts = hosts };

    [Fact]
    public void RoundTrip_ThroughTheStrictJson_GivesTheParsersResult()
    {
        var wire = Parse("# c\n0.0.0.0 virustotal.com www.virustotal.com\n::1 localhost\nnot-an-address x\n0x7f.1 eset.com\n");
        var json = WorkerJson.Serialize(wire, WorkerLimits.MaxHostsResponseBytes);

        var parsed = WireParsedFileCodec.FromWire(WorkerJson.Deserialize<WireParsedFile>(json), WorkerParseKind.HostsFile);

        var hosts = parsed.Hosts!;
        Assert.Null(parsed.Error);
        Assert.Equal(3, hosts.TotalEntries);
        Assert.Equal(new[] { "virustotal.com", "www.virustotal.com" }, hosts.Entries[0].Names);
        Assert.True(hosts.Entries[0].IsBlocking);
        Assert.Equal(HostsAddressFamily.IPv6, hosts.Entries[1].Family);
        Assert.Equal("0x7f.1", hosts.Entries[2].RawAddress);
        Assert.True(hosts.Entries[2].IsBlocking); // 127.0.0.1, recomputed engine-side
        Assert.Equal(4, Assert.Single(hosts.MalformedLines).Line);
    }

    [Fact]
    public void AUtf16Decoding_RoundTrips()
    {
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("127.0.0.1 bitdefender.com\r\n")).ToArray();
        var wire = WireParsedFileCodec.ParseHostsInWorker(bytes, inputTruncated: false, null);

        var hosts = WireParsedFileCodec.FromWire(WorkerJson.Deserialize<WireParsedFile>(WorkerJson.Serialize(wire, WorkerLimits.MaxHostsResponseBytes)),
            WorkerParseKind.HostsFile).Hosts!;

        Assert.True(hosts.EncodingMismatch);
        Assert.Equal("bitdefender.com", Assert.Single(hosts.Utf16Decoding!.Entries).Names[0]);
    }

    [Fact]
    public void AnInvalidNameFilter_IsAnErrorAnswer_AndTheFilterMatchesSubdomainsOnly()
    {
        Assert.NotNull(Parse("127.0.0.1 a\n", ["has space"]).Error);
        Assert.NotNull(Parse("127.0.0.1 a\n", Enumerable.Repeat("a.com", HostsNameFilter.MaxSuffixes + 1).ToArray()).Error);

        Assert.True(HostsNameFilter.Matches("WWW.VirusTotal.com.", ["virustotal.com"]));
        Assert.False(HostsNameFilter.Matches("evilvirustotal.com", ["virustotal.com"]));
    }

    public static TheoryData<string> BrokenAnswers => new()
    {
        "octal address", "not an address", "uppercase IPv6", "zone ID", "raw that reads elsewhere", "no names", "too many names",
        "name with space", "overlong name", "lines out of order", "malformed out of order", "too many entries", "total below listed",
        "missing truncated flag", "total over the line cap", "hosts answer to a task request", "error and hosts", "hosts request without hosts",
        "overlong malformed line", "nested decoding without a UTF-16 BOM",
    };

    [Theory]
    [MemberData(nameof(BrokenAnswers))]
    public void BrokenAnswers_AreProtocolViolations(string what)
    {
        var good = Hosts(Entry("127.0.0.1", 1, "a.example"));
        var expected = WorkerParseKind.HostsFile;
        WireParsedFile answer = what switch
        {
            "octal address" => Answer(Hosts(Entry("0177.0.0.1", 1, "a"))),
            "not an address" => Answer(Hosts(Entry("evil", 1, "a"))),
            "uppercase IPv6" => Answer(Hosts(Entry("2001:DB8::1", 1, "a"))),
            "zone ID" => Answer(Hosts(Entry("fe80::1%4", 1, "a"))),
            "raw that reads elsewhere" => Answer(Hosts(Entry("127.0.0.1", 1, "a") with { RawAddress = "0x0a.1" })),
            "no names" => Answer(Hosts(Entry("127.0.0.1", 1))),
            "too many names" => Answer(Hosts(Entry("127.0.0.1", 1, Enumerable.Repeat("a", HostsParseResult.MaxNamesPerLine + 1).ToArray()))),
            "name with space" => Answer(Hosts(Entry("127.0.0.1", 1, "a b"))),
            "overlong name" => Answer(Hosts(Entry("127.0.0.1", 1, new string('a', HostsParseResult.MaxNameLength + 1)))),
            "lines out of order" => Answer(Hosts(Entry("127.0.0.1", 5, "a"), Entry("127.0.0.1", 5, "b"))),
            "malformed out of order" => Answer(good with { MalformedLines = [Bad(9), Bad(3)], MalformedCount = 2 }),
            "too many entries" => Answer(Hosts(Enumerable.Range(1, WireHostsCodec.MaxEntries + 1).Select(i => Entry("127.0.0.1", i, "a")).ToArray())),
            "total below listed" => Answer(good with { TotalEntries = 0 }),
            "missing truncated flag" => Answer(good with { TotalEntries = 2 }),
            "total over the line cap" => Answer(good with { TotalEntries = WireHostsCodec.MaxLine, EntriesTruncated = true, MalformedCount = 5 }),
            "hosts answer to a task request" => Answer(good) with { Kind = WorkerParseKind.ScheduledTask },
            "error and hosts" => Answer(good) with { Error = "x" },
            "hosts request without hosts" => Answer(good) with
            {
                Hosts = null,
                Link = new WireShellLink
                {
                    IdListPath = "a", IdListUnsupported = false, LinkInfoPath = null, LinkInfoNetworkShare = null, EnvironmentTarget = null,
                    RelativePath = null, WorkingDirectory = null, Arguments = null, Truncated = false,
                },
            },
            "overlong malformed line" => Answer(good with
            {
                MalformedLines = [new WireHostsMalformedLine { Line = 2, Text = new string('x', HostsParseResult.MaxMalformedLineLength + 1), Reason = "r" }],
                MalformedCount = 1,
            }),
            "nested decoding without a UTF-16 BOM" => Answer(good with { Utf16Decoding = good }),
            _ => throw new ArgumentOutOfRangeException(nameof(what)),
        };

        if (what == "hosts answer to a task request")
        {
            expected = WorkerParseKind.ScheduledTask;
        }

        Assert.Throws<WorkerProtocolException>(() => WireParsedFileCodec.FromWire(answer, expected));
    }

    [Fact]
    public void TheLargestAnswer_FitsTheHostsResponseCap_EvenFullyEscaped()
    {
        // Worst case for the JSON size: both decodings full, the character budget spent on one-character names that each escape
        // to six bytes, and every malformed line at its caps.
        int perEntry = WireHostsCodec.MaxCharacters / (2 * WireHostsCodec.MaxEntries); // address + names
        int names = perEntry - 3;
        WireHostsFile Full(HostsTextEncoding encoding, WireHostsFile? nested) => Hosts(Enumerable.Range(1, WireHostsCodec.MaxEntries)
                .Select(i => Entry("::1", i, Enumerable.Repeat("é", names).ToArray())).ToArray()) with
        {
            Encoding = encoding,
            MalformedLines = Enumerable.Range(1, WireHostsCodec.MaxMalformedLines).Select(i => new WireHostsMalformedLine
            {
                Line = WireHostsCodec.MaxEntries + i,
                Text = new string('é', HostsParseResult.MaxMalformedLineLength),
                Reason = new string('é', HostsParseResult.MaxReasonLength),
            }).ToArray(),
            MalformedCount = WireHostsCodec.MaxMalformedLines,
            Utf16Decoding = nested,
        };
        var answer = Answer(Full(HostsTextEncoding.Utf16LittleEndian, Full(HostsTextEncoding.Utf16LittleEndian, null)));

        Assert.NotNull(WireParsedFileCodec.FromWire(answer, WorkerParseKind.HostsFile).Hosts); // valid
        Assert.InRange(WorkerJson.Serialize(answer, WorkerLimits.MaxHostsResponseBytes).Length, 1, WorkerLimits.MaxHostsResponseBytes);
    }

    [Fact]
    public void TheWorkerSide_DropsEntriesPastTheCharacterBudget_AndSaysSo()
    {
        var name = new string('a', HostsParseResult.MaxNameLength);
        var sb = new StringBuilder();
        for (int i = 0; i < 4000; i++)
        {
            sb.Append("127.0.0.1 ").Append(name).Append('\n'); // 4000 x 264 characters > the budget
        }

        var wire = Parse(sb.ToString()).Hosts!;

        Assert.True(wire.EntriesTruncated);
        Assert.Equal(4000, wire.TotalEntries);
        Assert.True(wire.Entries.Sum(e => e.Address.Length + e.Names.Sum(n => n.Length)) <= WireHostsCodec.MaxCharacters);
        Assert.Equal(4000, wire.Entries[^1].Line); // head and tail alternately: the tail is represented too
        Assert.NotNull(WireHostsCodec.FromWire(wire));
    }

    [Fact]
    public void KeptEntries_SurviveLongNamePadding_InTheHead()
    {
        // Review H1: 64 names x 255 characters per padding line used to spend the whole budget before the kept entry.
        var padding = "0.0.0.0 " + string.Join(' ', Enumerable.Range(0, HostsParseResult.MaxNamesPerLine)
            .Select(i => $"{i:D3}" + new string('p', HostsParseResult.MaxNameLength - 3)));
        var sb = new StringBuilder();
        for (int i = 0; i < 50; i++)
        {
            sb.Append(padding).Append('\n');
        }

        sb.Append("10.6.6.6 www.virustotal.com\n");

        var wire = Parse(sb.ToString(), HostsNameFilter.DefaultSecurityDomains).Hosts!;

        Assert.True(wire.EntriesTruncated);
        Assert.Contains(wire.Entries, e => e.Names.Contains("www.virustotal.com"));
        Assert.Equal(51, wire.TotalEntries);
        Assert.NotNull(WireHostsCodec.FromWire(wire));
    }
}
