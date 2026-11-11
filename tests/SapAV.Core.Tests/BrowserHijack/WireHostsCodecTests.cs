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
        new() { Address = address, Names = names, Line = line, NamesTruncated = false };

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
    };

    private static WireParsedFile Answer(WireHostsFile hosts) =>
        new() { Kind = WorkerParseKind.HostsFile, Error = null, Task = null, Link = null, Hosts = hosts };

    [Fact]
    public void RoundTrip_ThroughTheStrictJson_GivesTheParsersResult()
    {
        var wire = Parse("# c\n0.0.0.0 virustotal.com www.virustotal.com\n::1 localhost\nnot-an-address x\n");
        var json = WorkerJson.Serialize(wire, WorkerLimits.MaxHostsResponseBytes);

        var parsed = WireParsedFileCodec.FromWire(WorkerJson.Deserialize<WireParsedFile>(json), WorkerParseKind.HostsFile);

        var hosts = parsed.Hosts!;
        Assert.Null(parsed.Error);
        Assert.Equal(2, hosts.TotalEntries);
        Assert.Equal(new[] { "virustotal.com", "www.virustotal.com" }, hosts.Entries[0].Names);
        Assert.True(hosts.Entries[0].IsBlocking);
        Assert.Equal(HostsAddressFamily.IPv6, hosts.Entries[1].Family);
        Assert.Equal(4, Assert.Single(hosts.MalformedLines).Line);
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
        "octal address", "not an address", "no names", "too many names", "name with space", "overlong name", "lines out of order",
        "too many entries", "total below listed", "missing truncated flag", "hosts answer to a task request", "error and hosts",
        "hosts request without hosts", "overlong malformed line",
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
            "no names" => Answer(Hosts(Entry("127.0.0.1", 1))),
            "too many names" => Answer(Hosts(Entry("127.0.0.1", 1, Enumerable.Repeat("a", HostsParseResult.MaxNamesPerLine + 1).ToArray()))),
            "name with space" => Answer(Hosts(Entry("127.0.0.1", 1, "a b"))),
            "overlong name" => Answer(Hosts(Entry("127.0.0.1", 1, new string('a', HostsParseResult.MaxNameLength + 1)))),
            "lines out of order" => Answer(Hosts(Entry("127.0.0.1", 5, "a"), Entry("127.0.0.1", 5, "b"))),
            "too many entries" => Answer(Hosts(Enumerable.Range(1, WireHostsCodec.MaxEntries + 1).Select(i => Entry("127.0.0.1", i, "a")).ToArray())),
            "total below listed" => Answer(good with { TotalEntries = 0 }),
            "missing truncated flag" => Answer(good with { TotalEntries = 2 }),
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
        // Worst case for the JSON size: the character budget spent on one-character names that each escape to six bytes.
        const int namesPerEntry = 45;
        Assert.True(WireHostsCodec.MaxEntries * (namesPerEntry + 3) <= WireHostsCodec.MaxCharacters);
        var entries = Enumerable.Range(1, WireHostsCodec.MaxEntries)
            .Select(i => Entry("::1", i, Enumerable.Repeat("é", namesPerEntry).ToArray())).ToArray();
        var malformed = Enumerable.Range(1, HostsParseResult.MaxMalformedLines).Select(i => new WireHostsMalformedLine
        {
            Line = WireHostsCodec.MaxEntries + i,
            Text = new string('é', HostsParseResult.MaxMalformedLineLength),
            Reason = new string('é', WorkerLimits.MaxTextLength),
        }).ToArray();
        var answer = Answer(Hosts(entries) with { MalformedLines = malformed, MalformedCount = malformed.Length });

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
        Assert.NotNull(WireHostsCodec.FromWire(wire));
    }
}
