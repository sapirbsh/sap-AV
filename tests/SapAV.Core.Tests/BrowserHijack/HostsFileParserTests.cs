using System.Text;
using SapAV.Core.BrowserHijack;

namespace SapAV.Core.Tests.BrowserHijack;

/// <summary>E6: the hosts parser (comments, tabs, multiple names, IPv6, malformed lines, caps, encodings). Synthetic content only.</summary>
public sealed class HostsFileParserTests
{
    private static HostsParseResult Parse(string text, bool truncated = false, Func<string, bool>? keep = null) =>
        HostsFileParser.Parse(Encoding.UTF8.GetBytes(text), truncated, keep);

    [Fact]
    public void CommentsTabsAndMultipleNames_AreParsed()
    {
        var result = Parse("# Copyright (c) Microsoft\r\n\r\n#\t127.0.0.1 localhost\r\n" +
            "0.0.0.0\tvirustotal.com  www.virustotal.com # blocked\r\n" +
            "  10.6.6.6 update.microsoft.com\r\n");

        Assert.Equal(2, result.TotalEntries);
        Assert.Equal(0, result.MalformedCount);
        var blocked = result.Entries[0];
        Assert.Equal("0.0.0.0", blocked.Address);
        Assert.True(blocked.IsBlocking);
        Assert.Equal(new[] { "virustotal.com", "www.virustotal.com" }, blocked.Names);
        Assert.Equal(4, blocked.Line);
        var redirect = result.Entries[1];
        Assert.False(redirect.IsBlocking);
        Assert.Equal(5, redirect.Line);
    }

    [Fact]
    public void IPv6_IsValid_AndLoopbackIsBlocking()
    {
        var result = Parse("::1 localhost\n2001:db8::66 eset.com\n");

        Assert.Equal(2, result.TotalEntries);
        Assert.All(result.Entries, e => Assert.Equal(HostsAddressFamily.IPv6, e.Family));
        Assert.True(result.Entries[0].IsBlocking);
        Assert.False(result.Entries[1].IsBlocking);
    }

    [Theory]
    [InlineData("256.1.1.1 kaspersky.com")]
    [InlineData("1.2.3.4.5 kaspersky.com")]
    [InlineData("fe80::1%4 kaspersky.com")] // a zone ID
    [InlineData("kaspersky.com 127.0.0.1")]
    [InlineData("127.0.0.1")] // no name
    public void MalformedLines_AreCountedAndKeptRaw(string line)
    {
        var result = Parse("127.0.0.1 localhost\n" + line + "\n");

        Assert.Equal(1, result.TotalEntries);
        Assert.Equal(1, result.MalformedCount);
        Assert.Equal(2, result.MalformedLines[0].Line);
        Assert.Equal(line, result.MalformedLines[0].Text);
    }

    [Fact]
    public void Utf16Content_IsInTheUtf16Decoding_AndFlaggedAsAMismatch()
    {
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("127.0.0.1 bitdefender.com\r\n")).ToArray();

        var result = HostsFileParser.Parse(bytes, inputTruncated: false);

        Assert.Equal(HostsTextEncoding.Utf16LittleEndian, result.Encoding);
        Assert.True(result.Utf16Bom);
        Assert.Empty(result.Entries); // what the resolver sees: NUL-riddled bytes
        Assert.Equal("bitdefender.com", Assert.Single(result.Utf16Decoding!.Entries).Names[0]);
        Assert.True(result.EncodingMismatch);
        Assert.Single(result.AllEntries);
    }

    [Fact]
    public void AsciiBehindAUtf16Bom_IsStillReadAsTheResolverReadsIt()
    {
        // Review H2: an editor shows garbage, but the resolver reads these bytes as ANSI and uses line 2.
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.ASCII.GetBytes("127.0.0.1 a.example\r\n10.6.6.6 www.virustotal.com\r\n")).ToArray();

        var result = HostsFileParser.Parse(bytes, inputTruncated: false);

        var entry = Assert.Single(result.Entries);
        Assert.Equal("www.virustotal.com", entry.Names[0]);
        Assert.Equal(2, entry.Line);
        Assert.Equal(1, result.MalformedLines[0].Line); // the BOM bytes are part of line 1
        Assert.True(result.EncodingMismatch);
    }

    [Theory]
    [InlineData("0177.0.0.1", "127.0.0.1")] // octal
    [InlineData("0x7f.1", "127.0.0.1")] // hex, short form
    [InlineData("2130706433", "127.0.0.1")] // one integer
    [InlineData("10.1", "10.0.0.1")]
    public void NonCanonicalIPv4_IsAnEntryWithItsRawText(string written, string canonical)
    {
        var entry = Assert.Single(Parse($"{written} kaspersky.com\n").Entries);

        Assert.Equal(canonical, entry.Address);
        Assert.Equal(written, entry.RawAddress);
        Assert.True(entry.NonCanonicalAddress);
    }

    [Fact]
    public void MalformedLines_KeepFirstLastAndFilterMatches()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 500; i++)
        {
            sb.Append("bad").Append(i).Append(" x\n");
            if (i == 250)
            {
                sb.Append("999.1.1.1 www.virustotal.com\n");
            }
        }

        var result = Parse(sb.ToString(), keep: n => n.EndsWith("virustotal.com", StringComparison.Ordinal));

        Assert.Equal(501, result.MalformedCount);
        Assert.Equal(HostsParseResult.MaxMalformedLines + 1, result.MalformedLines.Count);
        Assert.StartsWith("bad0 ", result.MalformedLines[0].Text);
        Assert.StartsWith("bad499 ", result.MalformedLines[^1].Text);
        Assert.Contains(result.MalformedLines, m => m.Text.Contains("virustotal"));
    }

    [Fact]
    public void TruncatedInput_DropsThePartialLastLine()
    {
        var result = Parse("127.0.0.1 a.example\n10.0.0.1 secur", truncated: true);

        Assert.True(result.PartialLastLineDropped);
        Assert.Equal("a.example", Assert.Single(result.Entries).Names[0]);
    }

    [Fact]
    public void ManyEntries_KeepHeadAndTail_PlusAskedForNamesFromTheMiddle()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 20_000; i++)
        {
            sb.Append("0.0.0.0 ad").Append(i).Append(".example\n");
            if (i == 10_000)
            {
                sb.Append("10.6.6.6 www.malwarebytes.com\n");
            }
        }

        var result = Parse(sb.ToString(), keep: name => name.EndsWith("malwarebytes.com", StringComparison.OrdinalIgnoreCase));

        Assert.Equal(20_001, result.TotalEntries);
        Assert.True(result.EntriesTruncated);
        Assert.Equal(HostsParseResult.MaxEntries + 1, result.Entries.Count);
        Assert.Equal("ad0.example", result.Entries[0].Names[0]);
        Assert.Equal("ad19999.example", result.Entries[^1].Names[0]);
        Assert.Contains(result.Entries, e => e.Names.Contains("www.malwarebytes.com"));
    }

    [Fact]
    public void OverlongNamesAndTooManyNames_AreCapped_AndControlCharactersReplaced()
    {
        var names = string.Join(' ', Enumerable.Range(0, 100).Select(i => "n" + i));
        var result = Parse($"127.0.0.1 {new string('x', 1000)} a\u0001b\n127.0.0.2 {names}\n");

        Assert.Equal(HostsParseResult.MaxNameLength, result.Entries[0].Names[0].Length);
        Assert.Equal("a�b", result.Entries[0].Names[1]);
        Assert.True(result.Entries[0].NamesTruncated);
        Assert.Equal(HostsParseResult.MaxNamesPerLine, result.Entries[1].Names.Count);
        Assert.True(result.Entries[1].NamesTruncated);
    }
}
