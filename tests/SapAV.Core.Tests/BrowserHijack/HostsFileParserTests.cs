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
    [InlineData("0177.0.0.1 kaspersky.com")] // octal-looking: resolvers disagree
    [InlineData("256.1.1.1 kaspersky.com")]
    [InlineData("1 kaspersky.com")]
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
    public void Utf16LittleEndianWithBom_IsDecoded()
    {
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("127.0.0.1 bitdefender.com\r\n")).ToArray();

        var result = HostsFileParser.Parse(bytes, inputTruncated: false);

        Assert.Equal(HostsTextEncoding.Utf16LittleEndian, result.Encoding);
        Assert.Equal("bitdefender.com", Assert.Single(result.Entries).Names[0]);
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
