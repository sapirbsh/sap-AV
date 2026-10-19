using System.Text;
using SapAV.Core.Blocklist;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Blocklist;

/// <summary>File-level format edges: comment-only, BOM-only, CRLF vs LF bytes, tabs, case.</summary>
public sealed class HashBlocklistFormatEdgeTests : IDisposable
{
    private const string Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string Hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    private static readonly byte[] Bom = Encoding.UTF8.GetPreamble();

    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<HashBlocklist> LoadFile(byte[] content, string name = "list.txt")
    {
        var path = _dir.WriteFile(name, content);
        return await HashBlocklist.LoadAsync(path);
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public async Task CommentsOnlyFile_IsEmpty_WithoutErrors()
    {
        var list = await LoadFile(Utf8("# header\r\n# another\n   # indented\n\t#tabbed\n#" + Abc + "\n"));

        Assert.Equal(0, list.Count);
        Assert.Empty(list.Errors);
        Assert.Equal(0, list.DuplicateCount);
        Assert.False(list.Contains(Abc));
    }

    [Fact]
    public async Task BomOnlyFile_IsEmpty_WithoutErrors()
    {
        var list = await LoadFile(Bom);

        Assert.Equal(0, list.Count);
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task BomPlusNewlineOnlyFile_IsEmpty_WithoutErrors()
    {
        var list = await LoadFile([.. Bom, .. Utf8("\r\n\r\n")]);

        Assert.Equal(0, list.Count);
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task BomThenComment_IsTreatedAsComment()
    {
        var list = await LoadFile([.. Bom, .. Utf8("# comment right after BOM\n" + Abc)]);

        Assert.Equal(1, list.Count);
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task BomThenHash_FirstLineHashIsLoaded()
    {
        var list = await LoadFile([.. Bom, .. Utf8(Abc + "\r\n")]);

        Assert.True(list.Contains(Abc));
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task CrlfAndLfFiles_LoadIdentically()
    {
        var lf = await LoadFile(Utf8($"# c\n{Abc}\nbad\n{Hello}\n"), "lf.txt");
        var crlf = await LoadFile(Utf8($"# c\r\n{Abc}\r\nbad\r\n{Hello}\r\n"), "crlf.txt");

        foreach (var list in new[] { lf, crlf })
        {
            Assert.Equal(2, list.Count);
            Assert.True(list.Contains(Abc));
            Assert.True(list.Contains(Hello));
            Assert.Equal([3], list.Errors.Select(e => e.LineNumber));
        }
    }

    [Fact]
    public async Task MixedLineEndingsInOneFile_KeepLineNumbers()
    {
        var list = await LoadFile(Utf8($"{Abc}\r\nbad\n{Hello}\rworse\r\n"));

        Assert.Equal(2, list.Count);
        Assert.Equal([2, 4], list.Errors.Select(e => e.LineNumber));
    }

    [Fact]
    public async Task NoTrailingNewline_LastLineIsLoaded()
    {
        var list = await LoadFile(Utf8($"{Abc}\r\n{Hello}"));

        Assert.Equal(2, list.Count);
    }

    [Theory]
    [InlineData("\t{0}\t")]
    [InlineData("\t\t{0}")]
    [InlineData("{0}\t\t")]
    [InlineData(" \t {0} \t ")]
    [InlineData("\t{0}\t\r")] // tab before a CR of a CRLF ending
    public async Task HashWithSurroundingTabs_InFile_IsLoaded(string format)
    {
        var list = await LoadFile(Utf8(string.Format(format, Abc) + "\n"));

        Assert.True(list.Contains(Abc));
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task TabInsideHash_IsMalformed()
    {
        var list = await LoadFile(Utf8(Abc[..32] + "\t" + Abc[32..] + "\n"));

        Assert.Equal(0, list.Count);
        Assert.Equal([1], list.Errors.Select(e => e.LineNumber));
    }

    [Fact]
    public async Task UppercaseFileEntry_MatchesLowerUpperAndMixedLookups()
    {
        var list = await LoadFile(Utf8(Abc.ToUpperInvariant() + "\n"));
        var mixed = string.Concat(Abc.Select((c, i) => i % 2 == 0 ? char.ToUpperInvariant(c) : c));

        Assert.True(list.Contains(Abc));
        Assert.True(list.Contains(Abc.ToUpperInvariant()));
        Assert.True(list.Contains(mixed));
        Assert.True(list.TryMatch(mixed, out var detection));
        Assert.Contains(Abc, detection.Reason); // reason uses the normalized lowercase form
    }
}
