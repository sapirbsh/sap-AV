using System.Text;
using SapAV.Core.Blocklist;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Blocklist;

/// <summary>
/// The chunked line reader at the 1024/1025 line-length boundary and at chunk edges (CR as the last char
/// of a chunk), with readers that hand out text in small pieces; plus Fingerprint stability across reloads.
/// </summary>
public sealed class HashBlocklistChunkingTests : IDisposable
{
    private const string Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string Hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    private const string Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const int Chunk = 4096; // HashBlocklist's internal read chunk

    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A TextReader that returns at most <c>pieceSize</c> characters per read.</summary>
    private sealed class TrickleReader(string text, int pieceSize) : TextReader
    {
        private int _pos;

        public override int Read(char[] buffer, int index, int count) => Read(buffer.AsSpan(index, count));

        public override int Read(Span<char> buffer)
        {
            int n = Math.Min(Math.Min(pieceSize, buffer.Length), text.Length - _pos);
            text.AsSpan(_pos, n).CopyTo(buffer);
            _pos += n;
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(buffer.Span));
    }

    /// <summary>Pads a hash with spaces so the whole line is exactly <paramref name="length"/> chars.</summary>
    private static string Padded(string hash, int length)
    {
        int pad = length - hash.Length;
        return new string(' ', pad / 2) + hash + new string(' ', pad - pad / 2);
    }

    private static string Describe(HashBlocklist l) =>
        $"count={l.Count} dup={l.DuplicateCount} total={l.TotalErrorCount} fp={l.Fingerprint} errors=" +
        string.Join(";", l.Errors.Select(e => $"{e.LineNumber}:{e.Reason}"));

    /// <summary>Parses via StringReader, trickle readers of several sizes, and a UTF-8 stream; all must agree.</summary>
    private static async Task<HashBlocklist> ParseEverywhere(string text)
    {
        var reference = await HashBlocklist.LoadAsync(new StringReader(text));
        var expected = Describe(reference);

        foreach (int piece in new[] { 1, 2, 3, 63, 64, 65, 1023, 1024, 1025, Chunk - 1, Chunk + 1 })
        {
            var viaTrickle = await HashBlocklist.LoadAsync(new TrickleReader(text, piece));
            Assert.True(expected == Describe(viaTrickle), $"piece size {piece}: {Describe(viaTrickle)} != {expected}");
        }

        var viaStream = await HashBlocklist.LoadAsync(new MemoryStream(Encoding.UTF8.GetBytes(text)));
        Assert.Equal(expected, Describe(viaStream));
        return reference;
    }

    // --- 1024 / 1025 ---

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\r")]
    [InlineData("")] // last line, no newline
    public async Task PaddedHash_Exactly1024Chars_Loads(string ending)
    {
        var line = Padded(Abc, 1024);
        Assert.Equal(1024, line.Length);

        var list = await ParseEverywhere(line + ending);

        Assert.True(list.Contains(Abc));
        Assert.Equal(0, list.TotalErrorCount);
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\r")]
    [InlineData("")]
    public async Task PaddedHash_1025Chars_IsTooLong_AndNextLineStillLoads(string ending)
    {
        var line = Padded(Abc, 1025);

        // "" = the next line is the last line without a newline (lines still need a separator).
        var list = await ParseEverywhere(ending == ""
            ? line + "\n" + Hello
            : line + ending + Hello + ending);

        Assert.False(list.Contains(Abc));
        Assert.True(list.Contains(Hello));
        var error = Assert.Single(list.Errors);
        Assert.Equal(1, error.LineNumber);
        Assert.Contains("longer than", error.Reason);
    }

    [Fact]
    public async Task Line1024_StraddlingAChunkBoundary_Loads()
    {
        // First line puts the 1024-char line across the 4096 boundary.
        var first = "#" + new string('x', Chunk - 501);       // 3596 chars + "\n"; line 2 spans 3597..4620
        var text = first + "\n" + Padded(Abc, 1024) + "\n" + Padded(Hello, 1025) + "\n" + Empty;

        var list = await ParseEverywhere(text);

        Assert.True(list.Contains(Abc));
        Assert.False(list.Contains(Hello));
        Assert.True(list.Contains(Empty));
        Assert.Equal([3], list.Errors.Select(e => e.LineNumber));
    }

    [Fact]
    public async Task Line1025_WhereThe1025thCharIsAtTheChunkEdge_IsTooLong()
    {
        // Line 2 starts at offset 4096 - 1024 so its 1025th char is the first char of the second chunk.
        var first = "#" + new string('x', Chunk - 1024 - 2);  // + "\n" -> line 2 starts at 3072
        var text = first + "\n" + new string('a', 1025) + "\n" + Abc;

        var list = await ParseEverywhere(text);

        Assert.True(list.Contains(Abc));
        var error = Assert.Single(list.Errors);
        Assert.Equal(2, error.LineNumber);
        Assert.Contains("longer than", error.Reason);
    }

    [Fact]
    public async Task Comment_Of1025PlusChars_IsStillAComment_AtAnyPieceSize()
    {
        var list = await ParseEverywhere("#" + new string('c', 1024) + "\r\n" + Abc);

        Assert.Equal(0, list.TotalErrorCount);
        Assert.True(list.Contains(Abc));
    }

    // --- CR as the last char of a chunk ---

    [Fact]
    public async Task LoneCr_AsLastCharOfChunk_FollowedByHash_EndsTheLine()
    {
        var first = "#" + new string('x', Chunk - 2); // 4095 chars, CR is char 4096 = last of chunk 1
        var text = first + "\r" + Abc + "\r" + Hello;

        var list = await ParseEverywhere(text);

        Assert.Equal(2, list.Count);
        Assert.Equal(0, list.TotalErrorCount);
    }

    [Fact]
    public async Task Cr_AsLastCharOfChunk_FollowedByCr_IsABlankLine()
    {
        var first = "#" + new string('x', Chunk - 2);
        var text = first + "\r\rbad\r" + Abc;

        var list = await ParseEverywhere(text);

        // lines: 1 comment, 2 blank, 3 "bad", 4 Abc
        Assert.Equal([3], list.Errors.Select(e => e.LineNumber));
        Assert.True(list.Contains(Abc));
    }

    [Fact]
    public async Task Cr_AsLastCharOfChunk_FollowedByLfAndAnotherLf_CountsOneBlankLine()
    {
        var first = "#" + new string('x', Chunk - 2);
        var text = first + "\r\n\nbad\n" + Abc;

        var list = await ParseEverywhere(text);

        // lines: 1 comment, 2 blank, 3 "bad"
        Assert.Equal([3], list.Errors.Select(e => e.LineNumber));
    }

    [Fact]
    public async Task Cr_AsVeryLastCharOfInput_AtChunkEdge_EndsLastLine()
    {
        var text = new string(' ', Chunk - 65) + Abc + "\r"; // exactly 4096 chars, ends with CR
        Assert.Equal(Chunk, text.Length);

        var list = await HashBlocklist.LoadAsync(new StringReader(text));

        // Line is 4095 chars -> too long; what matters is no extra line and no crash.
        Assert.Equal([1], list.Errors.Select(e => e.LineNumber));
        Assert.Equal(1, list.TotalErrorCount);
    }

    [Fact]
    public async Task ManyMixedEndings_ParseIdentically_AtEveryPieceSize()
    {
        var sb = new StringBuilder();
        var endings = new[] { "\n", "\r\n", "\r", "\r\r\n", "\n\r" };
        for (int i = 0; i < 300; i++)
        {
            sb.Append(i % 7 == 0 ? "bad" + i : i % 3 == 0 ? "# c" : Padded(i % 2 == 0 ? Abc : Hello, 64 + (i % 1000)));
            sb.Append(endings[i % endings.Length]);
        }

        await ParseEverywhere(sb.ToString());
    }

    // --- Fingerprint across reloads ---

    [Fact]
    public async Task Fingerprint_IsStableAcrossReloads_OfTheSameFile()
    {
        var path = _dir.File("blocklist.txt");
        await File.WriteAllTextAsync(path, $"# list\n{Abc}\n{Hello}\n{Empty}\n");

        var first = await HashBlocklist.LoadAsync(path);
        var second = await HashBlocklist.LoadAsync(path);

        Assert.Equal(first.Fingerprint, second.Fingerprint);

        // Rewritten with another order, case, line endings and a BOM: same set, same fingerprint.
        await File.WriteAllTextAsync(path, $"{Empty.ToUpperInvariant()}\r\n{Hello}\r\n\r\n{Abc}\r\n{Abc}\r\n",
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        var third = await HashBlocklist.LoadAsync(path);

        Assert.Equal(first.Fingerprint, third.Fingerprint);
    }

    [Fact]
    public async Task Fingerprint_ChangesWhenOneHashChanges_AndReturnsWhenChangedBack()
    {
        var path = _dir.File("blocklist.txt");
        await File.WriteAllTextAsync(path, $"{Abc}\n{Hello}\n{Empty}\n");
        var original = await HashBlocklist.LoadAsync(path);

        // Change one hex digit of one hash: same count, different set.
        var changed = Hello[..^1] + (Hello[^1] == '4' ? '5' : '4');
        await File.WriteAllTextAsync(path, $"{Abc}\n{changed}\n{Empty}\n");
        var modified = await HashBlocklist.LoadAsync(path);

        Assert.Equal(original.Count, modified.Count);
        Assert.NotEqual(original.Fingerprint, modified.Fingerprint);

        await File.WriteAllTextAsync(path, $"{Abc}\n{Hello}\n{Empty}\n");
        var restored = await HashBlocklist.LoadAsync(path);

        Assert.Equal(original.Fingerprint, restored.Fingerprint);
    }
}
