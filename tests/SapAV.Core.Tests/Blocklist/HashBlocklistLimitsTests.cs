using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Blocklist;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Blocklist;

/// <summary>Size cap, error cap, line-length cap, chunk-boundary line endings and the content fingerprint.</summary>
public sealed class HashBlocklistLimitsTests : IDisposable
{
    private const string Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string Hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static Task<HashBlocklist> Parse(string text) => HashBlocklist.LoadAsync(new StringReader(text));

    // --- Size cap ---

    [Fact]
    public void DefaultMaxSize_Is64MiB()
    {
        Assert.Equal(64L * 1024 * 1024, HashBlocklist.DefaultMaxSizeBytes);
    }

    [Fact]
    public async Task FileOverMaxSize_Throws_ClearException()
    {
        var path = _dir.File("big.txt");
        await File.WriteAllTextAsync(path, Abc + "\n" + Hello + "\n"); // 130 bytes

        var ex = await Assert.ThrowsAsync<InvalidDataException>(
            () => HashBlocklist.LoadAsync(path, maxSizeBytes: 100));
        Assert.Contains("100", ex.Message);
    }

    [Fact]
    public async Task FileAtMaxSize_Loads()
    {
        var path = _dir.File("exact.txt");
        await File.WriteAllTextAsync(path, Abc + "\n"); // 65 bytes

        var list = await HashBlocklist.LoadAsync(path, maxSizeBytes: 65);

        Assert.True(list.Contains(Abc));
    }

    [Fact]
    public async Task SeekableStreamOverMaxSize_Throws_WithoutReading()
    {
        var stream = new ScriptedStream(Encoding.ASCII.GetBytes(Abc + "\n" + Hello));

        await Assert.ThrowsAsync<InvalidDataException>(() => HashBlocklist.LoadAsync(stream, maxSizeBytes: 100));
        Assert.Equal(0, stream.ReadCount);
    }

    [Fact]
    public async Task NonSeekableStreamOverMaxSize_Throws_WhileReading()
    {
        var stream = new ScriptedStream(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(Abc + "\n", 1000))))
        {
            Seekable = false,
        };

        await Assert.ThrowsAsync<InvalidDataException>(() => HashBlocklist.LoadAsync(stream, maxSizeBytes: 1000));
        Assert.True(stream.TotalBytesRead < 65_000, "should stop soon after the limit");
    }

    [Fact]
    public async Task StreamGrowingPastReportedLength_Throws()
    {
        // Reported length is small (as for a file that grows after opening), real content is not.
        var stream = new ScriptedStream(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(Abc + "\n", 100))))
        {
            ReportedLength = 10,
        };

        await Assert.ThrowsAsync<InvalidDataException>(() => HashBlocklist.LoadAsync(stream, maxSizeBytes: 1000));
    }

    [Fact]
    public async Task TextReaderOverMaxSize_Throws()
    {
        await Assert.ThrowsAsync<InvalidDataException>(
            () => HashBlocklist.LoadAsync(new StringReader(Abc + "\n" + Hello), maxSizeBytes: 100));
    }

    [Fact]
    public async Task NegativeMaxSize_IsRejected()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => HashBlocklist.LoadAsync(new StringReader(""), maxSizeBytes: -1));
    }

    // --- Error cap ---

    [Fact]
    public async Task ManyMalformedLines_KeepsFirst100_AndCountsAll()
    {
        var lines = Enumerable.Range(0, 250).Select(i => "bad" + i).Append(Abc);

        var list = await Parse(string.Join("\n", lines));

        Assert.Equal(HashBlocklist.MaxReportedErrors, list.Errors.Count);
        Assert.Equal(100, list.Errors.Count);
        Assert.Equal(250, list.TotalErrorCount);
        Assert.Equal(Enumerable.Range(1, 100), list.Errors.Select(e => e.LineNumber));
        Assert.True(list.Contains(Abc)); // loading continued past the error cap
    }

    [Fact]
    public async Task FewMalformedLines_TotalMatchesErrors()
    {
        var list = await Parse(string.Join("\n", "bad", Abc, "worse"));

        Assert.Equal(2, list.TotalErrorCount);
        Assert.Equal(2, list.Errors.Count);
    }

    // --- Line length cap ---

    [Fact]
    public async Task OverlongLine_IsReportedMalformed_AndNextLinesLoad()
    {
        var huge = new string('a', 5_000_000); // would be a 10 MB string if read whole

        var list = await Parse(Empty + "\n" + huge + "\n" + Abc + "\n");

        Assert.Equal(2, list.Count);
        Assert.True(list.Contains(Abc));
        var error = Assert.Single(list.Errors);
        Assert.Equal(2, error.LineNumber);
        Assert.Contains(HashBlocklist.MaxLineLength.ToString(), error.Reason);
    }

    [Theory]
    [InlineData(1024, false)] // exactly at the cap: judged on content (64 hex chars? no) -> length error, not "too long"
    [InlineData(1025, true)]
    public async Task LineLengthCap_Boundary(int length, bool tooLong)
    {
        var list = await Parse(new string('a', length));

        var error = Assert.Single(list.Errors);
        Assert.Equal(tooLong, error.Reason.Contains("longer than"));
    }

    [Fact]
    public async Task HashPaddedWithWhitespace_UpToTheCap_StillLoads()
    {
        var padded = new string(' ', 480) + Abc + new string(' ', 480); // 1024 chars

        var list = await Parse(padded);

        Assert.True(list.Contains(Abc));
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task OverlongCommentLine_IsStillAComment()
    {
        var list = await Parse("#" + new string('x', 100_000) + "\n" + Abc);

        Assert.Empty(list.Errors);
        Assert.True(list.Contains(Abc));
    }

    [Fact]
    public async Task OverlongWhitespaceLine_IsMalformed()
    {
        var list = await Parse(new string(' ', 2000) + "\n" + Abc);

        Assert.Equal([1], list.Errors.Select(e => e.LineNumber));
    }

    // --- Line endings split across read chunks ---

    [Theory]
    [InlineData(4095)] // CR is the last char of the first 4096-char chunk, LF the first of the next
    [InlineData(4094)]
    [InlineData(4096)]
    public async Task CrLfSplitAcrossChunks_CountsAsOneLineEnd(int firstLineLength)
    {
        var text = "#" + new string('x', firstLineLength - 1) + "\r\nbad\r\n" + Abc;

        var list = await Parse(text);

        Assert.Equal([2], list.Errors.Select(e => e.LineNumber));
        Assert.True(list.Contains(Abc));
    }

    [Fact]
    public async Task LoneCrAtEndOfInput_EndsLastLine()
    {
        var list = await Parse(Abc + "\r");

        Assert.True(list.Contains(Abc));
        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task BlankLinesBetweenCrs_CountLineNumbers()
    {
        var list = await Parse("\r\r\nbad\n\rworse");

        // lines: 1 "", 2 "", 3 "bad", 4 "", 5 "worse"
        Assert.Equal([3, 5], list.Errors.Select(e => e.LineNumber));
    }

    // --- Fingerprint ---

    [Fact]
    public async Task Fingerprint_DependsOnlyOnTheSetOfHashes()
    {
        var a = await Parse($"# list A\n{Abc}\n{Hello}\n");
        var b = await Parse($"{Hello.ToUpperInvariant()}\r\n\r\n# other comment\r\n  {Abc}  \r\n{Abc}\r\nbad line\r\n");

        Assert.Equal(a.Fingerprint, b.Fingerprint);
        Assert.Matches("^[0-9a-f]{64}$", a.Fingerprint);
    }

    [Fact]
    public async Task Fingerprint_ChangesWhenTheSetChanges()
    {
        var one = await Parse(Abc);
        var two = await Parse(Abc + "\n" + Hello);
        var other = await Parse(Hello);

        Assert.NotEqual(one.Fingerprint, two.Fingerprint);
        Assert.NotEqual(one.Fingerprint, other.Fingerprint);
        Assert.NotEqual(two.Fingerprint, other.Fingerprint);
    }

    [Fact]
    public async Task Fingerprint_IsSha256OfSortedHashesWithNewlines()
    {
        var list = await Parse(Hello + "\n" + Abc);

        var expected = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(Hello + "\n" + Abc + "\n")));
        // "2cf2..." sorts before "ba78...", so Hello comes first.
        Assert.Equal(expected, list.Fingerprint);
    }

    [Fact]
    public async Task EmptyFingerprint_IsShaOfNothing_AndMatchesEmptyInstance()
    {
        var parsedEmpty = await Parse("# nothing here\n");

        Assert.Equal(Empty, HashBlocklist.Empty.Fingerprint);
        Assert.Equal(HashBlocklist.Empty.Fingerprint, parsedEmpty.Fingerprint);
    }
}
