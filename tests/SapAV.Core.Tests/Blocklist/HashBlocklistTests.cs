using System.Text;
using SapAV.Core.Blocklist;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Blocklist;

public sealed class HashBlocklistTests : IDisposable
{
    // Benign known hashes: SHA-256 of "", "abc" and "hello".
    private const string Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string Hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    // U+FEFF, written as a char code so no invisible character sits in the source.
    private static readonly string Bom = ((char)0xFEFF).ToString();

    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static Task<HashBlocklist> Parse(string text) => HashBlocklist.LoadAsync(new StringReader(text));

    [Fact]
    public async Task Parses_CommentsBlanksWhitespaceAndMixedCase()
    {
        var text = string.Join("\r\n",
            "# SHA-256 blocklist",          // 1 comment
            "",                             // 2 blank
            "   ",                          // 3 whitespace only
            Empty,                          // 4
            "  " + Abc.ToUpperInvariant(),  // 5 leading spaces, uppercase
            "\t" + "2CF24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 \t", // 6 tabs, mixed case
            "   # indented comment",        // 7
            "#" + Abc);                     // 8 commented-out hash

        var list = await Parse(text);

        Assert.Equal(3, list.Count);
        Assert.Empty(list.Errors);
        Assert.Equal(0, list.DuplicateCount);
        Assert.True(list.Contains(Empty));
        Assert.True(list.Contains(Abc));
        Assert.True(list.Contains(Hello));
    }

    [Fact]
    public async Task MalformedLines_AreSkippedAndReportedWithLineNumbers_RestStillLoads()
    {
        var text = string.Join("\n",
            Empty,                                  // 1 ok
            Abc[..63],                              // 2 too short
            Abc + "0",                              // 3 too long
            "g" + Abc[1..],                         // 4 non-hex
            Abc + " # trailing comment",            // 5 trailing text
            Empty + " " + Abc,                      // 6 two hashes on a line
            "0x" + Abc[2..],                        // 7 0x prefix (64 chars, non-hex 'x')
            "not a hash at all",                    // 8
            Hello);                                 // 9 ok, after the bad lines

        var list = await Parse(text);

        Assert.Equal(2, list.Count);
        Assert.True(list.Contains(Empty));
        Assert.True(list.Contains(Hello));
        Assert.False(list.Contains(Abc));
        Assert.Equal([2, 3, 4, 5, 6, 7, 8], list.Errors.Select(e => e.LineNumber));
        Assert.Contains("63", list.Errors[0].Reason);
        Assert.Contains("65", list.Errors[1].Reason);
        Assert.Contains("hexadecimal", list.Errors[2].Reason);
        Assert.All(list.Errors, e => Assert.DoesNotContain(Abc[10..40], e.Reason)); // content not echoed
    }

    [Fact]
    public async Task Duplicates_AreCounted_IncludingCaseDifferences()
    {
        var text = string.Join("\n", Abc, Abc.ToUpperInvariant(), "  " + Abc, Empty, Empty);

        var list = await Parse(text);

        Assert.Equal(2, list.Count);
        Assert.Equal(3, list.DuplicateCount);
        Assert.Empty(list.Errors);
    }

    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\r")]
    public async Task LineNumbers_WorkForAnyLineEnding(string newline)
    {
        var list = await Parse(string.Join(newline, Empty, "bad", Abc, "also bad"));

        Assert.Equal(2, list.Count);
        Assert.Equal([2, 4], list.Errors.Select(e => e.LineNumber));
    }

    [Fact]
    public async Task EmptyInput_GivesEmptyList()
    {
        var list = await Parse("");

        Assert.Equal(0, list.Count);
        Assert.Empty(list.Errors);
        Assert.False(list.Contains(Empty));
    }

    [Fact]
    public async Task LeadingBom_IsIgnored_FromTextReaderAndStream()
    {
        var fromReader = await Parse(Bom + Abc + "\n");
        Assert.True(fromReader.Contains(Abc));
        Assert.Empty(fromReader.Errors);

        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("# c\r\n" + Abc)).ToArray();
        var fromStream = await HashBlocklist.LoadAsync(new MemoryStream(bytes));
        Assert.True(fromStream.Contains(Abc));
        Assert.Empty(fromStream.Errors);

        var bomOnSecondLine = await Parse(Empty + "\n" + Bom + Abc);
        Assert.Equal([2], bomOnSecondLine.Errors.Select(e => e.LineNumber)); // only a leading BOM is stripped
    }

    [Fact]
    public async Task LoadFromStream_LeavesStreamOpen()
    {
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(Abc));

        await HashBlocklist.LoadAsync(stream);

        Assert.True(stream.CanRead);
    }

    // --- Lookup ---

    [Fact]
    public async Task Contains_IsCaseInsensitive_AndNeverThrowsOnBadInput()
    {
        var list = await Parse(Abc);

        Assert.True(list.Contains(Abc.ToUpperInvariant()));
        Assert.False(list.Contains(Hello));
        Assert.False(list.Contains(null));
        Assert.False(list.Contains(""));
        Assert.False(list.Contains("garbage"));
        Assert.False(list.Contains(" " + Abc)); // lookup input is not trimmed
    }

    [Fact]
    public async Task TryMatch_Hit_GivesMaliciousBlocklistDetection_WithFallbackMitreId()
    {
        var list = await Parse(Abc);

        Assert.True(list.TryMatch(Abc.ToUpperInvariant(), out var detection));
        Assert.Equal(Verdict.Malicious, detection.Verdict);
        Assert.Equal(DetectionSource.Blocklist, detection.Source);
        Assert.Equal(MitreTechniqueIds.MaliciousFile, detection.TechniqueId);
        Assert.Equal("T1204.002", detection.TechniqueId);
        Assert.Empty(detection.SecondaryTechniqueIds);
        Assert.Contains(Abc, detection.Reason);
    }

    [Theory]
    [InlineData(Hello)]
    [InlineData(null)]
    [InlineData("nope")]
    public async Task TryMatch_Miss_GivesNoDetection(string? sha256)
    {
        var list = await Parse(Abc);

        Assert.False(list.TryMatch(sha256, out var detection));
        Assert.Null(detection);
    }

    [Fact]
    public void EmptyInstance_MatchesNothing()
    {
        Assert.Equal(0, HashBlocklist.Empty.Count);
        Assert.False(HashBlocklist.Empty.Contains(Abc));
        Assert.Empty(HashBlocklist.Empty.Errors);
    }

    [Fact]
    public async Task LargeList_LoadsAndLooksUp()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 50_000; i++)
        {
            sb.Append(i.ToString("x64")).Append('\n');
        }

        var list = await Parse(sb.ToString());

        Assert.Equal(50_000, list.Count);
        Assert.True(list.Contains(49_999.ToString("x64")));
        Assert.False(list.Contains(50_000.ToString("x64")));
    }

    [Fact]
    public async Task ConcurrentLookups_AreSafe()
    {
        var list = await Parse(string.Join("\n", Empty, Abc));

        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(i =>
            Task.Run(() => Enumerable.Range(0, 1000).All(_ => list.Contains(i % 2 == 0 ? Abc : Empty) && !list.Contains(Hello)))));

        Assert.All(results, Assert.True);
    }

    // --- Files ---

    [Fact]
    public async Task LoadFromFile_Works_WhileAnotherProcessHasItOpenForWriting()
    {
        var path = _dir.File("blocklist.txt");
        await File.WriteAllTextAsync(path, "# test\n" + Abc + "\n");
        await using var writer = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);

        var list = await HashBlocklist.LoadAsync(path);

        Assert.True(list.Contains(Abc));
    }

    [Fact]
    public async Task LoadFromMissingFile_Throws()
    {
        await Assert.ThrowsAsync<FileNotFoundException>(() => HashBlocklist.LoadAsync(_dir.File("missing.txt")));
    }

    [Fact]
    public async Task RepositoryBlocklistFile_LoadsWithoutErrors()
    {
        var path = Path.Combine(FindRepoRoot(), "data", "hashes", "blocklist.txt");

        var list = await HashBlocklist.LoadAsync(path);

        Assert.Empty(list.Errors);
    }

    [Fact]
    public async Task Reload_BuildsNewInstance_OldInstanceUnchanged()
    {
        var path = _dir.File("blocklist.txt");
        await File.WriteAllTextAsync(path, Abc);
        var first = await HashBlocklist.LoadAsync(path);

        await File.WriteAllTextAsync(path, Hello);
        var second = await HashBlocklist.LoadAsync(path);

        Assert.True(first.Contains(Abc));
        Assert.False(first.Contains(Hello));
        Assert.True(second.Contains(Hello));
        Assert.False(second.Contains(Abc));
    }

    [Fact]
    public async Task Cancellation_Throws()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => HashBlocklist.LoadAsync(new StringReader(Abc), cts.Token));
    }

    [Fact]
    public async Task RejectsNullArguments()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => HashBlocklist.LoadAsync((TextReader)null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => HashBlocklist.LoadAsync((Stream)null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => HashBlocklist.LoadAsync((string)null!));
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "SapAV.sln")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Repository root (SapAV.sln) not found.");
    }
}
