using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Heuristics;

/// <summary>
/// Heuristic rules: positive and negative cases for each, the score threshold, and that heuristics alone are
/// never Malicious.
/// </summary>
/// <remarks>
/// <para>
/// The PE rules are tested <b>in memory</b> (<see cref="AnalyzeInMemory"/>): the same rule code as the handle path,
/// but a real antivirus never sees a synthetic PE file, so it can't block it. The in-memory path is under a fake
/// Temp folder (<see cref="SyntheticPe.FakeTempPath"/>), so the risky-folder rule applies to executables.
/// </para>
/// <para>
/// The real handle/I/O path is covered by marker-free non-PE files in %TEMP% (<see cref="AnalyzeOnDisk"/>) and by
/// <see cref="OnDisk_SyntheticPe_PathAndHandle_MatchInMemory"/>, which is skipped (with the reason) only when a
/// real antivirus is explicitly detected blocking the synthetic PE files (<see cref="Requires.SyntheticPeOnDisk"/>).
/// </para>
/// </remarks>
public sealed class FileHeuristicsTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly FileHeuristics _heuristics = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>
    /// Writes and analyses a temp file (no PE content, so nothing for an antivirus to object to). Fails loudly if
    /// the content wasn't inspected: otherwise only the name rules run, and a negative assertion would pass vacuously.
    /// </summary>
    private HeuristicResult AnalyzeOnDisk(string name, byte[] content, HeuristicContext? context = null)
    {
        var result = _heuristics.Analyze(_dir.WriteFile(name, content), context ?? HeuristicContext.None);
        AssertInspected(name, result);
        return result;
    }

    /// <summary>Analyses <paramref name="content"/> in memory as if it were <c>%TEMP%\<paramref name="name"/></c>.</summary>
    private HeuristicResult AnalyzeInMemory(string name, byte[] content, HeuristicContext? context = null, FileHeuristics? heuristics = null)
    {
        var result = (heuristics ?? _heuristics).Analyze(content, SyntheticPe.FakeTempPath(name), context ?? HeuristicContext.None);
        AssertInspected(name, result);
        return result;
    }

    private static void AssertInspected(string name, HeuristicResult result) =>
        Assert.True(result.ContentInspected,
            $"{name}: content not inspected ({result.ContentFailureReason}: {result.ContentError}); the content rules did not run.");

    /// <summary>Unsigned context: a parsed PE then always gets <see cref="HeuristicKind.UnsignedExecutable"/> (a positive control).</summary>
    private static HeuristicContext UnsignedContext => new(SyntheticPe.Unsigned());

    private static HeuristicKind[] Kinds(HeuristicResult r) => r.Findings.Select(f => f.Kind).ToArray();

    // --- Name rules ---

    [Theory]
    [InlineData("invoice.pdf.exe", ".pdf.exe")]
    [InlineData("Holiday.JPG.scr", ".jpg.scr")]
    [InlineData("report.docx        .exe", ".docx.exe")]
    [InlineData("setup.exe", null)]
    [InlineData("archive.tar.gz", null)]
    [InlineData("tool.v2.1.exe", null)]
    [InlineData(".pdf.exe", null)]
    [InlineData("invoice.pdf", null)]
    public void DoubleExtension_IsRecognized(string name, string? expected)
    {
        Assert.Equal(expected, FileNameRules.DoubleExtension(name));
    }

    [Fact]
    public void DoubleExtension_AloneIsSuspicious_NeverMalicious()
    {
        var result = AnalyzeOnDisk("invoice.pdf.exe", "not really a program"u8.ToArray());

        Assert.Equal([HeuristicKind.DoubleExtension], Kinds(result));
        var detection = Assert.IsType<Detection>(result.Detection);
        Assert.Equal(Verdict.Suspicious, detection.Verdict);
        Assert.Equal(DetectionSource.Heuristic, detection.Source);
        Assert.Equal(MitreTechniqueIds.DoubleFileExtension, detection.TechniqueId);
        Assert.Contains(".pdf.exe", detection.Reason);
    }

    [Fact]
    public void RightToLeftOverride_IsFlagged()
    {
        var result = AnalyzeOnDisk("invoice\u202Efdp.exe", [1, 2, 3]);

        Assert.Contains(HeuristicKind.RightToLeftOverride, Kinds(result));
        Assert.True(result.IsSuspicious);
        Assert.False(FileNameRules.HasRightToLeftOverride("invoice.pdf"));
    }

    [Theory]
    [InlineData(@"C:\Users\bob\Downloads\a.exe", RiskyFolder.Downloads)]
    [InlineData(@"\\?\C:\Users\bob\Downloads\sub\a.exe", RiskyFolder.Downloads)]
    [InlineData(@"D:\Users\alice\AppData\Local\Temp\x\a.exe", RiskyFolder.Temp)]
    [InlineData(@"C:\Users\alice\AppData\Roaming\App\a.exe", RiskyFolder.AppData)]
    [InlineData(@"C:\Windows\Temp\a.exe", RiskyFolder.Temp)]
    [InlineData(@"C:\Windows\SystemTemp\a.exe", RiskyFolder.Temp)]
    [InlineData(@"C:\Program Files\App\a.exe", RiskyFolder.None)]
    [InlineData(@"C:\Users\bob\Downloads", RiskyFolder.None)]    // the folder itself, not a file in it
    [InlineData(@"C:\Users\bob\Documents\a.exe", RiskyFolder.None)]
    public void RiskyFolders_AreClassifiedBySegments(string path, RiskyFolder expected)
    {
        Assert.Equal(expected, FileNameRules.ClassifyFolder(path));
    }

    // --- Entropy / packing (in memory) ---

    [Fact]
    public void Entropy_Extremes()
    {
        Assert.Equal(0, ShannonEntropy.Of(new byte[1000]));
        Assert.Equal(8, ShannonEntropy.Of(Enumerable.Range(0, 256 * 4).Select(i => (byte)i).ToArray()), 6);
        Assert.Equal(0, ShannonEntropy.Of([]));
    }

    [Fact]
    public void PackedUnsignedExecutableInTemp_IsSuspicious_WithPackingAsPrimaryTechnique()
    {
        var result = AnalyzeInMemory("tool.exe", SyntheticPe.Build(SyntheticPe.Random(64 * 1024)), UnsignedContext);

        Assert.Equal([HeuristicKind.HighEntropyExecutable, HeuristicKind.UnsignedExecutable, HeuristicKind.RiskyFolderExecutable], Kinds(result));
        Assert.Equal(FileHeuristics.HighEntropyScore + FileHeuristics.UnsignedScore + FileHeuristics.RiskyFolderScore, result.Score);
        var detection = result.Detection!;
        Assert.Equal(Verdict.Suspicious, detection.Verdict);
        Assert.Equal(MitreTechniqueIds.SoftwarePacking, detection.TechniqueId);
        Assert.Equal([MitreTechniqueIds.MaliciousFile], detection.SecondaryTechniqueIds);
    }

    [Fact]
    public void LowEntropyExecutable_HasNoPackingFinding_AndWeakSignalsStayUnderThreshold()
    {
        var result = AnalyzeInMemory("tool.exe", SyntheticPe.Build(new byte[64 * 1024]), UnsignedContext);

        Assert.Equal([HeuristicKind.UnsignedExecutable, HeuristicKind.RiskyFolderExecutable], Kinds(result));
        Assert.False(result.IsSuspicious);
        Assert.Null(result.Detection);
    }

    [Fact]
    public void HighEntropyOverlay_IsNotPacking()
    {
        // Like an installer: normal sections, compressed payload appended after them.
        var pe = SyntheticPe.Build(new byte[16 * 1024]);
        var result = AnalyzeInMemory("installer.exe", [.. pe, .. SyntheticPe.Random(256 * 1024)], UnsignedContext);

        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(result)); // control: the PE was parsed
        Assert.DoesNotContain(HeuristicKind.HighEntropyExecutable, Kinds(result));
    }

    [Fact]
    public void HighEntropyNonExecutable_HasNoFindings()
    {
        var result = AnalyzeOnDisk("photos.zip", SyntheticPe.Random(64 * 1024));

        Assert.Empty(result.Findings);
        Assert.True(result.ContentInspected);
    }

    [Fact]
    public void TrustedSignature_CancelsWeakSignals_ButNotMasquerading()
    {
        var packedBytes = SyntheticPe.Build(SyntheticPe.Random(64 * 1024));
        var control = AnalyzeInMemory("tool-unsigned.exe", packedBytes, UnsignedContext);
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(control)); // control: the same bytes do trigger the content rule

        var packed = AnalyzeInMemory("tool.exe", packedBytes, new HeuristicContext(SyntheticPe.TrustedSignature()));
        Assert.Empty(packed.Findings);

        var masquerading = AnalyzeInMemory("invoice.pdf.exe", SyntheticPe.Build(new byte[8192]), new HeuristicContext(SyntheticPe.TrustedSignature()));
        Assert.Equal([HeuristicKind.DoubleExtension], Kinds(masquerading));
        Assert.True(masquerading.IsSuspicious);
    }

    [Fact]
    public void BrokenSignature_ScoresMoreThanUnsigned()
    {
        var result = AnalyzeInMemory("tool.exe", SyntheticPe.Build(new byte[8192]), new HeuristicContext(SyntheticPe.Tampered()));

        var finding = Assert.Single(result.Findings, f => f.Kind == HeuristicKind.BrokenSignature);
        Assert.Equal(FileHeuristics.BrokenSignatureScore, finding.Score);
        Assert.True(FileHeuristics.BrokenSignatureScore > FileHeuristics.UnsignedScore);
        Assert.Contains("HashMismatch", finding.Reason);
        Assert.DoesNotContain(HeuristicKind.UnsignedExecutable, Kinds(result));
    }

    [Fact]
    public void ScriptInTemp_IsRiskyFolderExecutable_ByName()
    {
        Assert.Equal([HeuristicKind.RiskyFolderExecutable], Kinds(AnalyzeOnDisk("run.ps1", "Write-Output 1"u8.ToArray())));
        Assert.Empty(AnalyzeOnDisk("notes.txt", "hello"u8.ToArray()).Findings);
    }

    // --- Padded oversized executables (carried over from the A2 review; in memory) ---

    [Fact]
    public void OversizedExecutable_PaddedWithZeros_IsSuspicious()
    {
        var small = new FileHeuristics(maxSizeBytes: 64 * 1024);
        var result = AnalyzeInMemory("big.exe", SyntheticPe.Build(SyntheticPe.Random(8192), overlayLength: 1024 * 1024), heuristics: small);

        var finding = Assert.Single(result.Findings, f => f.Kind == HeuristicKind.PaddedOversizedExecutable);
        Assert.Contains("padding", finding.Reason);
        Assert.Equal(MitreTechniqueIds.BinaryPadding, result.Detection!.TechniqueId);
        Assert.DoesNotContain(HeuristicKind.HighEntropyExecutable, Kinds(result)); // big files: headers and samples only
    }

    [Theory]
    [InlineData(0xFF, true)]   // any repeated byte is padding
    [InlineData(-1, false)]    // random overlay: real data
    public void OversizedExecutable_OverlayKind(int overlayByte, bool padded)
    {
        var small = new FileHeuristics(maxSizeBytes: 64 * 1024);
        var pe = overlayByte >= 0
            ? SyntheticPe.Build(new byte[8192], 1024 * 1024, (byte)overlayByte)
            : [.. SyntheticPe.Build(new byte[8192]), .. SyntheticPe.Random(1024 * 1024)];

        var kinds = Kinds(AnalyzeInMemory("big.exe", pe, UnsignedContext, small));

        Assert.Contains(HeuristicKind.UnsignedExecutable, kinds); // control: the PE headers were parsed
        Assert.Equal(padded, kinds.Contains(HeuristicKind.PaddedOversizedExecutable));
    }

    [Fact]
    public void ZeroPaddedExecutable_UnderTheLimit_IsNotPaddingFinding()
    {
        var result = AnalyzeInMemory("ok.exe", SyntheticPe.Build(new byte[8192], overlayLength: 1024 * 1024), UnsignedContext);

        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(result)); // control: the PE was parsed
        Assert.DoesNotContain(HeuristicKind.PaddedOversizedExecutable, Kinds(result));
    }

    [Fact]
    public void SyntheticPe_IsAcceptedByThePeParser()
    {
        // Self-test for the fixture every PE test relies on.
        foreach (var bytes in new[] { SyntheticPe.Build(new byte[8192]), SyntheticPe.Build(SyntheticPe.Random(4096), overlayLength: 4096) })
        {
            Assert.NotNull(PeHeaders.TryParse(bytes.AsSpan(0, Math.Min(bytes.Length, 64 * 1024)), bytes.Length));
        }
    }

    // --- In-memory path ---

    [Fact]
    public void InMemory_NeverOpensThePath()
    {
        // The path names nothing on disk: content rules still run on the bytes, name/folder rules on the path.
        var missing = _dir.File("missing.pdf.exe");
        var result = _heuristics.Analyze(SyntheticPe.Build(SyntheticPe.Random(64 * 1024)), missing, UnsignedContext);

        Assert.False(File.Exists(missing));
        AssertInspected(missing, result);
        Assert.Equal([HeuristicKind.DoubleExtension, HeuristicKind.HighEntropyExecutable, HeuristicKind.UnsignedExecutable,
            HeuristicKind.RiskyFolderExecutable], Kinds(result));
    }

    [Fact]
    public void InMemory_EmptyAndTruncatedContent_DoNotThrow()
    {
        Assert.Empty(AnalyzeInMemory("empty.exe", [], UnsignedContext).Findings);

        // Headers claim 8 KiB of section data that isn't there: parsed as a PE, nothing read out of range.
        var truncated = SyntheticPe.Build(new byte[8192])[..0x500];
        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(AnalyzeInMemory("cut.exe", truncated, UnsignedContext)));
    }

    // --- On-disk synthetic PE: the real handle/I/O path ---

    public static TheoryData<string> OnDiskPeSamples => new(SyntheticPe.OnDiskSamples.Select(s => s.Name));

    /// <summary>
    /// The path and handle overloads read a real file and must give exactly the in-memory findings, including the
    /// sample's content finding (proof the section/overlay reads went through the file). Skipped only when a real
    /// antivirus is detected blocking the samples; a block that appears after the probe still fails here.
    /// </summary>
    [RequiresTheory(Requires.SyntheticPeOnDisk)]
    [MemberData(nameof(OnDiskPeSamples))]
    public void OnDisk_SyntheticPe_PathAndHandle_MatchInMemory(string name)
    {
        var sample = SyntheticPe.OnDisk(name);
        var heuristics = sample.Heuristics();
        var path = _dir.WriteFile(name, sample.Bytes);

        var byPath = heuristics.Analyze(path, UnsignedContext);
        HeuristicResult byHandle;
        using (var handle = File.OpenHandle(path))
        {
            byHandle = heuristics.Analyze(handle, path, UnsignedContext);
        }

        var inMemory = heuristics.Analyze(sample.Bytes, path, UnsignedContext);

        AssertInspected(name + " (path)", byPath);
        AssertInspected(name + " (handle)", byHandle);
        Assert.Contains(sample.ContentFinding, Kinds(byPath));          // control: the content reads ran
        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(byPath)); // control: the PE headers were parsed
        Assert.Equal(inMemory.Findings, byPath.Findings);
        Assert.Equal(inMemory.Findings, byHandle.Findings);
    }

    // --- Non-regular targets ---

    [Theory]
    [InlineData(@"\\.\NUL")]
    [InlineData("CON")]
    public void Devices_AreNotRead_AndDoNotThrow(string path)
    {
        var result = _heuristics.Analyze(path, HeuristicContext.None);

        Assert.False(result.ContentInspected);
        Assert.Equal(HashFailureReason.NotRegularFile, result.ContentFailureReason);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task NamedPipe_IsNeverOpened()
    {
        await using var probe = new PipeProbe();

        var result = _heuristics.Analyze(probe.Path, HeuristicContext.None);

        Assert.False(result.ContentInspected);
        Assert.False(await probe.WasConnectedAsync());
    }

    [Fact]
    public void Directory_WithExecutableName_StillGetsNameRules_ButNoContent()
    {
        var dir = Directory.CreateDirectory(_dir.File("invoice.pdf.exe")).FullName;

        var result = _heuristics.Analyze(dir, HeuristicContext.None);

        Assert.False(result.ContentInspected);
        Assert.NotEqual(HashFailureReason.None, result.ContentFailureReason);
        Assert.Equal([HeuristicKind.DoubleExtension], Kinds(result));
    }

    [Fact]
    public void MissingFile_ReportsNotFound_AndAnInspectedResultHasNoReason()
    {
        var missing = _heuristics.Analyze(_dir.File("gone.exe"), HeuristicContext.None);
        Assert.False(missing.ContentInspected);
        Assert.Equal(HashFailureReason.NotFound, missing.ContentFailureReason);

        Assert.Equal(HashFailureReason.None, AnalyzeOnDisk("ok.txt", [1]).ContentFailureReason);
    }
}
