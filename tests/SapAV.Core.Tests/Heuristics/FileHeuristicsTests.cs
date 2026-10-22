using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Heuristics;

/// <summary>
/// Heuristic rules: positive and negative cases for each, the score threshold, and that heuristics alone are
/// never Malicious. Test files live under %TEMP%, so the risky-folder rule (Temp) applies to executables here.
/// </summary>
public sealed class FileHeuristicsTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly FileHeuristics _heuristics = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>
    /// Writes and analyses a temp file. Fails loudly if the content wasn't inspected (e.g. a real antivirus blocked the
    /// open or read): otherwise only the name rules run, and a negative assertion about a content rule would pass vacuously.
    /// </summary>
    private HeuristicResult Analyze(string name, byte[] content, HeuristicContext? context = null, FileHeuristics? heuristics = null)
    {
        var result = (heuristics ?? _heuristics).Analyze(_dir.WriteFile(name, content), context ?? HeuristicContext.None);
        Assert.True(result.ContentInspected, $"{name}: content not inspected ({result.ContentError}); the content rules did not run.");
        return result;
    }

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
        var result = Analyze("invoice.pdf.exe", "not really a program"u8.ToArray());

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
        var result = Analyze("invoice\u202Efdp.exe", [1, 2, 3]);

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

    // --- Entropy / packing ---

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
        var result = Analyze("tool.exe", SyntheticPe.Build(SyntheticPe.Random(64 * 1024)),
            new HeuristicContext(SyntheticPe.Unsigned()));

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
        var result = Analyze("tool.exe", SyntheticPe.Build(new byte[64 * 1024]), new HeuristicContext(SyntheticPe.Unsigned()));

        Assert.Equal([HeuristicKind.UnsignedExecutable, HeuristicKind.RiskyFolderExecutable], Kinds(result));
        Assert.False(result.IsSuspicious);
        Assert.Null(result.Detection);
    }

    [Fact]
    public void HighEntropyOverlay_IsNotPacking()
    {
        // Like an installer: normal sections, compressed payload appended after them.
        var pe = SyntheticPe.Build(new byte[16 * 1024]);
        var result = Analyze("installer.exe", [.. pe, .. SyntheticPe.Random(256 * 1024)], UnsignedContext);

        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(result)); // control: the PE was parsed
        Assert.DoesNotContain(HeuristicKind.HighEntropyExecutable, Kinds(result));
    }

    [Fact]
    public void HighEntropyNonExecutable_HasNoFindings()
    {
        var result = Analyze("photos.zip", SyntheticPe.Random(64 * 1024));

        Assert.Empty(result.Findings);
        Assert.True(result.ContentInspected);
    }

    [Fact]
    public void TrustedSignature_CancelsWeakSignals_ButNotMasquerading()
    {
        var packedBytes = SyntheticPe.Build(SyntheticPe.Random(64 * 1024));
        var control = Analyze("tool-unsigned.exe", packedBytes, UnsignedContext);
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(control)); // control: the same bytes do trigger the content rule

        var packed = Analyze("tool.exe", packedBytes, new HeuristicContext(SyntheticPe.TrustedSignature()));
        Assert.Empty(packed.Findings);

        var masquerading = Analyze("invoice.pdf.exe", SyntheticPe.Build(new byte[8192]), new HeuristicContext(SyntheticPe.TrustedSignature()));
        Assert.Equal([HeuristicKind.DoubleExtension], Kinds(masquerading));
        Assert.True(masquerading.IsSuspicious);
    }

    [Fact]
    public void BrokenSignature_ScoresMoreThanUnsigned()
    {
        var result = Analyze("tool.exe", SyntheticPe.Build(new byte[8192]), new HeuristicContext(SyntheticPe.Tampered()));

        var finding = Assert.Single(result.Findings, f => f.Kind == HeuristicKind.BrokenSignature);
        Assert.Equal(FileHeuristics.BrokenSignatureScore, finding.Score);
        Assert.Contains("HashMismatch", finding.Reason);
    }

    [Fact]
    public void ScriptInTemp_IsRiskyFolderExecutable_ByName()
    {
        Assert.Equal([HeuristicKind.RiskyFolderExecutable], Kinds(Analyze("run.ps1", "Write-Output 1"u8.ToArray())));
        Assert.Empty(Analyze("notes.txt", "hello"u8.ToArray()).Findings);
    }

    // --- Padded oversized executables (carried over from the A2 review) ---

    [Fact]
    public void OversizedExecutable_PaddedWithZeros_IsSuspicious()
    {
        var small = new FileHeuristics(maxSizeBytes: 64 * 1024);
        var result = Analyze("big.exe", SyntheticPe.Build(SyntheticPe.Random(8192), overlayLength: 1024 * 1024), heuristics: small);

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

        var kinds = Kinds(Analyze("big.exe", pe, UnsignedContext, small));

        Assert.Contains(HeuristicKind.UnsignedExecutable, kinds); // control: the PE headers were parsed
        Assert.Equal(padded, kinds.Contains(HeuristicKind.PaddedOversizedExecutable));
    }

    [Fact]
    public void ZeroPaddedExecutable_UnderTheLimit_IsNotPaddingFinding()
    {
        var result = Analyze("ok.exe", SyntheticPe.Build(new byte[8192], overlayLength: 1024 * 1024), UnsignedContext);

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

    // --- Non-regular targets ---

    [Theory]
    [InlineData(@"\\.\NUL")]
    [InlineData("CON")]
    public void Devices_AreNotRead_AndDoNotThrow(string path)
    {
        var result = _heuristics.Analyze(path, HeuristicContext.None);

        Assert.False(result.ContentInspected);
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
        Assert.Equal([HeuristicKind.DoubleExtension], Kinds(result));
    }
}
