using System.Text;
using System.Text.Json;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Scanning;

/// <summary>
/// Section A cross-step checks: FileScanner wired to the REAL hasher, Authenticode verifier, YARA (shipped rules),
/// MOTW reader and heuristics. No fakes. EICAR stays in memory (no file written).
/// </summary>
public sealed class FileScannerEndToEndTests : IDisposable
{
    private const string TestYara = "rule E2E_Marker { strings: $a = \"sapav-e2e-marker\" condition: $a }";

    private readonly TempDirectory _dir = new();
    private readonly YaraRuleSet _rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);

    public void Dispose()
    {
        _rules.Dispose();
        _dir.Dispose();
    }

    private FileScanner Scanner(long maxSize = Sha256Hasher.DefaultMaxSizeBytes, HashBlocklist? blocklist = null,
        YaraScanner? yara = null)
    {
        var list = blocklist ?? HashBlocklist.Empty;
        return new FileScanner(new Sha256Hasher(maxSize), () => list, new AuthenticodeVerifier(),
            yara ?? new YaraScanner(_rules, maxSize), new MarkOfTheWebReader(), new FileHeuristics(maxSize));
    }

    private static ScanItem Item(string path) => new(path, ScanTrigger.CustomScan);

    [Fact]
    public async Task EicarInMemory_ThroughRealHasherAndShippedRules_IsMalicious()
    {
        // In-memory only: the real hasher and the real shipped YARA rule see the bytes without a file.
        var eicar = Eicar.Bytes();
        var hash = await new Sha256Hasher().HashStreamAsync(new MemoryStream(eicar));
        Assert.Equal(Eicar.KnownSha256, hash.Sha256);

        var scanner = new YaraScanner(_rules);
        var yara = scanner.ScanMemory(eicar);
        Assert.True(yara.IsScanned);
        Assert.Contains(yara.Detections, d => d.Verdict == Verdict.Malicious);
        Assert.Empty(scanner.ScanMemory("clean text"u8).Detections);
    }

    [Fact]
    public async Task CatalogSignedSystem32Binary_IsCleanMicrosoft_WithNoYaraOrHeuristics()
    {
        // Hard requirement on every Windows. If this fails on a CI image, read the chain in the message: a new
        // Microsoft issuing CA probably needs adding to MicrosoftCodeSigningCertificates (do not relax the rule).
        var path = SignedSamples.RequireCatalogOnlyWindowsBinary();

        var report = await Scanner().ScanAsync(Item(path));

        var sig = report.Signature!;
        var chain = string.Join(" <- ", sig.Signer!.Chain.Select(c => c.CommonName));
        Assert.True(report.Result.SignatureStatus == SignatureStatus.Microsoft,
            $"{path}: status {report.Result.SignatureStatus}, {sig.FailureReason}: {sig.Message}; chain: {chain}");
        Assert.Equal(Verdict.Clean, report.Result.Verdict);
        Assert.Null(report.Yara);
        Assert.Null(report.Heuristics);
        Assert.Null(report.MarkOfTheWeb);
        Assert.Empty(report.Result.Detections);
    }

    [Fact]
    public async Task ModifiedCopyOfMicrosoftBinary_IsNotMicrosoft()
    {
        // A catalog signature is bound to the file hash: appending one byte must lose the Microsoft status.
        var source = SignedSamples.RequireCatalogOnlyWindowsBinary();
        var bytes = File.ReadAllBytes(source).Concat(new byte[] { 0x90 }).ToArray();
        var copy = _dir.WriteFile("cmd.exe", bytes);

        var report = await Scanner().ScanAsync(Item(copy));

        Assert.NotEqual(SignatureStatus.Microsoft, report.Result.SignatureStatus);
        Assert.NotNull(report.Yara);
        Assert.NotNull(report.Heuristics);
    }

    [Fact]
    public async Task UnsignedDoubleExtensionExeInTemp_IsSuspicious()
    {
        var path = _dir.WriteFile("invoice.pdf.exe", Encoding.ASCII.GetBytes("not really a program"));

        var report = await Scanner().ScanAsync(Item(path));

        Assert.Equal(Verdict.Suspicious, report.Result.Verdict);
        Assert.Contains(report.Result.Detections, d => d.Source == DetectionSource.Heuristic);
        Assert.NotNull(report.Result.Sha256);
    }

    [Fact]
    public async Task OversizedFile_IsNeverClean()
    {
        var path = _dir.WriteFile("big.bin", new byte[4096]);

        var report = await Scanner(maxSize: 1024).ScanAsync(Item(path));

        Assert.Equal(ScanStatus.SkippedTooLarge, report.Result.Status);
        Assert.NotEqual(Verdict.Clean, report.Result.Verdict);
        Assert.Contains(report.Notes, n => n.Level == ScanNoteLevel.Warning);
    }

    [Fact]
    public async Task LockedFile_IsNotScanned_AndUnlockedLaterIsScanned()
    {
        var path = _dir.WriteFile("locked.txt", "hello"u8.ToArray());
        ScanResult locked;
        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            locked = (await Scanner().ScanAsync(Item(path))).Result;
        }

        Assert.Equal(ScanStatus.Locked, locked.Status);
        Assert.Null(locked.Verdict);

        var again = await Scanner().ScanAsync(Item(path));
        Assert.Equal(Verdict.Clean, again.Result.Verdict);
    }

    [Fact]
    public async Task BlocklistedHash_OfARealFile_IsMalicious_WithRealComponents()
    {
        var content = Encoding.ASCII.GetBytes("benign content that the test pretends is blocklisted");
        var path = _dir.WriteFile("listed.txt", content);
        var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content));
        var list = await HashBlocklist.LoadAsync(new StringReader(sha));

        var report = await Scanner(blocklist: list).ScanAsync(Item(path));

        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal(sha, report.Result.Sha256);
    }

    [Theory]
    [InlineData(@"\\.\pipe\sapav-e2e-no-such-pipe")]
    [InlineData(@"\\.\NUL")]
    [InlineData(@"\\.\C:")]
    [InlineData("missing-no-such-file.exe")]
    public async Task DevicePipeOrMissingPath_IsNotScanned_WithoutThrowing(string path)
    {
        if (path.StartsWith("missing", StringComparison.Ordinal))
        {
            path = _dir.File(path);
        }

        var report = await Scanner().ScanAsync(Item(path));

        Assert.NotEqual(ScanStatus.Scanned, report.Result.Status);
        Assert.Null(report.Result.Verdict);
    }

    [Fact]
    public async Task Directory_IsNotScanned()
    {
        var report = await Scanner().ScanAsync(Item(_dir.Path));

        Assert.NotEqual(ScanStatus.Scanned, report.Result.Status);
        Assert.Null(report.Result.Verdict);
    }

    [Fact]
    public async Task RealScanResult_RoundTripsThroughJson()
    {
        var path = _dir.WriteFile("report.pdf.exe", Encoding.ASCII.GetBytes("x"));
        var suspicious = (await Scanner().ScanAsync(Item(path))).Result;
        var notScanned = (await Scanner().ScanAsync(Item(_dir.File("gone.exe")))).Result;

        foreach (var result in new[] { suspicious, notScanned })
        {
            var back = JsonSerializer.Deserialize<ScanResult>(JsonSerializer.Serialize(result))!;
            Assert.Equal(result, back);
            Assert.Equal(result.Verdict, back.Verdict);
            Assert.Equal(result.Status, back.Status);
        }
    }

    [Fact]
    public async Task ParallelScans_WhileRulesAreSwapped_AllFinishCorrectly()
    {
        var marker = _dir.WriteFile("marker.txt", "xx sapav-e2e-marker xx"u8.ToArray());
        var plain = _dir.WriteFile("plain.txt", "nothing to see"u8.ToArray());
        var yara = new YaraScanner(_rules);
        var scanner = Scanner(yara: yara);
        var alt = new[] { YaraRuleSet.FromSource("e2e.yar", TestYara), YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory) };
        using var cts = new CancellationTokenSource();

        var swapper = Task.Run(() =>
        {
            int i = 0;
            while (!cts.IsCancellationRequested)
            {
                yara.SwapRules(alt[i++ % 2]);
                Thread.Sleep(1);
            }
        });

        try
        {
            var scans = Enumerable.Range(0, 60).Select(i =>
                Task.Run(() => scanner.ScanAsync(Item(i % 2 == 0 ? marker : plain)))).ToArray();
            var reports = await Task.WhenAll(scans).WaitAsync(TimeSpan.FromSeconds(60));

            for (int i = 0; i < reports.Length; i++)
            {
                var r = reports[i].Result;
                Assert.Equal(ScanStatus.Scanned, r.Status);
                // The marker file is Clean or Malicious depending on which rules were current; plain is always Clean.
                if (i % 2 == 1)
                {
                    Assert.Equal(Verdict.Clean, r.Verdict);
                }
                else
                {
                    Assert.True(r.Verdict is Verdict.Clean or Verdict.Malicious or Verdict.Suspicious, $"scan {i}: {r.Verdict}");
                }
            }
        }
        finally
        {
            cts.Cancel();
            await swapper;
            yara.SwapRules(_rules);
            foreach (var set in alt)
            {
                set.Dispose();
            }
        }
    }
}
