using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Tests.Yara;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Scanning;

/// <summary>
/// The pipeline order and its short-cuts (ROADMAP A7): blocklist beats signature, Microsoft-signed skips YARA and
/// heuristics, other trusted signed still gets YARA + heuristics but no online lookup, EICAR is Malicious, and a
/// file that can't be hashed is NotScanned (never Clean).
/// </summary>
public sealed class FileScannerTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);
    private const string Sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private readonly TempDirectory _dir = new();
    private readonly FakeHasher _hasher = new() { Next = HashResult.Hashed(Sha, 10) };
    private readonly FakeVerifier _verifier = new() { Next = SignatureCheckResult.NotSigned() };
    private readonly FakeYara _yara = new();
    private readonly FakeMotw _motw = new();
    private readonly FakeHeuristics _heuristics = new();
    private readonly FakeOnline _online = new();
    private HashBlocklist _blocklist = HashBlocklist.Empty;

    public void Dispose() => _dir.Dispose();

    private FileScanner Scanner(IOnlineHashLookup? online = null) =>
        new(_hasher, () => _blocklist, _verifier, _yara, _motw, _heuristics, online ?? _online, new FixedTime(Now));

    private static ScanItem Item(string path = @"C:\scan\file.exe") => new(path, ScanTrigger.CustomScan);

    private static async Task<HashBlocklist> BlocklistOf(string sha256) =>
        await HashBlocklist.LoadAsync(new StringReader(sha256));

    private static Detection YaraDetection(Verdict verdict = Verdict.Malicious) =>
        new(verdict, "YARA rule X matched (x.yar)", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara);

    // --- Hash failures: NotScanned, never Clean ---

    [Theory]
    [InlineData(HashFailureReason.Locked, ScanStatus.Locked)]
    [InlineData(HashFailureReason.AccessDenied, ScanStatus.AccessDenied)]
    [InlineData(HashFailureReason.NotRegularFile, ScanStatus.Error)]
    public async Task HashFailure_IsNotScanned_AndNothingElseRuns(HashFailureReason reason, ScanStatus status)
    {
        _hasher.Next = HashResult.NotHashed(reason, "nope");

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(status, report.Result.Status);
        Assert.Null(report.Result.Verdict);
        Assert.Equal(0, _verifier.Calls + _yara.Calls + _heuristics.Calls + _motw.Calls + _online.Calls);
        Assert.Contains(report.Notes, n => n.Level == ScanNoteLevel.Warning && n.Message.Contains(reason.ToString()));
    }

    [Fact]
    public async Task TooLarge_IsSkippedTooLarge_WithAClearNote_AndOnlyHeuristicsRun()
    {
        _hasher.Next = HashResult.NotHashed(HashFailureReason.TooLarge, length: 300_000_000);

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(ScanStatus.SkippedTooLarge, report.Result.Status);
        Assert.Null(report.Result.Verdict);
        var note = Assert.Single(report.Notes);
        Assert.Equal(ScanNoteLevel.Warning, note.Level);
        Assert.Contains("Skipped (too large)", note.Message);
        Assert.Contains("300000000", note.Message);
        Assert.Contains(_hasher.MaxSizeBytes.ToString(), note.Message);
        Assert.Equal(1, _heuristics.Calls);
        Assert.Equal(0, _verifier.Calls + _yara.Calls);
    }

    [Fact]
    public async Task TooLarge_ButPadded_IsSuspicious_WithoutHash()
    {
        _hasher.Next = HashResult.NotHashed(HashFailureReason.TooLarge, length: 300_000_000);
        _heuristics.Next = Suspicious(HeuristicKind.PaddedOversizedExecutable, MitreTechniqueIds.BinaryPadding);

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(ScanStatus.Scanned, report.Result.Status);
        Assert.Equal(Verdict.Suspicious, report.Result.Verdict);
        Assert.Null(report.Result.Sha256);
    }

    [Fact]
    public async Task Offline_IsSkippedOffline_WithAClearNote()
    {
        _hasher.Next = HashResult.NotHashed(HashFailureReason.Offline);

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(ScanStatus.SkippedOffline, report.Result.Status);
        Assert.Contains("Skipped (offline)", Assert.Single(report.Notes).Message);
        Assert.Equal(0, _verifier.Calls + _yara.Calls + _heuristics.Calls);
    }

    // --- Blocklist and signatures ---

    [Fact]
    public async Task BlocklistHit_BeatsAMicrosoftSignature()
    {
        _blocklist = await BlocklistOf(Sha);
        _verifier.Next = SignatureCheckResult.Trusted(SignatureStatus.Microsoft, SignatureKind.Catalog, SyntheticPe.TrustedSignature().Signer!);

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal(DetectionSource.Blocklist, Assert.Single(report.Result.Detections).Source);
        Assert.Equal(SignatureStatus.Microsoft, report.Result.SignatureStatus);
        Assert.Equal("Contoso", report.Result.Signer);
        Assert.Equal(0, _yara.Calls + _heuristics.Calls + _online.Calls);
    }

    [Fact]
    public async Task MicrosoftSigned_IsClean_AndSkipsYaraHeuristicsAndOnline()
    {
        _verifier.Next = SignatureCheckResult.Trusted(SignatureStatus.Microsoft, SignatureKind.Catalog, SyntheticPe.TrustedSignature().Signer!);
        _yara.Next = YaraScanResult.NotScanned(YaraFailureReason.EngineError); // would matter if it ran

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(Verdict.Clean, report.Result.Verdict);
        Assert.Equal(SignatureStatus.Microsoft, report.Result.SignatureStatus);
        Assert.Equal(Sha, report.Result.Sha256);
        Assert.Equal(0, _yara.Calls + _heuristics.Calls + _motw.Calls + _online.Calls);
    }

    [Fact]
    public async Task OtherTrusted_GetsYaraAndHeuristics_ButNoOnlineLookup()
    {
        _verifier.Next = SyntheticPe.TrustedSignature();
        _yara.Detection = YaraDetection();

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal(SignatureStatus.OtherTrusted, report.Result.SignatureStatus);
        Assert.Equal("Contoso", report.Result.Signer);
        Assert.Equal(1, _yara.Calls);
        Assert.Equal(1, _heuristics.Calls);
        Assert.True(_heuristics.LastContext!.IsTrustedSigned);
        Assert.Equal(0, _online.Calls);
    }

    [Fact]
    public async Task Unsigned_RunsEveryStep_InOrder_AndMergesAllDetections()
    {
        _yara.Detection = YaraDetection(Verdict.Suspicious);
        _heuristics.Next = Suspicious(HeuristicKind.DoubleExtension, MitreTechniqueIds.DoubleFileExtension);
        _online.Next = new Detection(Verdict.Malicious, "VirusTotal: 40/70", MitreTechniqueIds.MaliciousFile, DetectionSource.VirusTotal);
        var mark = MarkOfTheWeb.Parse("[ZoneTransfer]\nZoneId=3\nHostUrl=https://dl.test/x.exe\n"u8);
        _motw.Next = MarkOfTheWebResult.Present(mark);

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal([DetectionSource.Yara, DetectionSource.Heuristic, DetectionSource.VirusTotal], report.Result.Detections.Select(d => d.Source));
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, report.Result.SignatureStatus);
        Assert.Null(report.Result.Signer);
        Assert.Same(mark, _heuristics.LastContext!.MarkOfTheWeb);
        Assert.Equal("https://dl.test/x.exe", report.SourceUrl);
        Assert.Equal(Verdict.Suspicious, _online.LastRequest!.LocalVerdict);
        Assert.Equal(Sha, _online.LastRequest.Sha256);
        Assert.Equal(Now, report.Result.Timestamp);
    }

    [Fact]
    public async Task NoFindings_IsClean_WithHashAndSignatureStatus()
    {
        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(Verdict.Clean, report.Result.Verdict);
        Assert.Equal(Sha, report.Result.Sha256);
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, report.Result.SignatureStatus);
        Assert.Empty(report.Notes);
    }

    // --- YARA failures ---

    [Fact]
    public async Task YaraFailure_WithNoOtherFinding_IsNotScanned_NeverClean()
    {
        _yara.Next = YaraScanResult.NotScanned(YaraFailureReason.Timeout, "timed out");

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Null(report.Result.Verdict);
        Assert.Contains(report.Notes, n => n.Message.Contains("Timeout"));
    }

    [Fact]
    public async Task YaraFailure_WithAHeuristicFinding_KeepsTheFinding()
    {
        _yara.Next = YaraScanResult.NotScanned(YaraFailureReason.Timeout, "timed out");
        _heuristics.Next = Suspicious(HeuristicKind.DoubleExtension, MitreTechniqueIds.DoubleFileExtension);

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(Verdict.Suspicious, report.Result.Verdict);
        Assert.Contains(report.Notes, n => n.Message.Contains("Timeout"));
    }

    [Fact]
    public async Task FileChangedBetweenHashAndYara_IsNotScanned()
    {
        _yara.ScannedLength = 999; // the hasher saw 10 bytes

        var report = await Scanner().ScanAsync(Item());

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Contains(report.Notes, n => n.Message.Contains("changed between hashing"));
    }

    [Fact]
    public async Task BlocklistReload_IsPickedUpByTheNextScan()
    {
        var scanner = Scanner();
        Assert.Equal(Verdict.Clean, (await scanner.ScanAsync(Item())).Result.Verdict);

        _blocklist = await BlocklistOf(Sha);

        Assert.Equal(Verdict.Malicious, (await scanner.ScanAsync(Item())).Result.Verdict);
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Scanner().ScanAsync(Item(), cts.Token));
    }

    // --- EICAR and real components ---

    [Fact]
    public async Task Eicar_IsMalicious_ByBlocklistHash_AndByTheShippedYaraRule()
    {
        // The EICAR bytes stay in memory: the hasher and YARA adapters hash/scan them instead of a file.
        var eicar = Eicar.Bytes();
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        var yara = new InMemoryYara(new YaraScanner(rules), eicar);
        var hasher = new FakeHasher { Next = await new Sha256Hasher().HashStreamAsync(new MemoryStream(eicar)) };
        _verifier.Next = SignatureCheckResult.NotSigned();

        var eicarBlocklist = await BlocklistOf(Eicar.KnownSha256);
        var withBlocklist = new FileScanner(hasher, () => eicarBlocklist, _verifier, yara, _motw, _heuristics);
        var report = await withBlocklist.ScanAsync(Item(@"C:\scan\eicar.com"));
        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal(Eicar.KnownSha256, report.Result.Sha256);

        var yaraOnly = new FileScanner(hasher, () => HashBlocklist.Empty, _verifier, yara, _motw, _heuristics);
        var viaYara = await yaraOnly.ScanAsync(Item(@"C:\scan\eicar.com"));
        Assert.Equal(Verdict.Malicious, viaYara.Result.Verdict);
        Assert.Contains("EICAR_Test_File", Assert.Single(viaYara.Result.Detections).Reason);
    }

    [Fact]
    public async Task RealComponents_CleanTextFile_IsClean()
    {
        var path = _dir.WriteFile("notes.txt", Encoding.ASCII.GetBytes("just some notes"));
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        var scanner = new FileScanner(new Sha256Hasher(), () => HashBlocklist.Empty, new AuthenticodeVerifier(),
            new YaraScanner(rules), new MarkOfTheWebReader(), new FileHeuristics());

        var report = await scanner.ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.Equal(Verdict.Clean, report.Result.Verdict);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))), report.Result.Sha256);
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, report.Result.SignatureStatus);
        Assert.True(report.Yara!.IsScanned);
        Assert.Equal(MarkOfTheWebStatus.Absent, report.MarkOfTheWeb!.Status);
    }

    [RequiresFact(Requires.EicarFileOnDisk)]
    public async Task RealComponents_EicarFileInTemp_IsMalicious()
    {
        var path = _dir.WriteFile("eicar.com", Eicar.Bytes());
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        var scanner = new FileScanner(new Sha256Hasher(), () => HashBlocklist.Empty, new AuthenticodeVerifier(),
            new YaraScanner(rules), new MarkOfTheWebReader(), new FileHeuristics());

        var report = await scanner.ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
        Assert.Equal(Eicar.KnownSha256, report.Result.Sha256);
    }

    // --- Fakes ---

    private static HeuristicResult Suspicious(HeuristicKind kind, string technique) =>
        new([new HeuristicFinding(kind, 100, kind.ToString(), technique)], FileHeuristics.DefaultThreshold, contentInspected: true, null);

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FakeHasher : IFileHasher
    {
        public HashResult Next { get; set; } = null!;
        public long MaxSizeBytes => Sha256Hasher.DefaultMaxSizeBytes;
        public Task<HashResult> HashFileAsync(string path, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Next);
        }

        public Task<HashResult> HashStreamAsync(Stream stream, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class FakeVerifier : ISignatureVerifier
    {
        public SignatureCheckResult Next { get; set; } = null!;
        public int Calls { get; private set; }
        public long MaxSizeBytes => Sha256Hasher.DefaultMaxSizeBytes;
        public SignatureCheckResult Verify(string path, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Next;
        }
    }

    private sealed class FakeYara : IYaraScanner
    {
        public YaraScanResult? Next { get; set; }
        public Detection? Detection { get; set; }
        public long ScannedLength { get; set; } = 10;
        public int Calls { get; private set; }
        public long MaxSizeBytes => Sha256Hasher.DefaultMaxSizeBytes;

        public YaraScanResult ScanFile(string path, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (Next is not null)
            {
                return Next;
            }

            YaraRuleInfo[] matches = Detection is null
                ? []
                : [new YaraRuleInfo("x.yar", "X", [], Detection.Verdict, MitreTechniqueIdFormat.SelectOrDefault(null), null)];
            return YaraScanResult.Scanned(matches, ScannedLength, new string('f', 64));
        }

        public YaraScanResult ScanMemory(ReadOnlySpan<byte> data, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    /// <summary>Scans fixed bytes instead of the file, so EICAR never has to be on disk.</summary>
    private sealed class InMemoryYara(YaraScanner inner, byte[] content) : IYaraScanner
    {
        public long MaxSizeBytes => inner.MaxSizeBytes;
        public YaraScanResult ScanFile(string path, CancellationToken cancellationToken = default) => inner.ScanMemory(content, cancellationToken);
        public YaraScanResult ScanMemory(ReadOnlySpan<byte> data, CancellationToken cancellationToken = default) => inner.ScanMemory(data, cancellationToken);
    }

    private sealed class FakeMotw : IMarkOfTheWebReader
    {
        public MarkOfTheWebResult Next { get; set; } = MarkOfTheWebResult.Absent();
        public int Calls { get; private set; }
        public MarkOfTheWebResult Read(string path, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Next;
        }
    }

    private sealed class FakeHeuristics : IFileHeuristics
    {
        public HeuristicResult? Next { get; set; }
        public HeuristicContext? LastContext { get; private set; }
        public int Calls { get; private set; }
        public HeuristicResult Analyze(string path, HeuristicContext context, CancellationToken cancellationToken = default)
        {
            Calls++;
            LastContext = context;
            return Next ?? new HeuristicResult([], FileHeuristics.DefaultThreshold, contentInspected: true, null);
        }
    }

    private sealed class FakeOnline : IOnlineHashLookup
    {
        public Detection? Next { get; set; }
        public OnlineLookupRequest? LastRequest { get; private set; }
        public int Calls { get; private set; }
        public Task<Detection?> LookupAsync(OnlineLookupRequest request, CancellationToken cancellationToken = default)
        {
            Calls++;
            LastRequest = request;
            return Task.FromResult(Next);
        }
    }
}
