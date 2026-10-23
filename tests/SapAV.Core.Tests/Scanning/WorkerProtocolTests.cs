using System.Buffers.Binary;
using System.Text;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Scanning;

/// <summary>
/// B5 protocol between the engine's broker and the sandboxed worker: framing caps, strict JSON, and the report codec,
/// which must treat worker output as untrusted (reject, never partly trust).
/// </summary>
public sealed class WorkerProtocolTests : IDisposable
{
    private const string MarkerRule = "rule B5_Marker { strings: $a = \"sapav-b5-marker\" condition: $a }";

    private readonly TempDirectory _dir = new();
    private readonly YaraRuleSet _rules = YaraRuleSet.FromSource("b5.yar", MarkerRule);

    public void Dispose()
    {
        _rules.Dispose();
        _dir.Dispose();
    }

    private FileScanner Scanner(IMarkOfTheWebReader? motw = null) => new(new Sha256Hasher(), () => HashBlocklist.Empty,
        new AuthenticodeVerifier(), new YaraScanner(_rules), motw ?? new MarkOfTheWebReader(), new FileHeuristics());

    private static ScanItem Item(string path) => new(path, ScanTrigger.CustomScan);

    // ---- Framing ----

    [Fact]
    public void Frame_RoundTrips_AndCleanEofIsNull()
    {
        var stream = new MemoryStream();
        WorkerFraming.Write(stream, "hello"u8, 16);
        stream.Position = 0;
        Assert.Equal("hello"u8.ToArray(), WorkerFraming.Read(stream, 16));
        Assert.Null(WorkerFraming.Read(stream, 16));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1025)]
    [InlineData(int.MaxValue)]
    public void Frame_LengthOutsideCap_IsRejectedBeforeReadingTheBody(int announced)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, announced);
        var ex = Assert.Throws<WorkerProtocolException>(() => WorkerFraming.Read(new MemoryStream(bytes), 1024));
        Assert.Contains("outside", ex.Message);
    }

    [Fact]
    public void Frame_CutShort_IsRejected()
    {
        var bytes = new byte[4 + 3];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, 10);
        Assert.Throws<WorkerProtocolException>(() => WorkerFraming.Read(new MemoryStream(bytes), 1024));
        Assert.Throws<WorkerProtocolException>(() => WorkerFraming.Read(new MemoryStream([1, 0]), 1024));
    }

    [Fact]
    public void Frame_WriterRefusesPayloadOverCap() =>
        Assert.Throws<WorkerProtocolException>(() => WorkerFraming.Write(new MemoryStream(), new byte[17], 16));

    // ---- Strict JSON ----

    private const string ValidFailed = """{"Id":7,"Kind":"Failed","Rules":null,"Report":null,"Probe":null,"Error":"x"}""";

    [Fact]
    public void Json_ValidResponse_Parses() =>
        Assert.Equal(WorkerResponseKind.Failed, WorkerJson.Deserialize<WorkerResponse>(Encoding.UTF8.GetBytes(ValidFailed)).Kind);

    [Theory]
    [InlineData("""{"Id":7,"Kind":"Failed","Rules":null,"Report":null,"Probe":null,"Error":"x","Extra":1}""")] // unknown property
    [InlineData("""{"Id":7,"Id":8,"Kind":"Failed","Rules":null,"Report":null,"Probe":null,"Error":"x"}""")] // duplicate property
    [InlineData("""{"Id":7,"Kind":"Failed","Rules":null,"Report":null,"Probe":null}""")] // missing required
    [InlineData("""{"Id":7,"Kind":3,"Rules":null,"Report":null,"Probe":null,"Error":"x"}""")] // numeric enum
    [InlineData("""{"Id":"7","Kind":"Failed","Rules":null,"Report":null,"Probe":null,"Error":"x"}""")] // number as string
    [InlineData("""{"Id":7,"Kind":"failed","Rules":null,"Report":null,"Probe":null,"Error":"x"}""")] // enum case
    [InlineData("""{ this is not json""")]
    [InlineData("""null""")]
    public void Json_WrongSchemaOrMalformed_IsAProtocolError(string json) =>
        Assert.Throws<WorkerProtocolException>(() => WorkerJson.Deserialize<WorkerResponse>(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void Json_SerializeOverCap_Throws() =>
        Assert.Throws<WorkerProtocolException>(() => WorkerJson.Serialize(new string('a', 100), 50));

    // ---- Codec ----

    [Fact]
    public async Task Codec_RoundTrip_KeepsTheVerdict_WithTheEnginesItemAndTime()
    {
        var path = _dir.WriteFile("report.pdf.exe", Encoding.ASCII.GetBytes("MZ sapav-b5-marker"));
        var original = await Scanner().ScanAsync(Item(path));
        Assert.Equal(Verdict.Malicious, original.Result.Verdict);

        var json = WorkerJson.Serialize(WireReportCodec.ToWire(original), WorkerLimits.MaxResponseBytes);
        var engineItem = Item(path);
        var engineTime = DateTimeOffset.UnixEpoch;
        var back = WireReportCodec.FromWire(WorkerJson.Deserialize<WireScanReport>(json), engineItem, engineTime);

        Assert.Same(engineItem, back.Result.Item);
        Assert.Equal(engineTime, back.Result.Timestamp);
        Assert.Equal(original.Result with { Timestamp = engineTime }, back.Result);
        Assert.Equal(original.Hash, back.Hash);
        Assert.Equal(original.Signature, back.Signature);
        Assert.Equal(original.Yara!.Matches.Select(m => m.Identifier), back.Yara!.Matches.Select(m => m.Identifier));
        Assert.Equal(original.Heuristics!.Score, back.Heuristics!.Score);
        Assert.Equal(original.Notes, back.Notes);
        Assert.Null(back.Identity); // identity is the broker's, never the worker's
    }

    [Fact]
    public async Task Codec_CatalogSignedMicrosoftBinary_RoundTripsAsMicrosoft()
    {
        var original = await Scanner().ScanAsync(Item(SignedSamples.RequireCatalogOnlyWindowsBinary()));
        var back = RoundTrip(WireReportCodec.ToWire(original), original.Result.Item);
        Assert.Equal(SignatureStatus.Microsoft, back.Result.SignatureStatus);
        Assert.Equal(original.Signature, back.Signature);
    }

    [Fact]
    public async Task Codec_RejectsInconsistentOrOverCapReports()
    {
        var path = _dir.WriteFile("a.txt", Encoding.ASCII.GetBytes("sapav-b5-marker"));
        var good = WireReportCodec.ToWire(await Scanner().ScanAsync(Item(path)));
        var item = Item(path);

        var otherHash = new string('a', 64);
        AssertRejected(good with { Result = good.Result with { Sha256 = otherHash } }, item, "SHA-256");
        AssertRejected(good with { Result = good.Result with { SignatureStatus = SignatureStatus.Microsoft } }, item, "signature");
        AssertRejected(good with { Notes = [.. Enumerable.Repeat(good.Notes.FirstOrDefault() ?? new WireNote { Level = ScanNoteLevel.Information, Message = "n" }, 40)] }, item, "notes");
        AssertRejected(good with { Hash = good.Hash with { ErrorMessage = null, Sha256 = null } }, item, "SHA-256");
        AssertRejected(good with { Yara = good.Yara! with { Matches = [good.Yara.Matches[0] with { Verdict = Verdict.Clean }] } }, item, "Suspicious or Malicious");
        AssertRejected(good with { Yara = good.Yara! with { Matches = [good.Yara.Matches[0] with { Identifier = new string('x', 5000) }] } }, item, "over");
        AssertRejected(good with { Signature = good.Signature! with { Status = SignatureStatus.Microsoft, FailureReason = SignatureFailureReason.None, Kind = SignatureKind.Embedded, Signer = null } }, item, "signer");
        AssertRejected(good with { Heuristics = good.Heuristics! with { Findings = [new WireFinding { Kind = HeuristicKind.UnsignedExecutable, Score = 10, Reason = "r", TechniqueId = "not-mitre" }] } }, item, "MITRE");
        AssertRejected(good with { Result = good.Result with { Detections = [.. Enumerable.Repeat(good.Result.Detections[0], WorkerLimits.MaxDetections + 1)] } }, item, "detections");
    }

    [Fact]
    public void Codec_ToWire_ClipsNotesAndLongText()
    {
        var item = Item(_dir.File("x.bin"));
        var notes = Enumerable.Range(0, 100).Select(i => new ScanNote(ScanNoteLevel.Information, new string('n', 10_000))).ToArray();
        var report = new FileScanReport(ScanResult.NotScanned(item, ScanStatus.Error, DateTimeOffset.UnixEpoch),
            HashResult.NotHashed(HashFailureReason.IoError, new string('e', 50_000)), null, null, null, null, notes);

        var wire = WireReportCodec.ToWire(report);

        Assert.Equal(WorkerLimits.MaxNotes, wire.Notes.Count);
        Assert.Contains("dropped", wire.Notes[^1].Message);
        Assert.All(wire.Notes, n => Assert.True(n.Message.Length <= WorkerLimits.MaxNoteLength));
        Assert.True(wire.Hash.ErrorMessage!.Length <= WorkerLimits.MaxTextLength);
        Assert.True(WorkerJson.Serialize(wire, WorkerLimits.MaxResponseBytes).Length < WorkerLimits.MaxResponseBytes);
        _ = RoundTrip(wire, item); // and the engine accepts the clipped form
    }

    // ---- Worker-side pipeline pieces ----

    [Fact]
    public async Task ScanHandleAsync_MatchesScanAsync_WithoutIdentity()
    {
        var path = _dir.WriteFile("m.bin", Encoding.ASCII.GetBytes("sapav-b5-marker"));
        var byPath = await Scanner().ScanAsync(Item(path));
        using var handle = File.OpenHandle(path);
        var byHandle = await Scanner().ScanHandleAsync(Item(path), handle);

        Assert.Equal(byPath.Result with { Timestamp = default }, byHandle.Result with { Timestamp = default });
        Assert.NotNull(byPath.Identity);
        Assert.Null(byHandle.Identity);
    }

    [Fact]
    public void BrokeredMotw_ParsesTheGivenStream_AndNeverOpensByPath()
    {
        var path = _dir.WriteFile("d.exe", [1, 2, 3]);
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/d.exe\r\n");
        using var file = File.OpenHandle(path);
        using var stream = File.OpenHandle(path + ":Zone.Identifier");

        var present = new BrokeredMarkOfTheWebReader(stream, 0).Read(file);
        Assert.Equal(MarkOfTheWebStatus.Present, present.Status);
        Assert.True(present.Mark!.IsFromInternet);

        Assert.Equal(MarkOfTheWebStatus.Absent, new BrokeredMarkOfTheWebReader(null, 2).Read(file).Status);
        Assert.Equal(MarkOfTheWebStatus.NotRead, new BrokeredMarkOfTheWebReader(null, 5).Read(file).Status);
        Assert.Equal(MarkOfTheWebStatus.NotRead, new BrokeredMarkOfTheWebReader(stream, 0).Read(path).Status);
    }

    [Fact]
    public void RuleFiles_ReadThenCompile_MatchesLoadDirectory()
    {
        File.WriteAllText(_dir.File("good.yar"), MarkerRule);
        File.WriteAllBytes(_dir.File("bad.yar"), [0xFF, 0xFE, 0x00]);
        var files = YaraRuleSet.ReadDirectoryFiles(_dir.Path, out var readErrors);
        using var fromFiles = YaraRuleSet.FromFiles(files, readErrors);
        using var direct = YaraRuleSet.LoadDirectory(_dir.Path);

        Assert.Equal(direct.Fingerprint, fromFiles.Fingerprint);
        Assert.Equal(direct.Rules.Count, fromFiles.Rules.Count);
        Assert.Equal(direct.FileErrors.Select(e => e.File), fromFiles.FileErrors.Select(e => e.File));
    }

    private static FileScanReport RoundTrip(WireScanReport wire, ScanItem item) =>
        WireReportCodec.FromWire(WorkerJson.Deserialize<WireScanReport>(WorkerJson.Serialize(wire, WorkerLimits.MaxResponseBytes)),
            item, DateTimeOffset.UnixEpoch);

    private static void AssertRejected(WireScanReport wire, ScanItem item, string because)
    {
        var ex = Assert.Throws<WorkerProtocolException>(() => RoundTrip(wire, item));
        Assert.Contains(because, ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
