using System.Text;
using System.Text.Json;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

public sealed class PipeMappingTests
{
    [Fact]
    public void EveryEngineEnumValue_HasAWireName()
    {
        foreach (var v in Enum.GetValues<ScanJobState>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<ScanFileAction>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<QuarantineStatus>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<RestoreStatus>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<QuarantineEntryIntegrity>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
    }

    [Fact]
    public void ResultDetail_NeverCarriesScanWorkerText()
    {
        var notScanned = new ScanJobFileResult(@"C:\x\a.bin", ScanStatus.Error, null, ScanFileAction.None,
            "The scan worker could not scan the file: <secret file content from the worker>", null, null, null);
        var refused = new ScanJobFileResult(@"C:\x\b.bin", ScanStatus.Scanned, Verdict.Malicious, ScanFileAction.NeedsUserConfirmation,
            "Not quarantined automatically: protected system folder.\u200B\r\nFAKE", null, null, null);

        Assert.Equal("Not scanned (Error).", PipeMapping.Result(0, notScanned).Detail);
        Assert.Equal("Not quarantined automatically: protected system folder.\uFFFD  FAKE", PipeMapping.Result(1, refused).Detail);
    }

    [Fact]
    public void QuarantineReasons_AreCappedAndInvisibleCharactersMapped_PathsKeptExactButFlagged()
    {
        var entry = RecordingQuarantine.Entry("C:\\x\\inv\u202Efdp.exe",
            reasons: [.. Enumerable.Range(0, 20).Select(i => $"rule {i} \u2063" + new string('r', 500))]);

        var item = PipeMapping.Item(entry);

        Assert.Equal(PipeMapping.MaxReasons, item.Reasons.Count);
        Assert.All(item.Reasons, r =>
        {
            Assert.True(r.Length <= PipeMapping.MaxReasonLength);
            Assert.DoesNotContain('\u2063', r);
        });
        Assert.Equal("C:\\x\\inv\u202Efdp.exe", item.OriginalPath!.Value);
        Assert.True(item.OriginalPath.HasHiddenCharacters);
    }

    [Fact]
    public void ServerFrames_RoundTripWithTheStrictOptions_AndEscapeBidi()
    {
        var progress = new JobProgressInfo(Guid.NewGuid(), JobState.Running, 3, null, 1, 10, null, WirePath.From("C:\\a\u202Eb"), null,
            TimeSpan.FromSeconds(2), new JobCountersInfo(1, 0, 0, 0, 0, 0, 0, 0));
        var frame = new PipeFrame(PipeFrameKind.Event, Event: PipeEventKind.JobProgress, Body: PipeJson.ToElement(progress));

        byte[] bytes = PipeJson.Serialize(frame, PipeProtocol.MaxServerFrameBytes);
        var back = JsonSerializer.Deserialize<PipeFrame>(bytes, PipeJson.Options)!;

        Assert.Contains("\\u202E", Encoding.UTF8.GetString(bytes), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(progress.CurrentFile, PipeJson.Body<JobProgressInfo>(back.Body).CurrentFile);
    }
}

/// <summary>C1: the result fields the results screen (F2) needs, and what each kind of client may see.</summary>
public sealed class PipeResultFieldsTests
{
    private const string Sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static ScanJobFileResult Flagged(bool couldRead = true) =>
        new(@"C:\x\mal.bin", ScanStatus.Scanned, Verdict.Malicious, ScanFileAction.Quarantined, null, Sha, "item", Guid.NewGuid())
        {
            Detections =
            [
                new Detection(Verdict.Suspicious, "Heuristic: <worker text \u2063 secret>", "T1036.007", DetectionSource.Heuristic),
                new Detection(Verdict.Malicious, "YARA rule Leak_" + new string('x', 900), "T1204.002", DetectionSource.Yara, ["T1027.002"]),
            ],
            SignatureStatus = Core.Signatures.SignatureStatus.OtherTrusted,
            Signer = "Contoso \u202E" + new string('s', 400),
            SourceUrl = "https://example.test/" + new string('u', 900),
            RequesterCouldRead = couldRead,
        };

    [Fact]
    public void StandardUsers_GetEngineTemplatedReasons_WorstFirst_WithTechniques()
    {
        var info = PipeMapping.Result(0, Flagged());

        Assert.Equal(2, info.Reasons.Count);
        Assert.StartsWith("Malicious: a YARA rule matched (MITRE ATT&CK T1204.002", info.Reasons[0], StringComparison.Ordinal);
        Assert.StartsWith("Suspicious: heuristic analysis flagged it", info.Reasons[1], StringComparison.Ordinal);
        Assert.DoesNotContain(info.Reasons, r => r.Contains("Leak_", StringComparison.Ordinal) || r.Contains("secret", StringComparison.Ordinal));
        Assert.Equal(["T1204.002", "T1027.002", "T1036.007"], info.TechniqueIds);
        Assert.Equal(Sha, info.Sha256);
    }

    [Fact]
    public void Administrators_GetTheScannerText_SanitisedAndCapped()
    {
        var info = PipeMapping.Result(0, Flagged(), forAdmin: true);

        Assert.StartsWith("YARA rule Leak_", info.Reasons[0], StringComparison.Ordinal);
        Assert.All(info.Reasons, r => Assert.True(r.Length <= PipeMapping.MaxReasonLength));
        Assert.DoesNotContain('\u2063', info.Reasons[1]);
    }

    [Fact]
    public void SignerAndUrl_AreCappedAndCleanedForAdmins_HashOnlyWhenTheRequesterCouldRead()
    {
        var info = PipeMapping.Result(0, Flagged(), forAdmin: true);
        var hidden = PipeMapping.Result(0, Flagged(couldRead: false));

        Assert.Equal(Core.Signatures.SignatureStatus.OtherTrusted, info.SignatureStatus);
        Assert.True(info.Signer!.Length <= PipeMapping.MaxSignerLength);
        Assert.DoesNotContain('‮', info.Signer);
        Assert.True(info.SourceUrl!.Length <= PipeMapping.MaxUrlLength);
        Assert.Null(hidden.Sha256);
    }

    [Theory]
    [InlineData("OtherTrusted", "Contoso Ltd", null)] // a worker-supplied name is never shown to a standard user
    [InlineData("Microsoft", "Totally Microsoft ‮exe.", "Microsoft")] // only the fixed word
    [InlineData("UnsignedOrInvalid", null, null)]
    public void StandardUsers_GetOnlyAFixedSignerWord(string status, string? signer, string? expected)
    {
        var r = Flagged() with { SignatureStatus = Enum.Parse<Core.Signatures.SignatureStatus>(status), Signer = signer };

        Assert.Equal(expected, PipeMapping.Result(0, r).Signer);
    }

    [Theory]
    [InlineData("https://***@Downloads.Example.TEST/path/x.exe", "downloads.example.test")]
    [InlineData("https://bücher.example/x", "xn--bcher-kva.example")] // IDN to punycode
    [InlineData("http://[::1]/x", null)] // not a plain host name
    [InlineData("https://example.test/leak/of/other/file/content", "example.test")] // the path never reaches the user
    [InlineData("not a url", null)]
    public void StandardUsers_GetOnlyTheValidatedDownloadHost(string url, string? expected) =>
        Assert.Equal(expected, PipeMapping.Result(0, Flagged() with { SourceUrl = url }).SourceUrl);


    [Fact]
    public void NotScanned_HasAnEngineReasonAndTemplate_NeverTheStoredDetail()
    {
        var remote = new ScanJobFileResult(@"C:\x\r.bin", ScanStatus.Error, null, ScanFileAction.None, "worker said: secret", null, null, null)
        {
            SkipReason = ScanSkipReason.RemoteFile,
        };

        var info = PipeMapping.Result(0, remote);

        Assert.Equal(NotScannedReason.RemoteFile, info.NotScannedReason);
        Assert.Contains("network share", info.Detail, StringComparison.Ordinal);
        foreach (var v in Enum.GetValues<ScanSkipReason>())
        {
            Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString());
        }
    }

    [Fact]
    public void NewFields_RoundTripWithTheStrictOptions()
    {
        var info = PipeMapping.Result(3, Flagged(), forAdmin: true);

        var back = JsonSerializer.Deserialize<JobFileResultInfo>(JsonSerializer.SerializeToUtf8Bytes(info, PipeJson.Options), PipeJson.Options)!;

        Assert.Equal(info.Reasons, back.Reasons);
        Assert.Equal(info.TechniqueIds, back.TechniqueIds);
        Assert.Equal((info.SignatureStatus, info.Signer, info.SourceUrl), (back.SignatureStatus, back.Signer, back.SourceUrl));
    }
}
