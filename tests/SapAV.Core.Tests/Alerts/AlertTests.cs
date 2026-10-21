using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Alerts;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;

namespace SapAV.Core.Tests.Alerts;

public sealed class AlertTests
{
    private const string Sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    private const string Version = "0.1.0+3b681a8";
    private static readonly DateTimeOffset ScanTime = new(2026, 10, 21, 14, 30, 0, TimeSpan.FromHours(3));
    private static readonly ScanItem Download = new(@"C:\Users\test\Downloads\invoice.pdf.exe", ScanTrigger.RealTime);

    private static readonly Detection Heuristic = new(Verdict.Suspicious,
        "Heuristic score 70 (threshold 50): double extension .pdf.exe; unsigned executable in Downloads",
        "T1036.007", DetectionSource.Heuristic, ["T1204.002"]);

    private static readonly Detection Yara = new(Verdict.Malicious,
        "YARA rule Antivirus_Test_File matched (antivirus-test-file.yar)", "T1204.002", DetectionSource.Yara, ["T1059.001"]);

    private static FileScanReport Report(ScanResult result, string? hostUrl = null)
    {
        MarkOfTheWebResult? motw = hostUrl is null
            ? MarkOfTheWebResult.Absent()
            : MarkOfTheWebResult.Present(MarkOfTheWeb.Parse(Encoding.UTF8.GetBytes($"[ZoneTransfer]\nZoneId=3\nHostUrl={hostUrl}\n")));
        return new FileScanReport(result, HashResult.Hashed(Sha, 68), SignatureCheckResult.NotSigned(), null, motw, null, []);
    }

    private static Alert MaliciousAlert() => Alert.FromReport(
        Report(new ScanResult(Download, [Heuristic, Yara], ScanTime, Sha, ScanStatus.Scanned, SignatureStatus.UnsignedOrInvalid),
            "https://user:pw@cdn.test/invoice.pdf.exe?X-Amz-Signature=s3cr3t"),
        AlertAction.Quarantined, Version)!;

    // --- Building from a report ---

    [Fact]
    public void FromReport_MaliciousDownload_CarriesEveryField_WorstFindingFirst()
    {
        var alert = MaliciousAlert();

        Assert.Equal(AlertType.MaliciousFile, alert.Type);
        Assert.Equal(Verdict.Malicious, alert.Verdict);
        Assert.Equal(ScanTime.UtcDateTime, alert.Timestamp.UtcDateTime);
        Assert.Equal(TimeSpan.Zero, alert.Timestamp.Offset);
        Assert.Equal(Download.Path, alert.FilePath);
        Assert.Equal(Sha, alert.Sha256);
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, alert.SignatureStatus);
        Assert.Null(alert.Signer);
        Assert.Equal("T1204.002", alert.TechniqueId); // from the Malicious YARA detection, not the first one
        Assert.Equal(["T1059.001", "T1036.007"], alert.SecondaryTechniqueIds); // distinct, primary excluded
        Assert.Equal([Yara.Reason, Heuristic.Reason], alert.Reasons);
        Assert.Equal("https://***@cdn.test/invoice.pdf.exe", alert.SourceUrl); // log form: no query, user info redacted
        Assert.Equal(AlertAction.Quarantined, alert.Action);
        Assert.Equal(ScanTrigger.RealTime, alert.Trigger);
        Assert.Equal(Version, alert.EngineVersion);
        Assert.Equal(Alert.CurrentSchemaVersion, alert.SchemaVersion);
    }

    [Fact]
    public void FromScanResult_SuspiciousTrustedSigned_KeepsSigner()
    {
        var result = new ScanResult(Download, [Heuristic], ScanTime, Sha, ScanStatus.Scanned, SignatureStatus.OtherTrusted, "Contoso Ltd");

        var alert = Alert.FromScanResult(result, null, AlertAction.None, Version)!;

        Assert.Equal(AlertType.SuspiciousFile, alert.Type);
        Assert.Equal("Contoso Ltd", alert.Signer);
        Assert.Equal(["T1204.002"], alert.SecondaryTechniqueIds);
        Assert.Null(alert.SourceUrl);
    }

    [Fact]
    public void FromScanResult_CleanOrNotScanned_GivesNoAlert()
    {
        Assert.Null(Alert.FromScanResult(ScanResult.Clean(Download, ScanTime, Sha), null, AlertAction.None, Version));
        Assert.Null(Alert.FromScanResult(ScanResult.NotScanned(Download, ScanStatus.Locked, ScanTime), null, AlertAction.None, Version));
    }

    [Fact]
    public void AlertId_IsStableForTheSameIncident_AndDiffersForAnother()
    {
        var again = MaliciousAlert();
        var later = Alert.FromScanResult(
            new ScanResult(Download, [Yara], ScanTime.AddSeconds(1), Sha), null, AlertAction.None, Version)!;

        Assert.Equal(MaliciousAlert().AlertId, again.AlertId);
        Assert.NotEqual(again.AlertId, later.AlertId);
        Assert.Equal(8, again.AlertId.Version);
    }

    // --- JSON ---

    [Fact]
    public void Json_RoundTrips_WithEnumNamesAndUtcTimestamp()
    {
        var alert = MaliciousAlert();

        var json = JsonSerializer.Serialize(alert);
        var copy = JsonSerializer.Deserialize<Alert>(json);

        Assert.Equal(alert, copy);
        var node = JsonNode.Parse(json)!.AsObject();
        Assert.Equal("MaliciousFile", (string?)node["Type"]);
        Assert.Equal("Quarantined", (string?)node["Action"]);
        Assert.Equal("UnsignedOrInvalid", (string?)node["SignatureStatus"]);
        Assert.Equal(1, (int?)node["SchemaVersion"]);
        Assert.EndsWith("+00:00", (string?)node["Timestamp"]);
    }

    [Theory]
    [InlineData("AlertId")]
    [InlineData("Type")]
    [InlineData("FilePath")]
    [InlineData("EngineVersion")]
    public void Json_MissingRequiredMember_Throws(string member)
    {
        var node = JsonSerializer.SerializeToNode(MaliciousAlert())!.AsObject();
        node.Remove(member);

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Alert>(node.ToJsonString()));
    }

    [Fact]
    public void Json_NumericEnumOrMismatchedVerdict_IsRejected()
    {
        var numeric = JsonSerializer.SerializeToNode(MaliciousAlert())!.AsObject();
        numeric["Type"] = 0;
        var mismatch = JsonSerializer.SerializeToNode(MaliciousAlert())!.AsObject();
        mismatch["Verdict"] = "Suspicious";

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Alert>(numeric.ToJsonString()));
        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<Alert>(mismatch.ToJsonString()));
    }

    [Fact]
    public void Json_UntrustedContent_IsSanitisedOnRead()
    {
        var node = JsonSerializer.SerializeToNode(MaliciousAlert())!.AsObject();
        node["Reasons"] = new JsonArray("first\r\nsap-AV: Clean", new string('r', 5000));
        node["SourceUrl"] = "https://cdn.test/x.exe?token=s3cr3t";
        node["FilePath"] = "C:\\Users\\test\\a\u2028b.exe";

        var alert = JsonSerializer.Deserialize<Alert>(node.ToJsonString())!;

        Assert.Equal("first  sap-AV: Clean", alert.Reasons[0]);
        Assert.Equal(Detection.MaxReasonLength, alert.Reasons[1].Length);
        Assert.Equal("https://cdn.test/x.exe", alert.SourceUrl);
        Assert.Equal("C:\\Users\\test\\a\uFFFDb.exe", alert.FilePath);
    }

    // --- Validation ---

    [Fact]
    public void Constructor_RejectsInconsistentOrIncompleteAlerts()
    {
        Alert Make(AlertType type = AlertType.MaliciousFile, Verdict verdict = Verdict.Malicious, string? technique = "T1204.002",
            string[]? reasons = null, SignatureStatus? status = null, string? signer = null, string version = Version) =>
            new(Guid.NewGuid(), ScanTime, type, verdict, Download.Path, Sha, status, signer, technique, [],
                reasons ?? ["reason"], null, AlertAction.None, ScanTrigger.RealTime, version);

        Assert.NotNull(Make());
        Assert.ThrowsAny<ArgumentException>(() => Make(verdict: Verdict.Suspicious));
        Assert.ThrowsAny<ArgumentException>(() => Make(AlertType.QuarantineRestored, Verdict.Clean));
        Assert.ThrowsAny<ArgumentException>(() => Make(technique: null));
        Assert.ThrowsAny<ArgumentException>(() => Make(reasons: []));
        Assert.ThrowsAny<ArgumentException>(() => Make(reasons: ["\r\n"]));
        Assert.ThrowsAny<ArgumentException>(() => Make(status: SignatureStatus.UnsignedOrInvalid, signer: "Fake Corp"));
        Assert.ThrowsAny<ArgumentException>(() => Make(version: "1.0\r\nInjected"));
        Assert.NotNull(Make(AlertType.QuarantineRestored, Verdict.Suspicious, technique: null, reasons: []));
    }
}
