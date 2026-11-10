using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Alerts;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.Persistence;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Models;

/// <summary>
/// E1: the PotentiallyUnwanted verdict and threat categories, through the model, JSON, alerts, the persistence judgement,
/// YARA meta and the worker wire format (synthetic markers only).
/// </summary>
public sealed class PotentiallyUnwantedTests : IDisposable
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string KeygenRule = "rule E1_Keygen { meta: verdict = \"hacktool\" mitre = \"T1204.002\" strings: $a = \"sapav-e1-keygen-marker\" condition: $a }";

    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static ScanItem Item(string path = @"C:\Users\u\Downloads\tool.exe") => new(path, ScanTrigger.CustomScan);

    private static Detection Pup(ThreatCategory category = ThreatCategory.Pup) =>
        new(Verdict.PotentiallyUnwanted, "YARA rule Test_Pup matched", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara, null, category);

    private static Detection Of(Verdict verdict) => verdict == Verdict.PotentiallyUnwanted
        ? Pup()
        : new Detection(verdict, $"{verdict} finding", MitreTechniqueIds.MaliciousFile, DetectionSource.Heuristic);

    // ---- Ordering and the worst verdict ----

    [Fact]
    public void PotentiallyUnwanted_SitsBetweenSuspiciousAndMalicious_AndTheWorstDetectionWins()
    {
        Assert.True(Verdict.Clean < Verdict.Suspicious && Verdict.Suspicious < Verdict.PotentiallyUnwanted && Verdict.PotentiallyUnwanted < Verdict.Malicious);

        Assert.Equal(Verdict.PotentiallyUnwanted, new ScanResult(Item(), [Of(Verdict.Suspicious), Pup()], DateTimeOffset.UnixEpoch, Sha).Verdict);
        // A trojanized keygen: a hack tool AND malware is Malicious (ROADMAP feature 11).
        Assert.Equal(Verdict.Malicious, new ScanResult(Item(), [Pup(ThreatCategory.HackTool), Of(Verdict.Malicious)], DateTimeOffset.UnixEpoch, Sha).Verdict);
    }

    // ---- Detection invariants ----

    [Theory]
    [InlineData(ThreatCategory.Malware)]
    [InlineData(ThreatCategory.Infostealer)]
    [InlineData(ThreatCategory.Miner)]
    public void PotentiallyUnwanted_NeedsAPupOrHackToolCategory(ThreatCategory category)
    {
        Assert.Throws<ArgumentException>(() => Pup(category));
        Assert.Equal(ThreatCategory.HackTool, Pup(ThreatCategory.HackTool).Category);
    }

    [Theory]
    [InlineData(ThreatCategory.Pup)]
    [InlineData(ThreatCategory.HackTool)]
    public void PupAndHackTool_AreNeverMalicious_ButMayBeSuspicious(ThreatCategory category)
    {
        Assert.Throws<ArgumentException>(() => new Detection(Verdict.Malicious, "r", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara, null, category));
        Assert.Throws<ArgumentException>(() => Of(Verdict.Malicious) with { Category = category });
        Assert.Equal(category, new Detection(Verdict.Suspicious, "r", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara, null, category).Category);
    }

    [Fact]
    public void Category_DefaultsToMalware_AndUndefinedValuesAreRejected()
    {
        Assert.Equal(ThreatCategory.Malware, Of(Verdict.Malicious).Category);
        Assert.Throws<ArgumentOutOfRangeException>(() => Of(Verdict.Suspicious) with { Category = (ThreatCategory)42 });
        Assert.NotEqual(Of(Verdict.Suspicious), Of(Verdict.Suspicious) with { Category = ThreatCategory.Miner }); // part of equality
    }

    // ---- JSON ----

    [Fact]
    public void Json_RoundTripsTheNewValues_ByName()
    {
        foreach (var category in Enum.GetValues<ThreatCategory>())
        {
            Assert.Equal($"\"{category}\"", JsonSerializer.Serialize(category));
        }

        var detection = Pup(ThreatCategory.HackTool);
        string json = JsonSerializer.Serialize(detection);
        Assert.Contains("\"Verdict\":\"PotentiallyUnwanted\"", json, StringComparison.Ordinal);
        Assert.Contains("\"Category\":\"HackTool\"", json, StringComparison.Ordinal);
        Assert.Equal(detection, JsonSerializer.Deserialize<Detection>(json));

        var result = new ScanResult(Item(), [detection], DateTimeOffset.UnixEpoch, Sha);
        Assert.Equal(result, JsonSerializer.Deserialize<ScanResult>(JsonSerializer.Serialize(result)));
    }

    [Fact]
    public void Json_OlderDetectionWithoutCategory_ReadsAsMalware_ButAPupWithoutItIsRefused()
    {
        const string old = """{"Verdict":"Malicious","Reason":"r","TechniqueId":"T1204.002","SecondaryTechniqueIds":[],"Source":"Yara"}""";
        Assert.Equal(ThreatCategory.Malware, JsonSerializer.Deserialize<Detection>(old)!.Category);

        // A sender can't make a finding "potentially unwanted" (never quarantined) without saying which kind.
        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<Detection>(old.Replace("Malicious", "PotentiallyUnwanted", StringComparison.Ordinal)));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Detection>(old.Replace("}", ",\"Category\":1}", StringComparison.Ordinal)));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Detection>(old.Replace("}", ",\"Category\":\"pup\"}", StringComparison.Ordinal)));
    }

    // ---- Alerts (Event Log payload) ----

    [Fact]
    public void PupScan_IsAPotentiallyUnwantedFileAlert_WithItsCategoryInThePayload()
    {
        var result = new ScanResult(Item(), [Of(Verdict.Suspicious), Pup(ThreatCategory.HackTool)], DateTimeOffset.UnixEpoch, Sha);

        var alert = Alert.FromScanResult(result, null, AlertAction.None, "1.0.0")!;

        Assert.Equal((AlertType.PotentiallyUnwantedFile, Verdict.PotentiallyUnwanted, ThreatCategory.HackTool), (alert.Type, alert.Verdict, alert.Category));
        var node = JsonNode.Parse(JsonSerializer.Serialize(alert))!;
        Assert.Equal("HackTool", (string?)node["Category"]);
        Assert.Equal("PotentiallyUnwanted", (string?)node["Verdict"]);
        Assert.Equal(2, (int?)node["SchemaVersion"]);
        Assert.Equal(alert, JsonSerializer.Deserialize<Alert>(node.ToJsonString()));

        var malicious = Alert.FromScanResult(new ScanResult(Item(), [Of(Verdict.Malicious)], DateTimeOffset.UnixEpoch, Sha), null, AlertAction.None, "1.0.0")!;
        Assert.Equal((AlertType.MaliciousFile, ThreatCategory.Malware), (malicious.Type, malicious.Category));
    }

    [Fact]
    public void AlertCategory_IsOnlyForDetections_AndAPupAlertMustBePupOrHackTool()
    {
        Alert Make(AlertType type, Verdict verdict, ThreatCategory? category) => new(Guid.NewGuid(), DateTimeOffset.UnixEpoch, type, verdict,
            @"C:\x.exe", null, null, null, MitreTechniqueIds.MaliciousFile, null, ["r"], null, AlertAction.None, ScanTrigger.CustomScan, "1.0.0",
            null, category);

        Assert.Throws<ArgumentException>(() => Make(AlertType.PotentiallyUnwantedFile, Verdict.Suspicious, ThreatCategory.Pup)); // verdict must fit
        Assert.Throws<ArgumentException>(() => Make(AlertType.PotentiallyUnwantedFile, Verdict.PotentiallyUnwanted, ThreatCategory.Miner));
        Assert.Throws<ArgumentException>(() => Make(AlertType.ScanRulesDegraded, Verdict.Suspicious, ThreatCategory.Malware)); // health: none
        Assert.Null(Make(AlertType.SuspiciousFile, Verdict.Suspicious, null).Category); // older callers / JSON without it

        string json = JsonSerializer.Serialize(Make(AlertType.SuspiciousFile, Verdict.Suspicious, null));
        Assert.DoesNotContain("Category", json, StringComparison.Ordinal); // a file alert without one keeps the old field set
    }

    // ---- Persistence ----

    [Fact]
    public void AutostartOfAHackTool_IsPotentiallyUnwanted_AndAlertsAsASuspiciousAutostart_WithTheCategory()
    {
        const string target = @"C:\Users\alice\AppData\Roaming\Tools\keygen.exe";
        var entry = Judging.Entry(target, sid: Judging.Sid);
        var signed = Judging.Report(target, signature: Judging.VendorSigned());
        var report = signed with
        {
            Result = new ScanResult(signed.Result.Item, [Pup(ThreatCategory.HackTool)], signed.Result.Timestamp, signed.Result.Sha256, ScanStatus.Scanned,
                signed.Result.SignatureStatus, signed.Result.Signer),
        };

        var judgement = Judging.Run(entry, report);

        Assert.Equal((Verdict.PotentiallyUnwanted, PersistenceOutcome.PotentiallyUnwanted, PersistencePriority.Normal),
            (judgement.Verdict, judgement.Outcome, judgement.Priority));
        var alert = Alert.FromPersistence(new PersistenceFinding(entry, judgement, report.Result, null), AlertAction.None, ScanTrigger.Persistence,
            DateTimeOffset.UnixEpoch, "1.0.0")!;
        Assert.Equal((AlertType.SuspiciousPersistence, Verdict.PotentiallyUnwanted, ThreatCategory.HackTool), (alert.Type, alert.Verdict, alert.Category));
    }

    // ---- YARA meta ----

    [Theory]
    [InlineData("verdict = \"hacktool\"", Verdict.PotentiallyUnwanted, ThreatCategory.HackTool, false)]
    [InlineData("verdict = \"malicious\" category = \"pup\"", Verdict.PotentiallyUnwanted, ThreatCategory.Pup, true)] // capped, with a warning
    [InlineData("category = \"Info-Stealer\"", Verdict.Malicious, ThreatCategory.Infostealer, false)]
    [InlineData("verdict = \"suspicious\" category = \"miner\"", Verdict.Suspicious, ThreatCategory.Miner, false)]
    [InlineData("category = \"Pup,Miner\"", Verdict.Malicious, ThreatCategory.Malware, true)] // no comma-combined or numeric values
    [InlineData("category = \"1\"", Verdict.Malicious, ThreatCategory.Malware, true)]
    public void YaraVerdictAndCategoryMeta_AreInterpreted(string meta, Verdict verdict, ThreatCategory category, bool warns)
    {
        using var rules = YaraRuleSet.FromSource("e1.yar", $"rule R {{ meta: {meta} strings: $a = \"sapav-e1-yara-meta\" condition: $a }}");

        var rule = Assert.Single(rules.Rules);
        Assert.Equal((verdict, category), (rule.Verdict, rule.Category));
        Assert.Equal(warns, rules.Warnings.Any(w => w.Kind == YaraWarningKind.Category));
        Assert.Equal(category, rule.ToDetection().Category);
    }

    // ---- Worker wire format (untrusted) ----

    [Fact]
    public async Task AHackToolMatch_CrossesTheWorkerWire_AndMismatchedOrUndefinedCategoriesAreRejected()
    {
        using var rules = YaraRuleSet.FromSource("e1.yar", KeygenRule);
        var scanner = new FileScanner(new Sha256Hasher(), () => HashBlocklist.Empty, new AuthenticodeVerifier(), new YaraScanner(rules),
            new MarkOfTheWebReader(), new FileHeuristics());
        var path = _dir.WriteFile("notes.txt", Encoding.ASCII.GetBytes("sapav-e1-keygen-marker"));
        var item = new ScanItem(path, ScanTrigger.CustomScan);

        var wire = WireReportCodec.ToWire(await scanner.ScanAsync(item));
        var back = RoundTrip(wire, item);

        Assert.Equal(Verdict.PotentiallyUnwanted, back.Result.Verdict);
        Assert.Equal(ThreatCategory.HackTool, Assert.Single(back.Result.Detections).Category);
        Assert.Equal(ThreatCategory.HackTool, Assert.Single(back.Yara!.Matches).Category);

        var match = wire.Yara!.Matches[0];
        Rejected(wire with { Yara = wire.Yara with { Matches = [match with { Verdict = Verdict.Malicious }] } }, item); // a HackTool is never Malicious
        Rejected(wire with { Yara = wire.Yara with { Matches = [match with { Category = (ThreatCategory)99 }] } }, item);
        byte[] json = WorkerJson.Serialize(wire, WorkerLimits.MaxResponseBytes);
        string text = Encoding.UTF8.GetString(json).Replace("\"Category\":\"HackTool\"", "\"Category\":\"Malware\"", StringComparison.Ordinal);
        Assert.Throws<WorkerProtocolException>(() => WireReportCodec.FromWire(WorkerJson.Deserialize<WireScanReport>(Encoding.UTF8.GetBytes(text)), item, DateTimeOffset.UnixEpoch));
    }

    private static FileScanReport RoundTrip(WireScanReport wire, ScanItem item) =>
        WireReportCodec.FromWire(WorkerJson.Deserialize<WireScanReport>(WorkerJson.Serialize(wire, WorkerLimits.MaxResponseBytes)), item, DateTimeOffset.UnixEpoch);

    private static void Rejected(WireScanReport wire, ScanItem item) =>
        Assert.ThrowsAny<Exception>(() => RoundTrip(wire, item)); // WorkerProtocolException, or a JsonException for an undefined value on write
}
