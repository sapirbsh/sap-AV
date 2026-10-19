using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

/// <summary>
/// The models travel over the named pipe (B4) as JSON, using default <see cref="JsonSerializer"/> options.
/// Invalid content surfaces as <see cref="ArgumentException"/> (or a subclass) thrown by the model's
/// validation; structurally bad JSON (syntax, enum values that aren't exact names, missing/null required
/// value-type members) surfaces as <see cref="JsonException"/>.
/// </summary>
public class JsonRoundTripTests
{
    private static readonly ScanItem Item = new(@"C:\Users\test\Downloads\invoice.pdf.exe", ScanTrigger.RealTime);
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.FromHours(3));
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static readonly Detection DoubleExtension =
        new(Verdict.Suspicious, "Double extension .pdf.exe", "T1036.007", DetectionSource.Heuristic);

    private static readonly Detection Yara =
        new(Verdict.Malicious, "YARA rule Test_Rule", "T1566.001", DetectionSource.Yara, ["T1059.001", "T1059.003"]);

    private static T RoundTrip<T>(T value) =>
        JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value))!;

    [Fact]
    public void ScanItem_RoundTrips()
    {
        Assert.Equal(Item, RoundTrip(Item));
    }

    [Fact]
    public void Detection_RoundTrips_WithAndWithoutSecondaries()
    {
        Assert.Equal(Yara, RoundTrip(Yara));
        Assert.Equal(DoubleExtension, RoundTrip(DoubleExtension));
    }

    [Fact]
    public void ScanResult_RoundTrips_WithDetections()
    {
        var result = new ScanResult(Item, [DoubleExtension, Yara], Now, EicarSha256);

        var copy = RoundTrip(result);

        Assert.Equal(result, copy);
        Assert.Equal(Verdict.Malicious, copy.Verdict);
        Assert.Equal(Now.Offset, copy.Timestamp.Offset);
    }

    [Fact]
    public void ScanResult_RoundTrips_Clean()
    {
        var result = ScanResult.Clean(Item, Now);

        var copy = RoundTrip(result);

        Assert.Equal(result, copy);
        Assert.Equal(Verdict.Clean, copy.Verdict);
    }

    [Theory]
    [InlineData(ScanStatus.SkippedTooLarge)]
    [InlineData(ScanStatus.Locked)]
    public void ScanResult_RoundTrips_NotScanned(ScanStatus status)
    {
        var result = ScanResult.NotScanned(Item, status, Now);

        var copy = RoundTrip(result);

        Assert.Equal(result, copy);
        Assert.Equal(status, copy.Status);
        Assert.Null(copy.Verdict);
    }

    [Fact]
    public void Serialized_UsesEnumNames()
    {
        var json = JsonSerializer.Serialize(new ScanResult(Item, [Yara], Now));

        Assert.Contains("\"Trigger\":\"RealTime\"", json);
        Assert.Contains("\"Source\":\"Yara\"", json);
        Assert.Contains("\"Status\":\"Scanned\"", json);
        Assert.Contains("\"Verdict\":\"Malicious\"", json);
    }

    // --- Required value-type members: missing must not silently become the default ---

    [Fact]
    public void Deserialize_MissingStatus_Throws_InsteadOfDefaultingToScanned()
    {
        // A default of Scanned would make an unscanned file read as Clean.
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node.Remove("Status");

        var ex = Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
        Assert.Contains("Status", ex.Message);
    }

    [Fact]
    public void Deserialize_MissingTimestamp_Throws_InsteadOfDefaultingToMinValue()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node.Remove("Timestamp");

        var ex = Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
        Assert.Contains("Timestamp", ex.Message);
    }

    [Fact]
    public void Deserialize_NullTimestamp_ThrowsJsonException()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node["Timestamp"] = null;

        Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
    }

    [Theory]
    [InlineData("Verdict")] // would otherwise default to Clean
    [InlineData("Source")]  // would otherwise default to Blocklist
    public void Deserialize_DetectionMissingRequiredEnum_ThrowsJsonException(string property)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Yara))!.AsObject();
        node.Remove(property);

        var ex = Assert.Throws<JsonException>(() => node.Deserialize<Detection>());
        Assert.Contains(property, ex.Message);
    }

    [Theory]
    [InlineData("Verdict")]
    [InlineData("Source")]
    public void Deserialize_DetectionNullRequiredEnum_ThrowsJsonException(string property)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Yara))!.AsObject();
        node[property] = null;

        Assert.Throws<JsonException>(() => node.Deserialize<Detection>());
    }

    [Fact]
    public void Deserialize_ScanItemMissingTrigger_ThrowsJsonException()
    {
        // Would otherwise default to RealTime.
        var ex = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<ScanItem>("""{"Path":"C:\\a.exe"}"""));
        Assert.Contains("Trigger", ex.Message);
    }

    [Fact]
    public void Deserialize_DetectionsBeforeLockedStatus_InRawJson_ThrowsArgumentException()
    {
        // Property order must not let detections slip in before the status is known.
        const string json = """
            {
              "Item": { "Path": "C:\\x.bin", "Trigger": "RealTime" },
              "Detections": [
                { "Verdict": "Malicious", "Reason": "YARA rule Test_Rule", "TechniqueId": "T1204.002",
                  "SecondaryTechniqueIds": [], "Source": "Yara" }
              ],
              "Status": "Locked",
              "Timestamp": "2026-10-19T12:00:00+03:00"
            }
            """;

        var ex = Assert.Throws<ArgumentException>(() => JsonSerializer.Deserialize<ScanResult>(json));
        Assert.Equal(nameof(ScanResult.Detections), ex.ParamName);
    }

    // --- Forged verdicts are ignored: the verdict is always derived ---

    [Theory]
    [InlineData("Malicious")]
    [InlineData("Suspicious")]
    public void Deserialize_ForgedVerdict_OnCleanResult_IsIgnored(string forged)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node["Verdict"] = forged;

        var copy = node.Deserialize<ScanResult>()!;

        Assert.Equal(Verdict.Clean, copy.Verdict);
    }

    [Fact]
    public void Deserialize_ForgedCleanVerdict_OnMaliciousResult_IsIgnored()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(new ScanResult(Item, [Yara], Now)))!.AsObject();
        node["Verdict"] = "Clean";

        var copy = node.Deserialize<ScanResult>()!;

        Assert.Equal(Verdict.Malicious, copy.Verdict);
    }

    [Fact]
    public void Deserialize_ForgedCleanVerdict_OnNotScannedResult_IsIgnored()
    {
        var node = JsonNode.Parse(
            JsonSerializer.Serialize(ScanResult.NotScanned(Item, ScanStatus.AccessDenied, Now)))!.AsObject();
        node["Verdict"] = "Clean";

        var copy = node.Deserialize<ScanResult>()!;

        Assert.Null(copy.Verdict);
    }

    // --- Invalid input surfaces as an exception ---

    [Fact]
    public void Deserialize_InvalidTechniqueId_ThrowsArgumentException()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Yara))!.AsObject();
        node["TechniqueId"] = "bogus";

        var ex = Assert.Throws<ArgumentException>(() => node.Deserialize<Detection>());
        Assert.Equal(nameof(Detection.TechniqueId), ex.ParamName);
    }

    [Fact]
    public void Deserialize_CleanDetectionVerdict_ThrowsArgumentOutOfRange()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Yara))!.AsObject();
        node["Verdict"] = "Clean";

        Assert.Throws<ArgumentOutOfRangeException>(() => node.Deserialize<Detection>());
    }

    [Theory]
    [InlineData(42)]
    [InlineData(1)] // defined value (Yara), still rejected as a number
    public void Deserialize_NumericEnum_ThrowsJsonException(int raw)
    {
        // StrictEnumConverter accepts exact names only.
        var node = JsonNode.Parse(JsonSerializer.Serialize(Yara))!.AsObject();
        node["Source"] = raw;

        Assert.Throws<JsonException>(() => node.Deserialize<Detection>());
    }

    [Fact]
    public void Deserialize_RelativePath_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(
            () => JsonSerializer.Deserialize<ScanItem>("""{"Path":"relative.exe","Trigger":"CustomScan"}"""));
    }

    [Fact]
    public void Deserialize_MissingPath_ThrowsArgumentException()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => JsonSerializer.Deserialize<ScanItem>("""{"Trigger":"CustomScan"}"""));
    }

    [Fact]
    public void Deserialize_BadSha256_ThrowsArgumentException()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node["Sha256"] = "not-a-hash";

        var ex = Assert.Throws<ArgumentException>(() => node.Deserialize<ScanResult>());
        Assert.Equal(nameof(ScanResult.Sha256), ex.ParamName);
    }

    [Fact]
    public void Deserialize_DetectionsOnNotScannedResult_ThrowsArgumentException()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(new ScanResult(Item, [Yara], Now)))!.AsObject();
        node["Status"] = "Locked";

        var ex = Assert.Throws<ArgumentException>(() => node.Deserialize<ScanResult>());
        Assert.Equal(nameof(ScanResult.Detections), ex.ParamName);
    }

    [Fact]
    public void Deserialize_UnknownEnumName_ThrowsJsonException()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Yara))!.AsObject();
        node["Source"] = "Signature";

        Assert.Throws<JsonException>(() => node.Deserialize<Detection>());
    }

    [Fact]
    public void Deserialize_MalformedJson_ThrowsJsonException()
    {
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<ScanResult>("{\"Item\":"));
    }
}
