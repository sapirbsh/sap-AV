using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

/// <summary>
/// Gaps not covered by <see cref="JsonRoundTripTests"/>: every non-Scanned status, the wire shape of a
/// NotScanned result, undefined/null status values on the wire, and hashing of NotScanned results.
/// </summary>
public class ScanStatusJsonTests
{
    private static readonly ScanItem Item = new(@"C:\Users\test\Downloads\big.iso", ScanTrigger.FullScan);
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.FromHours(3));
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static readonly Detection Yara =
        new(Verdict.Malicious, "YARA rule Test_Rule", "T1204.002", DetectionSource.Yara);

    private static T RoundTrip<T>(T value) =>
        JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value))!;

    [Theory]
    [InlineData(ScanStatus.SkippedTooLarge)]
    [InlineData(ScanStatus.AccessDenied)]
    [InlineData(ScanStatus.Locked)]
    [InlineData(ScanStatus.Error)]
    public void NotScanned_RoundTrips_ForEveryStatus_WithSha256(ScanStatus status)
    {
        var result = ScanResult.NotScanned(Item, status, Now, EicarSha256);

        var copy = RoundTrip(result);

        Assert.Equal(result, copy);
        Assert.Equal(status, copy.Status);
        Assert.Null(copy.Verdict);
        Assert.Empty(copy.Detections);
        Assert.Equal(EicarSha256, copy.Sha256);
    }

    [Fact]
    public void NotScanned_Serializes_StatusByName_AndVerdictAsNull()
    {
        var json = JsonSerializer.Serialize(ScanResult.NotScanned(Item, ScanStatus.AccessDenied, Now));

        Assert.Contains("\"Status\":\"AccessDenied\"", json);
        Assert.Contains("\"Verdict\":null", json);
        Assert.DoesNotContain("\"Verdict\":\"Clean\"", json);
    }

    [Theory]
    [InlineData("SkippedTooLarge")]
    [InlineData("AccessDenied")]
    [InlineData("Error")]
    public void Deserialize_DetectionsWithAnyNonScannedStatus_IsRejected(string status)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(new ScanResult(Item, [Yara], Now)))!.AsObject();
        node["Status"] = status;

        var ex = Assert.Throws<ArgumentException>(() => node.Deserialize<ScanResult>());
        Assert.Equal(nameof(ScanResult.Detections), ex.ParamName);
    }

    [Fact]
    public void Deserialize_DetectionsWithNumericNonScannedStatus_IsRejected()
    {
        // StrictEnumConverter accepts names only; a number (3 == Locked) is a JSON error.
        var node = JsonNode.Parse(JsonSerializer.Serialize(new ScanResult(Item, [Yara], Now)))!.AsObject();
        node["Status"] = (int)ScanStatus.Locked;

        Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
    }

    [Theory]
    [InlineData(42)]
    [InlineData(-1)]
    [InlineData(0)] // even a defined value (Scanned) is rejected as a number
    public void Deserialize_NumericStatus_ThrowsJsonException(int raw)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node["Status"] = raw;

        Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
    }

    [Fact]
    public void Deserialize_UnknownStatusName_ThrowsJsonException()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node["Status"] = "Skipped";

        Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
    }

    [Fact]
    public void Deserialize_NullStatus_ThrowsJsonException()
    {
        // Status is a non-nullable enum; null must not silently become Scanned (which would mean Clean).
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!.AsObject();
        node["Status"] = null;

        Assert.Throws<JsonException>(() => node.Deserialize<ScanResult>());
    }

    [Fact]
    public void Deserialize_NotScannedWithEmptyDetectionsArray_IsAccepted()
    {
        const string json =
            """{"Item":{"Path":"C:\\x.bin","Trigger":"RealTime"},"Detections":[],"Timestamp":"2026-10-19T12:00:00+03:00","Status":"Locked"}""";

        var result = JsonSerializer.Deserialize<ScanResult>(json)!;

        Assert.Equal(ScanStatus.Locked, result.Status);
        Assert.Null(result.Verdict);
    }

    // --- Equality / hashing of NotScanned results ---

    [Fact]
    public void NotScanned_EqualAndSameHash_AcrossJsonAndSha256Casing()
    {
        var a = ScanResult.NotScanned(Item, ScanStatus.Error, Now, EicarSha256);
        var b = RoundTrip(ScanResult.NotScanned(
            new ScanItem(Item.Path, Item.Trigger), ScanStatus.Error, Now, EicarSha256.ToUpperInvariant()));

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void NotScanned_NotEqualToClean_WithOtherwiseIdenticalFields()
    {
        var notScanned = ScanResult.NotScanned(Item, ScanStatus.SkippedTooLarge, Now);
        var clean = ScanResult.Clean(Item, Now);

        Assert.NotEqual(clean, notScanned);
        Assert.False(clean == notScanned);
        Assert.True(clean != notScanned);
    }

    [Fact]
    public void NotScanned_InHashSet_DistinctByStatus_DeduplicatedWhenEqual()
    {
        var set = new HashSet<ScanResult>
        {
            ScanResult.Clean(Item, Now),
            ScanResult.NotScanned(Item, ScanStatus.Locked, Now),
            ScanResult.NotScanned(Item, ScanStatus.Locked, Now),
            ScanResult.NotScanned(Item, ScanStatus.Error, Now),
        };

        Assert.Equal(3, set.Count);
        Assert.Contains(RoundTrip(ScanResult.NotScanned(Item, ScanStatus.Locked, Now)), set);
    }

    [Fact]
    public void NotScanned_With_PreservesStatusAndEquality()
    {
        var locked = ScanResult.NotScanned(Item, ScanStatus.Locked, Now);

        var copy = locked with { };

        Assert.Equal(ScanStatus.Locked, copy.Status);
        Assert.Null(copy.Verdict);
        Assert.Equal(locked, copy);
        Assert.Equal(locked.GetHashCode(), copy.GetHashCode());
    }
}
