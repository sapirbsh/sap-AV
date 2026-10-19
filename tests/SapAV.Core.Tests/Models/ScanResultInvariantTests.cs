using System.Reflection;
using System.Text.Json;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

/// <summary>
/// Invariant checks for ScanResult and the model enums: Status's private init, assignment-order
/// independence of the "no detections unless Scanned" rule, and StrictEnumConverter in
/// property-name (dictionary key) position and inside nullable / collection contexts.
/// </summary>
public class ScanResultInvariantTests
{
    private static readonly ScanItem Item = new(@"C:\Users\test\Downloads\a.exe", ScanTrigger.RealTime);
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);

    private static readonly Detection Mal =
        new(Verdict.Malicious, "YARA rule Test_Rule", "T1204.002", DetectionSource.Yara);

    private static readonly MethodInfo StatusSetter =
        typeof(ScanResult).GetProperty(nameof(ScanResult.Status))!.GetSetMethod(nonPublic: true)!;

    // ---- Status private init ----

    [Fact]
    public void Status_Setter_IsNotPublic_SoWithAndInitializersCannotChangeIt()
    {
        // `r with { Status = ... }` and `new ScanResult(...) { Status = ... }` only compile if the
        // setter is accessible; a non-public setter means outside code cannot change Status.
        Assert.NotNull(StatusSetter);
        Assert.False(StatusSetter.IsPublic);
        Assert.False(StatusSetter.IsFamily || StatusSetter.IsFamilyOrAssembly || StatusSetter.IsAssembly);
    }

    [Fact]
    public void With_KeepsStatus_AndCannotSmuggleDetectionsIntoNotScanned()
    {
        var locked = ScanResult.NotScanned(Item, ScanStatus.Locked, Now);
        var copy = locked with { Timestamp = Now.AddMinutes(1) };
        Assert.Equal(ScanStatus.Locked, copy.Status);
        Assert.Null(copy.Verdict);
        Assert.Throws<ArgumentException>(() => locked with { Detections = [Mal] });
    }

    // ---- Rule holds in both assignment orders ----

    [Fact]
    public void Order_StatusThenDetections_Rejected()
    {
        // Constructor order: Status first, then Detections.
        Assert.Throws<ArgumentException>(() =>
            new ScanResult(Item, [Mal], Now, status: ScanStatus.AccessDenied));
    }

    [Fact]
    public void Order_DetectionsThenStatus_Rejected_ViaPrivateInit()
    {
        // Detections already set on a Scanned result; then Status is assigned a non-Scanned value
        // (simulating any future code path that assigns Status after Detections).
        var scanned = new ScanResult(Item, [Mal], Now);
        var ex = Assert.Throws<TargetInvocationException>(() =>
            StatusSetter.Invoke(scanned, [ScanStatus.Locked]));
        Assert.IsAssignableFrom<ArgumentException>(ex.InnerException);
        Assert.Equal(ScanStatus.Scanned, scanned.Status);
        Assert.Equal(Verdict.Malicious, scanned.Verdict);
    }

    [Fact]
    public void Order_DetectionsThenStatus_UndefinedValue_Rejected_ViaPrivateInit()
    {
        var clean = ScanResult.Clean(Item, Now);
        var ex = Assert.Throws<TargetInvocationException>(() =>
            StatusSetter.Invoke(clean, [(ScanStatus)99]));
        Assert.IsType<ArgumentOutOfRangeException>(ex.InnerException);
    }

    [Fact]
    public void Order_StatusAssignedLater_RecomputesVerdict()
    {
        // Clean result -> Status set to Locked afterwards: verdict must become null, not stay Clean.
        var clean = ScanResult.Clean(Item, Now);
        var copy = clean with { };
        StatusSetter.Invoke(copy, [ScanStatus.Locked]);
        Assert.Null(copy.Verdict);
    }

    [Fact]
    public void Json_DetectionsBeforeStatus_ScannedIsAccepted()
    {
        var json = $$"""
            {"Item":{"Path":"C:\\a.exe","Trigger":"RealTime"},
             "Detections":[{"Verdict":"Malicious","Reason":"r","TechniqueId":"T1204.002","SecondaryTechniqueIds":[],"Source":"Yara"}],
             "Timestamp":"2026-10-19T12:00:00+00:00","Status":"Scanned"}
            """;
        var r = JsonSerializer.Deserialize<ScanResult>(json)!;
        Assert.Equal(Verdict.Malicious, r.Verdict);
    }

    // ---- [JsonRequired] + ctor default ----

    [Theory]
    [InlineData("status")]   // wrong case: default options are case-sensitive, so this is "missing"
    [InlineData("STATUS")]
    public void Json_StatusWithWrongCase_TreatedAsMissing_Throws(string name)
    {
        var json = $$"""
            {"Item":{"Path":"C:\\a.exe","Trigger":"RealTime"},"Detections":[],
             "Timestamp":"2026-10-19T12:00:00+00:00","{{name}}":"Locked"}
            """;
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScanResult>(json));
    }

    [Fact]
    public void Json_MissingStatus_Throws_EvenWithCaseInsensitiveOptions()
    {
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var json = """
            {"Item":{"Path":"C:\\a.exe","Trigger":"RealTime"},"Detections":[],
             "Timestamp":"2026-10-19T12:00:00+00:00"}
            """;
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScanResult>(json, opts));
    }

    // ---- StrictEnumConverter as dictionary key / property name ----

    // StrictEnumConverter does not override ReadAsPropertyName/WriteAsPropertyName, so model enums
    // are NOT usable as dictionary keys. These tests pin the current fail-closed behavior: it throws
    // NotSupportedException rather than silently falling back to a lenient (numeric / case-insensitive)
    // parser. If enum-keyed dictionaries are ever needed (e.g. per-verdict counters over the pipe),
    // the converter must add those overrides and these tests should be replaced by exact-name tests.

    [Theory]
    [InlineData("""{"Locked":1}""")]
    [InlineData("""{"1":1}""")]
    [InlineData("""{"locked":1}""")]
    [InlineData("""{"Locked, Error":1}""")]
    public void DictionaryKey_Read_IsUnsupported_FailsClosed(string json)
    {
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<Dictionary<ScanStatus, int>>(json));
    }

    [Fact]
    public void DictionaryKey_Write_IsUnsupported_FailsClosed()
    {
        Assert.Throws<NotSupportedException>(() =>
            JsonSerializer.Serialize(new Dictionary<Verdict, int> { [Verdict.Malicious] = 1 }));
        Assert.Throws<NotSupportedException>(() =>
            JsonSerializer.Serialize(new Dictionary<ScanStatus, int> { [(ScanStatus)42] = 1 }));
    }

    // ---- Collections of nullable enums ----

    [Fact]
    public void NullableVerdictArray_NullOk_BadNameThrows()
    {
        var arr = JsonSerializer.Deserialize<Verdict?[]>("""[null,"Clean"]""")!;
        Assert.Equal([null, Verdict.Clean], arr);
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Verdict?[]>("""[null,"clean"]"""));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Verdict?[]>("""[0]"""));
    }
}
