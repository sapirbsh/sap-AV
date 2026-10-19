using System.Text.Json;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

/// <summary>Model enums serialize by name, so pipe/Event Log payloads don't depend on numeric order.</summary>
public class ModelEnumTests
{
    [Theory]
    [InlineData(Verdict.Clean, "\"Clean\"")]
    [InlineData(Verdict.Suspicious, "\"Suspicious\"")]
    [InlineData(Verdict.Malicious, "\"Malicious\"")]
    public void Verdict_SerializesAsName(Verdict value, string expectedJson)
    {
        Assert.Equal(expectedJson, JsonSerializer.Serialize(value));
        Assert.Equal(value, JsonSerializer.Deserialize<Verdict>(expectedJson));
    }

    [Fact]
    public void AllModelEnums_SerializeAsNames_AndRoundTrip()
    {
        AssertAllNames<Verdict>();
        AssertAllNames<ScanTrigger>();
        AssertAllNames<DetectionSource>();
        AssertAllNames<ScanStatus>();
    }

    [Fact]
    public void NullableVerdict_SerializesAsNameOrNull()
    {
        Assert.Equal("\"Malicious\"", JsonSerializer.Serialize<Verdict?>(Verdict.Malicious));
        Assert.Equal("null", JsonSerializer.Serialize<Verdict?>(null));
    }

    [Fact]
    public void UnknownEnumName_FailsWithJsonException()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<DetectionSource>("\"Signature\""));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScanStatus>("\"Bogus\""));
    }

    // --- StrictEnumConverter: only exact, case-sensitive names are accepted on read ---

    [Theory]
    [InlineData("\"AccessDenied, SkippedTooLarge\"")] // comma-combined (flags syntax)
    [InlineData("\"AccessDenied,SkippedTooLarge\"")]
    [InlineData("\" Locked \"")]                      // padded
    [InlineData("\"Locked \"")]
    [InlineData("\"3\"")]                             // quoted number
    [InlineData("\"-1\"")]
    [InlineData("3")]                                 // bare number
    [InlineData("0")]
    [InlineData("3.0")]
    [InlineData("\"locked\"")]                        // wrong case
    [InlineData("\"LOCKED\"")]
    [InlineData("\"\"")]                              // empty
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("[\"Locked\"]")]
    [InlineData("{}")]
    public void ScanStatus_RejectsAnythingButExactName(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScanStatus>(json));
    }

    [Theory]
    [InlineData("\"suspicious\"")]
    [InlineData("\"Suspicious, Malicious\"")]
    [InlineData("\" Malicious\"")]
    [InlineData("\"2\"")]
    [InlineData("2")]
    public void Verdict_RejectsAnythingButExactName(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Verdict>(json));
    }

    [Theory]
    [InlineData("\"realtime\"")]
    [InlineData("\"RealTime,FullScan\"")]
    [InlineData("1")]
    public void ScanTrigger_RejectsAnythingButExactName(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScanTrigger>(json));
    }

    [Theory]
    [InlineData("\"yara\"")]
    [InlineData("\" Yara\"")]
    [InlineData("\"1\"")]
    public void DetectionSource_RejectsAnythingButExactName(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<DetectionSource>(json));
    }

    [Fact]
    public void EscapedButExactName_IsAccepted()
    {
        // "\u004Cocked" is the JSON string "Locked"; the value, not the raw text, is compared.
        Assert.Equal(ScanStatus.Locked, JsonSerializer.Deserialize<ScanStatus>("\"\\u004Cocked\""));
    }

    [Fact]
    public void NullableEnum_ReadsNullAndExactNames()
    {
        Assert.Null(JsonSerializer.Deserialize<Verdict?>("null"));
        Assert.Equal(Verdict.Malicious, JsonSerializer.Deserialize<Verdict?>("\"Malicious\""));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Verdict?>("2"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Verdict?>("\"malicious\""));
    }

    [Fact]
    public void Write_UndefinedValue_ThrowsJsonException_InsteadOfWritingANumber()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize((ScanStatus)42));
        Assert.Throws<JsonException>(() => JsonSerializer.Serialize((Verdict)(-1)));
    }

    private static void AssertAllNames<T>() where T : struct, Enum
    {
        foreach (var value in Enum.GetValues<T>())
        {
            var json = JsonSerializer.Serialize(value);
            Assert.Equal($"\"{value}\"", json);
            Assert.Equal(value, JsonSerializer.Deserialize<T>(json));
        }
    }
}
