using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Models;
using SapAV.Core.Signatures;

namespace SapAV.Core.Tests.Models;

/// <summary>
/// The optional signature status and signer on <see cref="ScanResult"/> (A1 review carry-over, added in A3):
/// non-breaking, JSON round-trips, never on a NotScanned result, signer only with a trusted signature.
/// </summary>
public class ScanResultSignatureTests
{
    private static readonly ScanItem Item = new(@"C:\Windows\System32\cmd.exe", ScanTrigger.QuickScan);
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);
    private const string Sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static T RoundTrip<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value))!;

    [Fact]
    public void ExistingCallers_GetNoSignatureInfo()
    {
        var clean = ScanResult.Clean(Item, Now, Sha);
        var scanned = new ScanResult(Item, [], Now, Sha);

        Assert.Null(clean.SignatureStatus);
        Assert.Null(clean.Signer);
        Assert.Null(scanned.SignatureStatus);
    }

    [Fact]
    public void Clean_MicrosoftSigned_RoundTrips()
    {
        var result = ScanResult.Clean(Item, Now, Sha, SignatureStatus.Microsoft, "Microsoft Windows");

        var copy = RoundTrip(result);

        Assert.Equal(result, copy);
        Assert.Equal(SignatureStatus.Microsoft, copy.SignatureStatus);
        Assert.Equal("Microsoft Windows", copy.Signer);
        Assert.Equal(Verdict.Clean, copy.Verdict);
    }

    [Fact]
    public void WithDetections_AndUnsigned_RoundTrips()
    {
        var detection = new Detection(Verdict.Suspicious, "Double extension", "T1036.007", DetectionSource.Heuristic);
        var result = new ScanResult(Item, [detection], Now, Sha, signatureStatus: SignatureStatus.UnsignedOrInvalid);

        Assert.Equal(result, RoundTrip(result));
    }

    [Fact]
    public void Serialized_UsesTheEnumName()
    {
        var json = JsonSerializer.Serialize(ScanResult.Clean(Item, Now, signatureStatus: SignatureStatus.OtherTrusted, signer: "Google LLC"));
        var node = JsonNode.Parse(json)!;

        Assert.Equal("OtherTrusted", node["SignatureStatus"]!.GetValue<string>());
        Assert.Equal("Google LLC", node["Signer"]!.GetValue<string>());
    }

    [Fact]
    public void OlderJson_WithoutSignatureProperties_StillReads()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now, Sha)))!.AsObject();
        node.Remove("SignatureStatus");
        node.Remove("Signer");

        var copy = JsonSerializer.Deserialize<ScanResult>(node.ToJsonString())!;

        Assert.Null(copy.SignatureStatus);
        Assert.Equal(ScanResult.Clean(Item, Now, Sha), copy);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("\"microsoft\"")]
    [InlineData("\"Signed\"")]
    public void InvalidSignatureStatusInJson_IsJsonException(string value)
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now)))!;
        node["SignatureStatus"] = JsonNode.Parse(value);

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScanResult>(node.ToJsonString()));
    }

    [Fact]
    public void NotScanned_HasNoSignatureInfo_AndRejectsIt()
    {
        var notScanned = ScanResult.NotScanned(Item, ScanStatus.SkippedTooLarge, Now);
        Assert.Null(notScanned.SignatureStatus);
        Assert.Null(notScanned.Signer);

        Assert.Throws<ArgumentException>(() => notScanned with { SignatureStatus = SignatureStatus.Microsoft });
        Assert.Throws<ArgumentException>(() =>
            new ScanResult(Item, [], Now, null, ScanStatus.Locked, SignatureStatus.UnsignedOrInvalid));
    }

    [Fact]
    public void NotScannedJson_WithSignatureInfo_IsRejected()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.NotScanned(Item, ScanStatus.Locked, Now)))!;
        node["SignatureStatus"] = "Microsoft";

        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<ScanResult>(node.ToJsonString()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(SignatureStatus.UnsignedOrInvalid)]
    public void Signer_RequiresATrustedStatus(SignatureStatus? status)
    {
        Assert.Throws<ArgumentException>(() => ScanResult.Clean(Item, Now, signatureStatus: status, signer: "Evil Corp"));
    }

    [Fact]
    public void Constructor_RejectsSigner_WithUnsignedOrInvalid()
    {
        Assert.Throws<ArgumentException>(() =>
            new ScanResult(Item, [], Now, Sha, signatureStatus: SignatureStatus.UnsignedOrInvalid, signer: "Microsoft Windows"));
    }

    [Fact]
    public void Json_WithSigner_AndUnsignedOrInvalid_IsRejected()
    {
        // A tampered log/pipe message must not be able to show "signed by Microsoft Windows" on an unsigned file.
        var node = JsonNode.Parse(JsonSerializer.Serialize(
            ScanResult.Clean(Item, Now, Sha, SignatureStatus.Microsoft, "Microsoft Windows")))!;
        node["SignatureStatus"] = "UnsignedOrInvalid";

        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<ScanResult>(node.ToJsonString()));
    }

    [Fact]
    public void Json_WithSigner_AndNoSignatureStatus_IsRejected()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(ScanResult.Clean(Item, Now, Sha)))!;
        node["Signer"] = "Microsoft Windows";

        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<ScanResult>(node.ToJsonString()));
    }

    [Fact]
    public void Signer_CannotBeKeptWhenTheStatusBecomesUntrusted()
    {
        var trusted = ScanResult.Clean(Item, Now, signatureStatus: SignatureStatus.OtherTrusted, signer: "Google LLC");

        Assert.Throws<ArgumentException>(() => trusted with { SignatureStatus = SignatureStatus.UnsignedOrInvalid });
        Assert.Throws<ArgumentException>(() => trusted with { SignatureStatus = null });
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankSigner_IsRejected(string signer)
    {
        Assert.Throws<ArgumentException>(() => ScanResult.Clean(Item, Now, signatureStatus: SignatureStatus.Microsoft, signer: signer));
    }

    [Fact]
    public void UndefinedSignatureStatus_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ScanResult.Clean(Item, Now, signatureStatus: (SignatureStatus)42));
    }

    [Fact]
    public void Equality_IncludesSignatureInfo()
    {
        var a = ScanResult.Clean(Item, Now, Sha, SignatureStatus.Microsoft, "Microsoft Windows");
        var b = ScanResult.Clean(Item, Now, Sha, SignatureStatus.OtherTrusted, "Microsoft Windows");
        var c = ScanResult.Clean(Item, Now, Sha, SignatureStatus.Microsoft, ".NET");
        var d = ScanResult.Clean(Item, Now, Sha, SignatureStatus.Microsoft, "Microsoft Windows");

        Assert.NotEqual(a, b);
        Assert.NotEqual(a, c);
        Assert.Equal(a, d);
        Assert.Equal(a.GetHashCode(), d.GetHashCode());
    }
}
