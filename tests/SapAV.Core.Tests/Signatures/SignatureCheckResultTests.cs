using System.Text.Json;
using SapAV.Core.Hashing;
using SapAV.Core.Signatures;

namespace SapAV.Core.Tests.Signatures;

/// <summary>Factory invariants of <see cref="SignatureCheckResult"/>, the detail records, and the enums' JSON form.</summary>
public class SignatureCheckResultTests
{
    private static readonly SignatureCertificate Leaf = new(
        "CN=Microsoft Windows, O=Microsoft Corporation", "CN=Issuer", new string('1', 40), new string('2', 64));

    private static readonly SignatureSigner Signer = new([Leaf], DateTimeOffset.UnixEpoch);

    [Theory]
    [InlineData(SignatureStatus.Microsoft)]
    [InlineData(SignatureStatus.OtherTrusted)]
    public void Trusted_HasSignerAndNoFailure(SignatureStatus status)
    {
        var r = SignatureCheckResult.Trusted(status, SignatureKind.Catalog, Signer, @"C:\x.cat");

        Assert.True(r.IsChecked);
        Assert.True(r.IsTrusted);
        Assert.False(r.HasBrokenSignature);
        Assert.Equal(status, r.Status);
        Assert.Equal(SignatureFailureReason.None, r.FailureReason);
        Assert.Equal(HashFailureReason.None, r.NotCheckedReason);
        Assert.Equal("Microsoft Windows", r.TrustedSignerName);
    }

    [Fact]
    public void Trusted_RejectsBadArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SignatureCheckResult.Trusted(SignatureStatus.UnsignedOrInvalid, SignatureKind.Embedded, Signer));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SignatureCheckResult.Trusted(SignatureStatus.Microsoft, SignatureKind.None, Signer));
        Assert.Throws<ArgumentNullException>(() =>
            SignatureCheckResult.Trusted(SignatureStatus.Microsoft, SignatureKind.Embedded, null!));
    }

    [Fact]
    public void NotSigned_IsUnsignedOrInvalid_ButNotBroken()
    {
        var r = SignatureCheckResult.NotSigned();

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, r.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, r.FailureReason);
        Assert.False(r.HasBrokenSignature);
        Assert.False(r.IsTrusted);
        Assert.Null(r.Signer);
    }

    [Theory]
    [InlineData(SignatureFailureReason.HashMismatch, true)]
    [InlineData(SignatureFailureReason.UntrustedRoot, true)]
    [InlineData(SignatureFailureReason.Expired, true)]
    [InlineData(SignatureFailureReason.Revoked, true)]
    [InlineData(SignatureFailureReason.ExplicitlyDistrusted, true)]
    [InlineData(SignatureFailureReason.MalformedSignature, true)]
    [InlineData(SignatureFailureReason.Error, false)]
    public void Invalid_BrokenVsError(SignatureFailureReason reason, bool broken)
    {
        var r = SignatureCheckResult.Invalid(reason, SignatureKind.Embedded, -1, Signer);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, r.Status);
        Assert.Equal(broken, r.HasBrokenSignature);
        Assert.Null(r.TrustedSignerName); // the claimed signer of a broken signature is never shown as trusted
        Assert.NotNull(r.Signer);
    }

    [Theory]
    [InlineData(SignatureFailureReason.None)]
    [InlineData(SignatureFailureReason.NotSigned)]
    [InlineData((SignatureFailureReason)99)]
    public void Invalid_RejectsNonFailureReasons(SignatureFailureReason reason)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SignatureCheckResult.Invalid(reason, SignatureKind.Embedded, 0));
    }

    [Fact]
    public void NotChecked_HasNoStatusOrSigner()
    {
        var r = SignatureCheckResult.NotChecked(HashFailureReason.TooLarge);

        Assert.False(r.IsChecked);
        Assert.Null(r.Status);
        Assert.False(r.HasBrokenSignature);
        Assert.Throws<ArgumentOutOfRangeException>(() => SignatureCheckResult.NotChecked(HashFailureReason.None));
    }

    [Fact]
    public void Certificate_NormalizesThumbprints_AndReadsQuotedCommonName()
    {
        var c = new SignatureCertificate("CN=\"Now.gg, INC\", O=\"Now.gg, INC\", C=US", "CN=x",
            new string('a', 40), new string('b', 64));

        Assert.Equal(new string('A', 40), c.Sha1Thumbprint);
        Assert.Equal(new string('B', 64), c.Sha256Thumbprint);
        Assert.Equal("Now.gg, INC", c.CommonName);
    }

    [Theory]
    [InlineData("ABC", "0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("000000000000000000000000000000000000000G", "0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0000000000000000000000000000000000000000", "00")]
    public void Certificate_RejectsMalformedThumbprints(string sha1, string sha256)
    {
        Assert.Throws<ArgumentException>(() => new SignatureCertificate("CN=a", "CN=b", sha1, sha256));
    }

    [Fact]
    public void Signer_RequiresAChain_AndComparesByValue()
    {
        Assert.Throws<ArgumentException>(() => new SignatureSigner([], null));
        Assert.Equal(new SignatureSigner([Leaf], null), new SignatureSigner([Leaf with { }], null));
        Assert.NotEqual(new SignatureSigner([Leaf], null), new SignatureSigner([Leaf], DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void Enums_SerializeByName_AndRejectNumbers()
    {
        Assert.Equal("\"OtherTrusted\"", JsonSerializer.Serialize(SignatureStatus.OtherTrusted));
        Assert.Equal("\"HashMismatch\"", JsonSerializer.Serialize(SignatureFailureReason.HashMismatch));
        Assert.Equal("\"Catalog\"", JsonSerializer.Serialize(SignatureKind.Catalog));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SignatureStatus>("0"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SignatureStatus>("\"microsoft\""));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SignatureFailureReason>("1"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SignatureKind>("\"catalog\""));
    }
}
