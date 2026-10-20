using SapAV.Core.Signatures;
using static SapAV.Core.Signatures.MicrosoftCodeSigningCertificates;

namespace SapAV.Core.Tests.Signatures;

/// <summary>
/// The Microsoft decision on synthetic chains: only the exact first-party shape (leaf, allowlisted issuing CA,
/// its product root, all by thumbprint) is Microsoft. Names never matter.
/// </summary>
public class MicrosoftSignerPolicyTests
{
    private const string MicrosoftWindowsLeaf = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
    private const string MicrosoftCorporationLeaf = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    private static int _counter;

    /// <summary>A certificate with fresh random-looking thumbprints (not any real certificate).</summary>
    private static SignatureCertificate Fake(string subject, string issuer = "CN=Some Issuer")
    {
        int n = Interlocked.Increment(ref _counter);
        return new SignatureCertificate(subject, issuer, $"{n:X8}".PadLeft(40, 'E'), $"{n:X8}".PadLeft(64, 'E'));
    }

    /// <summary>A certificate carrying a known certificate's thumbprints.</summary>
    private static SignatureCertificate Real(KnownCertificate known) =>
        new($"CN={known.Name}, O=Microsoft Corporation", "CN=whatever", known.Sha1, known.Sha256);

    private static SignatureStatus Classify(params SignatureCertificate[] chain) => MicrosoftSignerPolicy.Classify(chain).Status;

    // --- Microsoft: the allowlisted shapes ---

    public static TheoryData<string> FirstPartyIssuers() =>
        new(FirstPartyIssuingCas.Select(e => e.Certificate.Name));

    [Theory]
    [MemberData(nameof(FirstPartyIssuers))]
    public void EachFirstPartyIssuingCa_UnderItsOwnRoot_IsMicrosoft(string issuerName)
    {
        var entry = FirstPartyIssuingCas.Single(e => e.Certificate.Name == issuerName);

        var result = MicrosoftSignerPolicy.Classify([Fake(MicrosoftWindowsLeaf), Real(entry.Certificate), Real(entry.Root)]);

        Assert.Equal(SignatureStatus.Microsoft, result.Status);
        Assert.Contains(entry.Certificate.Name, result.Reason);
    }

    [Fact]
    public void NotepadLikeCatalogChain_IsMicrosoft()
    {
        Assert.Equal(SignatureStatus.Microsoft,
            Classify(Fake(MicrosoftWindowsLeaf), Real(WindowsProductionPca2011), Real(RootCa2010)));
    }

    [Fact]
    public void DotNetLikeEmbeddedChain_IsMicrosoft()
    {
        Assert.Equal(SignatureStatus.Microsoft,
            Classify(Fake("CN=.NET, O=Microsoft Corporation"), Real(CodeSigningPca2011), Real(RootCa2011)));
    }

    [Fact]
    public void LeafSubjectDoesNotMatter_WhenIssuerAndRootAreFirstParty()
    {
        // Only Microsoft can get a certificate from these CAs; the leaf name is irrelevant to the decision.
        Assert.Equal(SignatureStatus.Microsoft, Classify(Fake("CN=x"), Real(CodeSigningPca2024), Real(RootCa2011)));
    }

    // --- Third-party content signed by Microsoft-operated CAs ---

    [Theory]
    [InlineData("Microsoft Windows Third Party Component CA 2012")]
    [InlineData("Microsoft Windows Third Party Component CA 2014")]
    public void WhqlLikeChain_UnderRoot2010_IsOtherTrusted(string componentCa)
    {
        var ca = ThirdPartyContentCas.Single(k => k.Name == componentCa);
        var leaf = Fake("CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US");

        var result = MicrosoftSignerPolicy.Classify([leaf, Real(ca), Real(RootCa2010)]);

        Assert.Equal(SignatureStatus.OtherTrusted, result.Status);
        Assert.Contains("third-party", result.Reason);
    }

    [Fact]
    public void SoftwareCompatibilityPublisherChain_UnderRoot2011_IsOtherTrusted()
    {
        var leaf = Fake("CN=Microsoft Windows Software Compatibility Publisher, O=Microsoft Corporation");
        Assert.Equal(SignatureStatus.OtherTrusted, Classify(leaf, Real(ThirdPartyComponentCa2013), Real(RootCa2011)));
    }

    [Fact]
    public void MarketplaceChain_IsOtherTrusted()
    {
        // Store apps: leaf -> Marketplace Production CA 2011 -> MarketPlace PCA 2011 -> Root 2011.
        Assert.Equal(SignatureStatus.OtherTrusted,
            Classify(Fake(MicrosoftCorporationLeaf), Real(MarketplaceProductionCa2011), Real(MarketplacePca2011), Real(RootCa2011)));
    }

    [Fact]
    public void IdVerifiedLikeChain_IsOtherTrusted()
    {
        // Trusted/Artifact Signing: any verified customer, even one whose subject says "Microsoft Corporation".
        var leaf = Fake(MicrosoftCorporationLeaf);
        var eoc = Fake("CN=Microsoft ID Verified CS EOC CA 01, O=Microsoft Corporation, C=US");
        var root = Real(IdentityVerificationRoot2020);

        var result = MicrosoftSignerPolicy.Classify([leaf, eoc, root]);

        Assert.Equal(SignatureStatus.OtherTrusted, result.Status);
        Assert.Contains("Identity Verification", result.Reason);
    }

    [Fact]
    public void IdVerifiedLikeChain_WithIntermediatePcaLevel_IsOtherTrusted()
    {
        var chain = new[]
        {
            Fake(MicrosoftCorporationLeaf),
            Fake("CN=Microsoft ID Verified CS AOC CA 02, O=Microsoft Corporation, C=US"),
            Fake("CN=Microsoft ID Verified Code Signing PCA 2021, O=Microsoft Corporation, C=US"),
            Real(IdentityVerificationRoot2020),
        };

        Assert.Equal(SignatureStatus.OtherTrusted, Classify(chain));
    }

    // --- Product root, but not an allowlisted issuer ---

    [Fact]
    public void Root2010_WithNonAllowlistedIntermediate_IsOtherTrusted()
    {
        var result = MicrosoftSignerPolicy.Classify(
            [Fake(MicrosoftWindowsLeaf), Fake("CN=Some Other Microsoft CA, O=Microsoft Corporation"), Real(RootCa2010)]);

        Assert.Equal(SignatureStatus.OtherTrusted, result.Status);
        Assert.Contains("issuing CA", result.Reason);
    }

    [Fact]
    public void Root2010_WithIntermediateNamedLikeAnAllowlistedOne_ButOtherThumbprint_IsOtherTrusted()
    {
        var lookalike = Fake("CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US");
        Assert.Equal(SignatureStatus.OtherTrusted, Classify(Fake(MicrosoftWindowsLeaf), lookalike, Real(RootCa2010)));
    }

    [Fact]
    public void AllowlistedIssuer_UnderTheOtherProductRoot_IsOtherTrusted()
    {
        // Code Signing PCA 2011 belongs under Root 2011; the pair must match exactly.
        var result = MicrosoftSignerPolicy.Classify([Fake(MicrosoftCorporationLeaf), Real(CodeSigningPca2011), Real(RootCa2010)]);

        Assert.Equal(SignatureStatus.OtherTrusted, result.Status);
        Assert.Contains("expected under", result.Reason);
    }

    [Fact]
    public void AllowlistedIssuer_WithExtraCertificateInTheChain_IsOtherTrusted()
    {
        // A first-party chain is exactly leaf -> issuing CA -> root; a CA inserted below the PCA is not.
        Assert.Equal(SignatureStatus.OtherTrusted,
            Classify(Fake(MicrosoftWindowsLeaf), Fake("CN=Sub CA"), Real(WindowsProductionPca2011), Real(RootCa2010)));
    }

    [Fact]
    public void AllowlistedIssuer_AsTheLeaf_IsOtherTrusted()
    {
        Assert.Equal(SignatureStatus.OtherTrusted, Classify(Real(CodeSigningPca2011), Real(RootCa2011)));
    }

    // --- Name-only lookalikes ---

    [Fact]
    public void MicrosoftNamesEverywhere_UnderANonMicrosoftRoot_IsOtherTrusted()
    {
        var chain = new[]
        {
            Fake(MicrosoftCorporationLeaf),
            Fake("CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"),
            Fake("CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"),
        };

        var result = MicrosoftSignerPolicy.Classify(chain);

        Assert.Equal(SignatureStatus.OtherTrusted, result.Status);
        Assert.Contains("root", result.Reason);
    }

    [Fact]
    public void MicrosoftCorporationLeaf_UnderACommercialCa_IsOtherTrusted()
    {
        Assert.Equal(SignatureStatus.OtherTrusted,
            Classify(Fake(MicrosoftCorporationLeaf), Fake("CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"),
                Fake("CN=DigiCert Trusted Root G4")));
    }

    [Fact]
    public void Sha256Matches_ButSha1DoesNot_IsNotAMatch()
    {
        var spoofedRoot = new SignatureCertificate("CN=Microsoft Root Certificate Authority 2010", "CN=x",
            new string('A', 40), RootCa2010.Sha256);

        Assert.Equal(SignatureStatus.OtherTrusted, Classify(Fake(MicrosoftWindowsLeaf), Real(WindowsProductionPca2011), spoofedRoot));
    }

    [Fact]
    public void ThumbprintMatching_IsCaseInsensitive()
    {
        var lower = new SignatureCertificate("CN=x", "CN=y", WindowsProductionPca2011.Sha1.ToLowerInvariant(),
            WindowsProductionPca2011.Sha256.ToLowerInvariant());

        Assert.Equal(SignatureStatus.Microsoft, Classify(Fake(MicrosoftWindowsLeaf), lower, Real(RootCa2010)));
    }

    // --- Degenerate input ---

    [Fact]
    public void EmptyChain_IsOtherTrusted()
    {
        Assert.Equal(SignatureStatus.OtherTrusted, MicrosoftSignerPolicy.Classify([]).Status);
    }

    [Fact]
    public void SelfSignedLeafOnly_IsOtherTrusted()
    {
        Assert.Equal(SignatureStatus.OtherTrusted, Classify(Real(RootCa2010)));
    }

    [Fact]
    public void NullChain_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => MicrosoftSignerPolicy.Classify(null!));
    }

    // --- The constants themselves ---

    [Fact]
    public void Allowlist_HasNoOverlapWithThirdPartyList_AndRootsAreProductRoots()
    {
        var thirdParty = ThirdPartyContentCas.Select(k => k.Sha256).ToHashSet();
        Assert.DoesNotContain(FirstPartyIssuingCas, e => thirdParty.Contains(e.Certificate.Sha256));
        Assert.DoesNotContain(ProductRoots, r => thirdParty.Contains(r.Sha256));
        Assert.All(FirstPartyIssuingCas, e => Assert.Contains(e.Root, ProductRoots));
    }

    [Fact]
    public void AllThumbprints_AreWellFormed_AndUnique()
    {
        var all = ProductRoots.Concat(FirstPartyIssuingCas.Select(e => e.Certificate)).Concat(ThirdPartyContentCas).ToArray();

        Assert.All(all, k =>
        {
            Assert.Matches("^[0-9A-F]{40}$", k.Sha1);
            Assert.Matches("^[0-9A-F]{64}$", k.Sha256);
            Assert.False(string.IsNullOrWhiteSpace(k.VerifiedFrom));
        });
        Assert.Equal(all.Length, all.Select(k => k.Sha256).Distinct().Count());
        Assert.Equal(all.Length, all.Select(k => k.Sha1).Distinct().Count());
    }
}
