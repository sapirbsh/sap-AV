using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Signatures;

/// <summary>
/// Checks the hard-coded thumbprints against real certificates on the machine running the tests, so a typo
/// can't silently break (or widen) the Microsoft decision. A certificate missing from the local stores (trimmed
/// image, root-store policy, fresh CI profile) makes the test Skipped, never failed; a present one must match.
/// </summary>
public class MicrosoftCertificateThumbprintTests(ITestOutputHelper output)
{
    private CertificateStores.StoreCertificate? FindInStores(string sha1) => CertificateStores.Find(sha1, output.WriteLine);

    private static void AssertMatches(KnownCertificate known, CertificateStores.StoreCertificate certificate)
    {
        Assert.Equal(known.Sha1, certificate.Sha1);
        Assert.Equal(known.Sha256, certificate.Sha256);
        Assert.Equal(known.Name, certificate.Name);
    }

    [RequiresFact(Requires.RootCa2010InStore)]
    public void RootCa2010_InTheLocalStores_HasMatchingSha256AndName()
    {
        var known = MicrosoftCodeSigningCertificates.RootCa2010;
        var certificate = FindInStores(known.Sha1);

        Assert.NotNull(certificate);
        AssertMatches(known, certificate);
    }

    [RequiresFact(Requires.RootCa2011InStore)]
    public void RootCa2011_InTheLocalStores_HasMatchingSha256AndName()
    {
        var known = MicrosoftCodeSigningCertificates.RootCa2011;
        var certificate = FindInStores(known.Sha1);

        Assert.NotNull(certificate);
        AssertMatches(known, certificate);
    }

    [Fact]
    public void ProductRoots_AreExactlyRoot2010AndRoot2011()
    {
        // Guards the two per-root tests above: if a product root is added, it needs its own store test.
        Assert.Equal(
            [MicrosoftCodeSigningCertificates.RootCa2010, MicrosoftCodeSigningCertificates.RootCa2011],
            MicrosoftCodeSigningCertificates.ProductRoots);
    }

    [Fact]
    public void ACertificateMissingFromEveryStore_IsNotFound_WithoutThrowing()
    {
        // Lookup of a thumbprint no store has (the missing-CA case) returns null instead of failing.
        Assert.Null(FindInStores(new string('0', 40)));
    }

    [Fact]
    public void MissingCaInStores_MakesTheRequirementUnmet_WithAReason()
    {
        // The skip mechanism itself: an unmet requirement yields a reason (Skipped), not an exception.
        var reason = TestRequirements.SkipReason([Requires.RootCa2010InStore], simulateCleanMachine: true);

        Assert.NotNull(reason);
        Assert.Contains(nameof(Requires.RootCa2010InStore), reason);
    }

    [RequiresFact(Requires.AnyKnownCertificateInStore)]
    public void EveryKnownCertificateFoundInAStore_HasMatchingSha256AndName()
    {
        var all = MicrosoftCodeSigningCertificates.ProductRoots
            .Concat(MicrosoftCodeSigningCertificates.FirstPartyIssuingCas.Select(e => e.Certificate))
            .Concat(MicrosoftCodeSigningCertificates.ThirdPartyContentCas);

        int checkedCount = 0;
        foreach (var known in all)
        {
            var certificate = FindInStores(known.Sha1);
            if (certificate is null)
            {
                output.WriteLine($"not in a local store (only seen in file chains): {known.Name}");
                continue;
            }

            AssertMatches(known, certificate);
            checkedCount++;
        }

        Assert.True(checkedCount > 0, "the requirement probe found a known certificate, but none was checked");
        output.WriteLine($"checked against store certificates: {checkedCount}");
    }

    [Fact]
    public void FirstPartyIssuer_OfACatalogSignedWindowsBinary_IsIssuedByItsRoot()
    {
        // Hard requirement: System32\cmd.exe is catalog-signed by Microsoft on every supported Windows.
        AssertFirstPartyChain(SignedSamples.RequireCatalogOnlyWindowsBinary());
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void FirstPartyIssuer_OfAnEmbeddedSignedRuntimeDll_IsIssuedByItsRoot()
    {
        AssertFirstPartyChain(SignedSamples.RequireEmbeddedSignedMicrosoftDll());
    }

    /// <summary>The chain of a real Microsoft file shows its allowlisted issuer directly under its listed root.</summary>
    private void AssertFirstPartyChain(string path)
    {
        var result = new AuthenticodeVerifier().Verify(path);
        Assert.True(result.IsTrusted, $"{path}: {result.FailureReason} {result.Message}");
        var chain = result.Signer.Chain;
        output.WriteLine($"{path}: {string.Join(" <- ", chain.Select(c => c.CommonName))}");

        Assert.Equal(3, chain.Count);
        var entry = MicrosoftCodeSigningCertificates.FirstPartyIssuingCas.Single(e => e.Certificate.Matches(chain[1]));
        Assert.True(entry.Root.Matches(chain[2]));
        Assert.Equal(chain[2].Subject, chain[1].Issuer);
    }
}
