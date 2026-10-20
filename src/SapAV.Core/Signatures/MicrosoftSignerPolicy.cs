namespace SapAV.Core.Signatures;

/// <summary>Outcome of <see cref="MicrosoftSignerPolicy.Classify"/>, with a short reason for logs.</summary>
public sealed record SignerClassification(SignatureStatus Status, string Reason);

/// <summary>
/// Decides whether a <b>valid, trusted</b> signature counts as Microsoft first-party, from the chain
/// WinVerifyTrust built. Pure logic on thumbprints, so it is unit-testable with synthetic chains.
/// </summary>
/// <remarks>
/// <para>
/// Microsoft's product roots also sign third-party content: WHQL/attestation drivers ("Microsoft Windows
/// Hardware Compatibility Publisher" under the Third Party Component CAs) and Store/Marketplace apps. And
/// Trusted/Artifact Signing signs any verified customer's files under Microsoft's Identity Verification root.
/// A root check alone, or any name check, would let all of that skip scanning. So a chain is
/// <see cref="SignatureStatus.Microsoft"/> only when <b>all</b> of these hold:
/// </para>
/// <list type="number">
/// <item>it has exactly three certificates: signing certificate, issuing CA, root;</item>
/// <item>the root is a product root (<see cref="MicrosoftCodeSigningCertificates.ProductRoots"/>), matched by
/// SHA-256 <b>and</b> SHA-1 thumbprint;</item>
/// <item>the issuing CA is a first-party code-signing CA
/// (<see cref="MicrosoftCodeSigningCertificates.FirstPartyIssuingCas"/>), matched the same way, and that
/// entry's root is this chain's root;</item>
/// <item>no certificate in the chain is a known third-party-content CA
/// (<see cref="MicrosoftCodeSigningCertificates.ThirdPartyContentCas"/>), as a second, explicit guard.</item>
/// </list>
/// Everything else is <see cref="SignatureStatus.OtherTrusted"/>. Subject and issuer names are never consulted.
/// Callers must only pass chains of signatures that already verified; this class does not verify anything.
/// </remarks>
public static class MicrosoftSignerPolicy
{
    /// <param name="chain">Signing certificate first, root last, as built by WinVerifyTrust.</param>
    public static SignerClassification Classify(IReadOnlyList<SignatureCertificate> chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        if (chain.Count == 0)
        {
            return Other("empty chain");
        }

        foreach (var certificate in chain)
        {
            var thirdParty = MicrosoftCodeSigningCertificates.ThirdPartyContentCas.FirstOrDefault(k => k.Matches(certificate));
            if (thirdParty is not null)
            {
                return Other($"chain contains '{thirdParty.Name}', which signs third-party content");
            }
        }

        if (chain.Count != 3)
        {
            return Other($"chain has {chain.Count} certificates; Microsoft first-party chains have exactly 3");
        }

        var root = MicrosoftCodeSigningCertificates.ProductRoots.FirstOrDefault(k => k.Matches(chain[2]));
        if (root is null)
        {
            return Other("root is not a Microsoft product root (by thumbprint)");
        }

        var issuing = MicrosoftCodeSigningCertificates.FirstPartyIssuingCas.FirstOrDefault(e => e.Certificate.Matches(chain[1]));
        if (issuing is null)
        {
            return Other($"issuing CA is not a Microsoft first-party code-signing CA (by thumbprint) under '{root.Name}'");
        }

        if (!ReferenceEquals(issuing.Root, root))
        {
            return Other($"'{issuing.Certificate.Name}' is expected under '{issuing.Root.Name}', not '{root.Name}'");
        }

        return new SignerClassification(SignatureStatus.Microsoft, $"issued by '{issuing.Certificate.Name}' under '{root.Name}'");
    }

    private static SignerClassification Other(string reason) => new(SignatureStatus.OtherTrusted, reason);
}
