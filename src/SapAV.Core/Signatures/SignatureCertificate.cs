using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SapAV.Core.Signatures;

/// <summary>
/// One certificate of a signer chain, reduced to what classification and logging need. Thumbprints are
/// uppercase hex (the form Windows shows), SHA-1 over the DER encoding (Windows' "Thumbprint") and SHA-256.
/// </summary>
/// <remarks>
/// Built from real certificates by the verifier, or directly in tests to describe synthetic chains.
/// Thumbprints are normalized to uppercase; anything that isn't 40 / 64 hex characters throws.
/// </remarks>
public sealed record SignatureCertificate
{
    public SignatureCertificate(
        string subject, string issuer, string sha1Thumbprint, string sha256Thumbprint,
        DateTime notBeforeUtc = default, DateTime notAfterUtc = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        Subject = subject;
        Issuer = issuer;
        Sha1Thumbprint = NormalizeHex(sha1Thumbprint, 40, nameof(sha1Thumbprint));
        Sha256Thumbprint = NormalizeHex(sha256Thumbprint, 64, nameof(sha256Thumbprint));
        NotBeforeUtc = notBeforeUtc;
        NotAfterUtc = notAfterUtc;
    }

    /// <summary>Subject distinguished name, e.g. <c>CN=Microsoft Windows, O=Microsoft Corporation, ...</c>.</summary>
    public string Subject { get; }

    /// <summary>Issuer distinguished name.</summary>
    public string Issuer { get; }

    /// <summary>SHA-1 thumbprint, 40 uppercase hex characters.</summary>
    public string Sha1Thumbprint { get; }

    /// <summary>SHA-256 thumbprint, 64 uppercase hex characters.</summary>
    public string Sha256Thumbprint { get; }

    public DateTime NotBeforeUtc { get; }

    public DateTime NotAfterUtc { get; }

    /// <summary>The subject's common name (CN), or the full subject if it has none.</summary>
    public string CommonName => TryGetCommonName(Subject) ?? Subject;

    internal static SignatureCertificate FromCertificate(X509Certificate2 certificate) => new(
        certificate.Subject,
        certificate.Issuer,
        certificate.Thumbprint,
        Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
        certificate.NotBefore.ToUniversalTime(),
        certificate.NotAfter.ToUniversalTime());

    private static string NormalizeHex(string value, int length, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        if (value.Length != length || !value.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException($"Thumbprint must be {length} hexadecimal characters.", paramName);
        }

        return value.ToUpperInvariant();
    }

    /// <summary>Reads <c>CN=</c> from an X.500 name as formatted by .NET (handles quoted values).</summary>
    private static string? TryGetCommonName(string distinguishedName)
    {
        try
        {
            var name = new X500DistinguishedName(distinguishedName);
            foreach (var rdn in name.EnumerateRelativeDistinguishedNames())
            {
                if (!rdn.HasMultipleElements && rdn.GetSingleElementType().Value == "2.5.4.3")
                {
                    return rdn.GetSingleElementValue();
                }
            }
        }
        catch (CryptographicException)
        {
            // Not a parseable name (e.g. free text in a synthetic test chain): no CN.
        }

        return null;
    }
}
