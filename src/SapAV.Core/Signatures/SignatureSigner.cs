namespace SapAV.Core.Signatures;

/// <summary>
/// The signer of the signature that was checked: the certificate chain WinVerifyTrust built (signing
/// certificate first, root last) and the countersignature (timestamp) time, if any.
/// </summary>
/// <remarks>
/// Present on trusted results, and on broken signatures when Windows could still read the signer (e.g. a
/// hash mismatch). For a broken signature these names are claims by whoever made the file, not facts;
/// only <see cref="SignatureCheckResult.TrustedSignerName"/> is safe to show as "signed by".
/// </remarks>
public sealed record SignatureSigner
{
    public SignatureSigner(IReadOnlyList<SignatureCertificate> chain, DateTimeOffset? timestamp)
    {
        ArgumentNullException.ThrowIfNull(chain);
        var copy = chain.ToArray();
        if (copy.Length == 0 || Array.Exists(copy, c => c is null))
        {
            throw new ArgumentException("The chain must contain at least the signing certificate and no nulls.", nameof(chain));
        }

        Chain = Array.AsReadOnly(copy);
        Timestamp = timestamp;
    }

    /// <summary>Signing certificate first, then intermediates, then the root.</summary>
    public IReadOnlyList<SignatureCertificate> Chain { get; }

    /// <summary>
    /// The time the signature was verified as of when it has a countersignature (timestamp): that is the
    /// timestamp's time. <c>null</c> if the signature isn't timestamped (it was verified as of now).
    /// </summary>
    public DateTimeOffset? Timestamp { get; }

    /// <summary>The signing (leaf) certificate.</summary>
    public SignatureCertificate Certificate => Chain[0];

    /// <summary>Signer common name, e.g. "Microsoft Windows".</summary>
    public string CommonName => Certificate.CommonName;

    /// <summary>Signer subject distinguished name.</summary>
    public string Subject => Certificate.Subject;

    /// <summary>Issuer distinguished name of the signing certificate.</summary>
    public string Issuer => Certificate.Issuer;

    /// <summary>SHA-1 thumbprint of the signing certificate (uppercase hex).</summary>
    public string Thumbprint => Certificate.Sha1Thumbprint;

    /// <summary>Value equality, comparing <see cref="Chain"/> element by element.</summary>
    public bool Equals(SignatureSigner? other) =>
        other is not null
        && (ReferenceEquals(this, other) || (Timestamp == other.Timestamp && Chain.SequenceEqual(other.Chain)));

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Timestamp);
        foreach (var certificate in Chain)
        {
            hash.Add(certificate);
        }

        return hash.ToHashCode();
    }
}
