using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Signatures;

/// <summary>
/// Machine-readable reason a checked file is <see cref="SignatureStatus.UnsignedOrInvalid"/>
/// (<see cref="None"/> when the signature is trusted). Serialized to JSON by name.
/// </summary>
/// <remarks>
/// <see cref="NotSigned"/> ("never signed") is common and weak evidence. Everything else except
/// <see cref="Error"/> means a signature is present but broken, which is a strong signal for heuristics
/// (A5/A7); see <see cref="SignatureCheckResult.HasBrokenSignature"/>.
/// </remarks>
[JsonConverter(typeof(StrictEnumConverter<SignatureFailureReason>))]
public enum SignatureFailureReason
{
    /// <summary>Trusted signature (Status is Microsoft or OtherTrusted).</summary>
    None,

    /// <summary>
    /// No embedded signature and no catalog entry (TRUST_E_NOSIGNATURE), or a file type Windows can't sign
    /// (TRUST_E_SUBJECT_FORM_UNKNOWN).
    /// </summary>
    NotSigned,

    /// <summary>The file's hash doesn't match its signature: modified after signing (TRUST_E_BAD_DIGEST).</summary>
    HashMismatch,

    /// <summary>The chain doesn't end in a trusted root, or can't be built (CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, ...).</summary>
    UntrustedRoot,

    /// <summary>A certificate is expired and the signature has no valid timestamp (CERT_E_EXPIRED).</summary>
    Expired,

    /// <summary>
    /// A certificate is known to be revoked (CERT_E_REVOKED). Online revocation checks are off, so this only
    /// appears if Windows already has the information locally.
    /// </summary>
    Revoked,

    /// <summary>A certificate in the chain is in the Disallowed store (TRUST_E_EXPLICIT_DISTRUST).</summary>
    ExplicitlyDistrusted,

    /// <summary>The certificate isn't valid for code signing (CERT_E_WRONG_USAGE).</summary>
    WrongUsage,

    /// <summary>
    /// The signature or a certificate is malformed or its cryptographic signature is wrong (TRUST_E_CERT_SIGNATURE,
    /// bad timestamp, ASN.1 errors, TRUST_E_FAIL, ...).
    /// </summary>
    MalformedSignature,

    /// <summary>Local policy blocks the signature (CRYPT_E_SECURITY_SETTINGS), e.g. a disallowed algorithm.</summary>
    BlockedByPolicy,

    /// <summary>The check itself failed (unexpected HRESULT, read error, no trust provider). Not evidence either way.</summary>
    Error,
}
