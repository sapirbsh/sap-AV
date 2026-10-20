using System.Diagnostics.CodeAnalysis;
using SapAV.Core.Hashing;

namespace SapAV.Core.Signatures;

/// <summary>
/// Outcome of an Authenticode check (<see cref="ISignatureVerifier"/>).
/// </summary>
/// <remarks>
/// <para>
/// Invariants (all properties are get-only, so <c>with</c> can't break them):
/// <list type="bullet">
/// <item>Not checked (<see cref="IsChecked"/> false): <see cref="Status"/> is <c>null</c>,
/// <see cref="NotCheckedReason"/> says why (reusing <see cref="HashFailureReason"/>: TooLarge, Directory,
/// NotRegularFile, Offline, ...), <see cref="FailureReason"/> is None, <see cref="Kind"/> is None and there
/// is no signer. The pipeline treats it like UnsignedOrInvalid (all steps run).</item>
/// <item>Microsoft / OtherTrusted: <see cref="FailureReason"/> is None, <see cref="Kind"/> is Embedded or
/// Catalog, and <see cref="Signer"/> is set.</item>
/// <item>UnsignedOrInvalid: <see cref="FailureReason"/> is not None. For NotSigned, <see cref="Kind"/> is None
/// and there is no signer. For a broken signature, <see cref="Kind"/> says which signature failed and
/// <see cref="Signer"/> may hold what it claims (untrusted).</item>
/// </list>
/// </para>
/// </remarks>
public sealed record SignatureCheckResult
{
    private SignatureCheckResult(
        SignatureStatus? status,
        SignatureFailureReason failureReason,
        HashFailureReason notCheckedReason,
        SignatureKind kind,
        SignatureSigner? signer,
        string? catalogPath,
        int trustResult,
        string? message)
    {
        Status = status;
        FailureReason = failureReason;
        NotCheckedReason = notCheckedReason;
        Kind = kind;
        Signer = signer;
        CatalogPath = catalogPath;
        TrustResult = trustResult;
        Message = message;
    }

    /// <summary>Microsoft / OtherTrusted / UnsignedOrInvalid; <c>null</c> when the file was not checked.</summary>
    public SignatureStatus? Status { get; }

    /// <summary>Why the file is UnsignedOrInvalid; None otherwise (also when not checked).</summary>
    public SignatureFailureReason FailureReason { get; }

    /// <summary>Why the file was not checked; None when it was.</summary>
    public HashFailureReason NotCheckedReason { get; }

    /// <summary>Which signature decided the result (Embedded / Catalog), or None.</summary>
    public SignatureKind Kind { get; }

    /// <summary>The signer and chain, when Windows could read them (see <see cref="SignatureSigner"/>).</summary>
    public SignatureSigner? Signer { get; }

    /// <summary>For catalog results: the full path of the matching <c>.cat</c> file.</summary>
    public string? CatalogPath { get; }

    /// <summary>
    /// The HRESULT from WinVerifyTrust for the signature that decided the result (0 = trusted). 0 when not
    /// checked, and TRUST_E_NOSIGNATURE (0x800B0100) for NotSigned. For diagnostics; use <see cref="FailureReason"/> in logic.
    /// </summary>
    public int TrustResult { get; }

    /// <summary>Human-readable detail for logs (the classification reason, or what failed).</summary>
    public string? Message { get; }

    /// <summary>True if the file was checked (<see cref="Status"/> is not null).</summary>
    [MemberNotNullWhen(true, nameof(Status))]
    public bool IsChecked => Status is not null;

    /// <summary>True for Microsoft and OtherTrusted.</summary>
    [MemberNotNullWhen(true, nameof(Signer))]
    public bool IsTrusted => Status is SignatureStatus.Microsoft or SignatureStatus.OtherTrusted;

    /// <summary>
    /// A signature is present but doesn't verify (tampered, untrusted, expired, distrusted, malformed, ...),
    /// as opposed to never signed or a failed check. A strong signal for heuristics.
    /// </summary>
    public bool HasBrokenSignature =>
        Status == SignatureStatus.UnsignedOrInvalid
        && FailureReason is not (SignatureFailureReason.NotSigned or SignatureFailureReason.Error);

    /// <summary>The signer common name for trusted results (safe to show as "signed by"); otherwise <c>null</c>.</summary>
    public string? TrustedSignerName => IsTrusted ? Signer.CommonName : null;

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="status"/> is not Microsoft or OtherTrusted, or <paramref name="kind"/> is None.</exception>
    public static SignatureCheckResult Trusted(
        SignatureStatus status, SignatureKind kind, SignatureSigner signer, string? catalogPath = null, string? message = null)
    {
        if (status is not (SignatureStatus.Microsoft or SignatureStatus.OtherTrusted))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "A trusted result is Microsoft or OtherTrusted.");
        }

        if (kind is not (SignatureKind.Embedded or SignatureKind.Catalog))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "A trusted result is Embedded or Catalog.");
        }

        ArgumentNullException.ThrowIfNull(signer);
        return new(status, SignatureFailureReason.None, HashFailureReason.None, kind, signer, catalogPath, 0, message);
    }

    /// <summary>No embedded signature and no catalog entry.</summary>
    public static SignatureCheckResult NotSigned(string? message = null) =>
        new(SignatureStatus.UnsignedOrInvalid, SignatureFailureReason.NotSigned, HashFailureReason.None,
            SignatureKind.None, null, null, unchecked((int)0x800B0100), message);

    /// <summary>A signature that doesn't verify, or a check that failed (<see cref="SignatureFailureReason.Error"/>).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None, NotSigned or undefined.</exception>
    public static SignatureCheckResult Invalid(
        SignatureFailureReason reason, SignatureKind kind, int trustResult,
        SignatureSigner? signer = null, string? catalogPath = null, string? message = null)
    {
        if (!Enum.IsDefined(reason) || reason is SignatureFailureReason.None or SignatureFailureReason.NotSigned)
        {
            throw new ArgumentOutOfRangeException(nameof(reason), reason, "Use Trusted() or NotSigned().");
        }

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Undefined signature kind.");
        }

        return new(SignatureStatus.UnsignedOrInvalid, reason, HashFailureReason.None, kind, signer, catalogPath, trustResult, message);
    }

    /// <summary>The file was not checked (too large, a directory, a device, offline, ...).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None or undefined.</exception>
    public static SignatureCheckResult NotChecked(HashFailureReason reason, string? message = null)
    {
        if (!Enum.IsDefined(reason) || reason == HashFailureReason.None)
        {
            throw new ArgumentOutOfRangeException(nameof(reason), reason, "A not-checked result needs a reason.");
        }

        return new(null, SignatureFailureReason.None, reason, SignatureKind.None, null, null, 0, message);
    }
}
