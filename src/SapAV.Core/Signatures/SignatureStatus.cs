using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Signatures;

/// <summary>
/// What the Authenticode check means for the detection pipeline (ROADMAP.md, feature 2). Serialized to JSON by name.
/// </summary>
/// <remarks>
/// These three values are all the pipeline (A7) branches on. Why a file is <see cref="UnsignedOrInvalid"/>
/// ("never signed" vs "signature broken") is in <see cref="SignatureCheckResult.FailureReason"/>.
/// </remarks>
[JsonConverter(typeof(StrictEnumConverter<SignatureStatus>))]
public enum SignatureStatus
{
    /// <summary>
    /// A valid signature (embedded or Windows catalog) from Microsoft's own code-signing CAs, decided by
    /// certificate thumbprints (see <see cref="MicrosoftSignerPolicy"/>), never by name. Skips all later steps.
    /// </summary>
    Microsoft,

    /// <summary>
    /// Any other valid, trusted signature, including third-party content that Microsoft signs on someone
    /// else's behalf (WHQL/attestation drivers, Store/Marketplace apps, Trusted/Artifact Signing). Skips
    /// VirusTotal only.
    /// </summary>
    OtherTrusted,

    /// <summary>No signature, or a signature that does not verify. All steps run.</summary>
    UnsignedOrInvalid,
}
