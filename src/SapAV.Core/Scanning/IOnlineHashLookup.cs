using SapAV.Core.Models;
using SapAV.Core.Signatures;

namespace SapAV.Core.Scanning;

/// <summary>What <see cref="FileScanner"/> knows when it offers a hash to the online lookup.</summary>
/// <param name="Item">The file being scanned.</param>
/// <param name="Sha256">Its SHA-256 (lowercase hex). Only the hash is ever sent, never the file.</param>
/// <param name="SignatureStatus">Authenticode outcome, or null if not checked. Never Microsoft or OtherTrusted here.</param>
/// <param name="LocalVerdict">The worst verdict of the local steps (blocklist misses, YARA, heuristics).</param>
public sealed record OnlineLookupRequest(ScanItem Item, string Sha256, SignatureStatus? SignatureStatus, Verdict LocalVerdict);

/// <summary>
/// What the online lookup adds to a scan: a detection (VirusTotal flagged the file), a note (a non-answer such as rate limited,
/// no key or offline: review D2 M4, never a scan failure and never "Clean"), both, or nothing (not looked up).
/// </summary>
public sealed record OnlineLookupOutcome(Detection? Detection, ScanNote? Note)
{
    /// <summary>Not looked up, nothing to add.</summary>
    public static OnlineLookupOutcome None { get; } = new(null, null);
}

/// <summary>
/// Seam for the VirusTotal hash lookup (D2/D3). <see cref="FileScanner"/> calls it only for files without a trusted
/// signature (Microsoft and OtherTrusted are never looked up, ROADMAP feature 3), after the local steps. The
/// implementation decides the rest of the policy (risky extensions, Suspicious-only for scans, rate limits,
/// cache). It must not throw for network errors: those become a <see cref="OnlineLookupOutcome.Note"/>.
/// </summary>
public interface IOnlineHashLookup
{
    Task<OnlineLookupOutcome> LookupAsync(OnlineLookupRequest request, CancellationToken cancellationToken = default);
}
