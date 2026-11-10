using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;

namespace SapAV.Engine.VirusTotal;

/// <summary>Whether a file's hash is offered to VirusTotal (<see cref="OnlineLookupPolicy.Decide"/>).</summary>
public enum OnlineLookupDecision
{
    Query,

    /// <summary>Microsoft- or otherwise trusted-signed: never sent (ROADMAP feature 3).</summary>
    TrustedSignature,

    /// <summary>The local engine already says Malicious: nothing to add, the budget is kept for others.</summary>
    AlreadyMalicious,

    /// <summary>Real time: not one of the risky extensions.</summary>
    NotRiskyExtension,

    /// <summary>Scans: only files the local engine rated Suspicious or PotentiallyUnwanted are looked up.</summary>
    NotSuspicious,
}

/// <summary>
/// When a hash is looked up (ROADMAP feature 3, CLAUDE.md pipeline step 8). Pure; the feature switch, key and rate limit come
/// after it (<see cref="VirusTotalOnlineLookup"/>).
/// <list type="bullet">
/// <item>Never for a valid trusted signature (Microsoft or OtherTrusted), whatever the trigger. Unsigned, invalid or unchecked
/// signatures count as unsigned.</item>
/// <item>Real time (new files in watched folders): only the risky extensions <c>.exe .dll .msi .ps1 .js .vbs .bat .cmd .zip
/// .docm .xlsm</c> (trailing dots and spaces ignored, so <c>evil.exe.</c> counts as <c>.exe</c>).</item>
/// <item>Scan jobs (Quick, Full, Custom) and autostart targets (Persistence): only files the local engine rated
/// Suspicious or PotentiallyUnwanted (E1).</item>
/// <item>Never when the local verdict is already Malicious.</item>
/// </list>
/// </summary>
public static class OnlineLookupPolicy
{
    /// <summary>The real-time risky extensions (ROADMAP feature 3).</summary>
    public static IReadOnlySet<string> RiskyExtensions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".ps1", ".js", ".vbs", ".bat", ".cmd", ".zip", ".docm", ".xlsm",
    };

    public static OnlineLookupDecision Decide(OnlineLookupRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SignatureStatus is SignatureStatus.Microsoft or SignatureStatus.OtherTrusted)
        {
            return OnlineLookupDecision.TrustedSignature;
        }

        if (request.LocalVerdict == Verdict.Malicious)
        {
            return OnlineLookupDecision.AlreadyMalicious;
        }

        if (request.Item.Trigger == ScanTrigger.RealTime)
        {
            return IsRiskyExtension(request.Item.Path) ? OnlineLookupDecision.Query : OnlineLookupDecision.NotRiskyExtension;
        }

        // E1: a local PUP / hack tool is looked up too: a trojanized keygen should come out Malicious, not just unwanted.
        return request.LocalVerdict is Verdict.Suspicious or Verdict.PotentiallyUnwanted ? OnlineLookupDecision.Query : OnlineLookupDecision.NotSuspicious;
    }

    /// <summary>True if the file name ends in a risky extension (trailing dots / spaces ignored).</summary>
    public static bool IsRiskyExtension(string path)
    {
        string name = Path.GetFileName(path.AsSpan()).TrimEnd(". ").ToString();
        return RiskyExtensions.Contains(Path.GetExtension(name));
    }
}
