using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Signatures;

namespace SapAV.Core.Heuristics;

/// <summary>Which heuristic produced a <see cref="HeuristicFinding"/>.</summary>
public enum HeuristicKind
{
    /// <summary>A document/media extension followed by an executable one, e.g. <c>invoice.pdf.exe</c>.</summary>
    DoubleExtension,

    /// <summary>A Unicode right-to-left override in the file name (e.g. <c>"invoice‮fdp.exe"</c> shows as "invoiceexe.pdf").</summary>
    RightToLeftOverride,

    /// <summary>A PE file over the scan size limit whose extra bytes are padding (zero or one repeated value).</summary>
    PaddedOversizedExecutable,

    /// <summary>A PE file whose section data has very high entropy (packed or encrypted).</summary>
    HighEntropyExecutable,

    /// <summary>An executable or script in Temp, Downloads or AppData.</summary>
    RiskyFolderExecutable,

    /// <summary>A PE file with no signature.</summary>
    UnsignedExecutable,

    /// <summary>A PE file with a signature that doesn't verify (tampered, untrusted, expired, ...).</summary>
    BrokenSignature,

    /// <summary>An executable downloaded from the Internet or Restricted zone (Mark-of-the-Web, A6).</summary>
    InternetOrigin,
}

/// <summary>One heuristic that fired, with its score contribution.</summary>
/// <param name="Kind">Which heuristic.</param>
/// <param name="Score">Points added to <see cref="HeuristicResult.Score"/>.</param>
/// <param name="Reason">Human-readable reason, e.g. "double extension .pdf.exe".</param>
/// <param name="TechniqueId">MITRE technique for this finding.</param>
public sealed record HeuristicFinding(HeuristicKind Kind, int Score, string Reason, string TechniqueId);

/// <summary>Facts from earlier pipeline steps that heuristics use.</summary>
/// <param name="Signature">The Authenticode result (A3), or null if it wasn't checked.</param>
/// <param name="MarkOfTheWeb">The Mark-of-the-Web (A6), or null if there is none or it wasn't read.</param>
public sealed record HeuristicContext(SignatureCheckResult? Signature = null, MarkOfTheWeb? MarkOfTheWeb = null)
{
    public static HeuristicContext None { get; } = new();

    internal bool IsTrustedSigned => Signature?.IsTrusted == true;
}

/// <summary>
/// Outcome of <see cref="IFileHeuristics.Analyze"/>: the findings and their total score. Heuristics alone are
/// never Malicious: at or above <see cref="Threshold"/> the result is one Suspicious <see cref="Detection"/>.
/// </summary>
public sealed record HeuristicResult
{
    internal HeuristicResult(
        IReadOnlyList<HeuristicFinding> findings, int threshold, bool contentInspected, string? contentError,
        HashFailureReason contentFailureReason = HashFailureReason.None)
    {
        Findings = findings;
        Threshold = threshold;
        Score = findings.Sum(f => f.Score);
        ContentInspected = contentInspected;
        ContentError = contentError;
        ContentFailureReason = contentInspected ? HashFailureReason.None : contentFailureReason;
        Detection = Score >= threshold && findings.Count > 0 ? BuildDetection() : null;
    }

    public IReadOnlyList<HeuristicFinding> Findings { get; }

    /// <summary>Sum of the findings' scores.</summary>
    public int Score { get; }

    /// <summary>Score at which the file is Suspicious.</summary>
    public int Threshold { get; }

    /// <summary>False if the file couldn't be opened, so only name/path heuristics ran (see <see cref="ContentError"/>).</summary>
    public bool ContentInspected { get; }

    public string? ContentError { get; }

    /// <summary>
    /// Why the content wasn't inspected (e.g. <see cref="HashFailureReason.BlockedByAntivirus"/> when a real antivirus
    /// refused the open or read); <see cref="HashFailureReason.None"/> when it was inspected, or when the reason is
    /// unknown (the scan worker's wire report carries only <see cref="ContentError"/>).
    /// </summary>
    public HashFailureReason ContentFailureReason { get; }

    /// <summary>A Suspicious detection (source Heuristic) when <see cref="Score"/> reaches <see cref="Threshold"/>; else null.</summary>
    public Detection? Detection { get; }

    public bool IsSuspicious => Detection is not null;

    private Detection BuildDetection()
    {
        // Primary technique: the strongest finding (first on ties); the others' distinct techniques are secondary.
        var ordered = Findings.Select((f, i) => (f, i)).OrderByDescending(x => x.f.Score).ThenBy(x => x.i).Select(x => x.f).ToArray();
        string primary = ordered[0].TechniqueId;
        var secondaries = ordered.Select(f => f.TechniqueId).Distinct(StringComparer.Ordinal).Where(t => t != primary).ToArray();
        string reason = $"Heuristic score {Score} (threshold {Threshold}): " + string.Join("; ", Findings.Select(f => f.Reason));
        return new Detection(Verdict.Suspicious, reason, primary, DetectionSource.Heuristic, secondaries);
    }
}
