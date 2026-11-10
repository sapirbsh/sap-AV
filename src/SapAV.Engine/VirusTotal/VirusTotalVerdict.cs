using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.VirusTotal;

namespace SapAV.Engine.VirusTotal;

/// <summary>
/// Turns a VirusTotal answer into what the scan gets (D3, E1):
/// <list type="bullet">
/// <item>Found, at least <see cref="VirusTotalOptions.MaliciousThreshold"/> (5) engines say malicious → <b>Malicious</b>, unless
/// the threat label is PUP-like (<see cref="IsPotentiallyUnwanted"/>).</item>
/// <item>Found with a PUP-like label and at least <see cref="VirusTotalOptions.SuspiciousThreshold"/> (3) engines →
/// <b>PotentiallyUnwanted</b>, category <see cref="ThreatCategory.HackTool"/> when the label says hacktool, else
/// <see cref="ThreatCategory.Pup"/> (E1; review D3 L2 had capped these at Suspicious). PUP / HackTool findings are never
/// auto-quarantined (CLAUDE.md): the verdict handler quarantines Malicious only.</item>
/// <item>Found, at least <see cref="VirusTotalOptions.SuspiciousThreshold"/> (3) engines say malicious → <b>Suspicious</b>.
/// Engines that only say "suspicious" don't count.</item>
/// <item>Found with fewer, or NotFound → no detection, an information note.</item>
/// <item>No answer (rate limited, no key, refused key, error) → a note, <b>never Clean and never a failure</b> (review D2 M4):
/// the local verdict stands.</item>
/// </list>
/// MITRE: VirusTotal says nothing about technique, only that engines know the file as malware the user could run, so every
/// VirusTotal detection is <c>T1204.002</c> (User Execution: Malicious File). The reason is engine text plus VirusTotal's
/// sanitized threat label (display-safe and capped by the parser).
/// </summary>
public static class VirusTotalVerdict
{
    public static OnlineLookupOutcome Map(VirusTotalLookupResult result, VirusTotalOptions options)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(options);
        if (!result.HasAnswer)
        {
            var level = result.Origin is VirusTotalOrigin.RateLimited or VirusTotalOrigin.NoKey ? ScanNoteLevel.Information : ScanNoteLevel.Warning;
            return new(null, new ScanNote(level, result.Detail));
        }

        if (result.Status != VirusTotalStatus.Found || result.Report is not { } report)
        {
            return new(null, new ScanNote(ScanNoteLevel.Information, result.Detail));
        }

        var unwanted = UnwantedCategory(report.ThreatLabel);
        var verdict = report.Malicious < options.SuspiciousThreshold ? (Verdict?)null
            : unwanted is not null ? Verdict.PotentiallyUnwanted
            : report.Malicious >= options.MaliciousThreshold ? Verdict.Malicious
            : Verdict.Suspicious;
        if (verdict is null)
        {
            return new(null, new ScanNote(ScanNoteLevel.Information,
                $"{result.Detail} Below the detection threshold ({options.SuspiciousThreshold} engines saying malicious); not counted."));
        }

        string label = report.ThreatLabel is { Length: > 0 } threat ? $", labelled {threat}" : string.Empty;
        string what = unwanted switch
        {
            ThreatCategory.HackTool => " (a hack tool: never quarantined automatically)",
            ThreatCategory.Pup => " (potentially unwanted: never quarantined automatically)",
            _ => string.Empty,
        };
        string reason = $"VirusTotal: {report.Malicious} of {report.TotalEngines} engines detect this file as malicious" +
            $" ({report.DetectionRatio} flagged it{label}){what}.";
        return new(new Detection(verdict.Value, reason, MitreTechniqueIds.MaliciousFile, DetectionSource.VirusTotal, null,
                unwanted ?? ThreatCategory.Malware),
            new ScanNote(ScanNoteLevel.Information, result.Detail));
    }

    /// <summary>
    /// Label words that mean potentially unwanted software or a hacking tool rather than malware. Matched as whole tokens of the
    /// label split on <c>.</c> <c>/</c> <c>-</c> <c>:</c> <c>_</c> <c>!</c> <c>[</c> <c>]</c> parentheses and spaces (review L2: <c>trojan.pupy</c>, the Pupy RAT,
    /// must not read as "pup"). Two-word forms: <c>not-a-virus</c>, <c>potentially unwanted</c>.
    /// </summary>
    public static IReadOnlyList<string> UnwantedLabelWords { get; } =
        ["hacktool", "pua", "pup", "riskware", "adware", "potentiallyunwanted", "not-a-virus", "potentially-unwanted"];

    private static readonly HashSet<string> UnwantedTokens = new(StringComparer.Ordinal)
    {
        "hacktool", "pua", "pup", "riskware", "adware", "potentiallyunwanted",
    };

    /// <summary>True if VirusTotal's threat label names a PUP / HackTool category (case-insensitive, whole tokens).</summary>
    public static bool IsPotentiallyUnwanted(string? threatLabel) => UnwantedCategory(threatLabel) is not null;

    /// <summary>E1: HackTool when the label has the token hacktool, Pup for the other unwanted tokens, null for anything else.</summary>
    public static ThreatCategory? UnwantedCategory(string? threatLabel)
    {
        if (threatLabel is not { Length: > 0 } label)
        {
            return null;
        }

        var tokens = label.ToLowerInvariant().Split(['.', '/', '-', ':', '_', '!', '[', ']', '(', ')', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Contains("hacktool"))
        {
            return ThreatCategory.HackTool;
        }

        bool phrase = false;
        for (int i = 0; i + 1 < tokens.Length && !phrase; i++)
        {
            phrase = (tokens[i] == "potentially" && tokens[i + 1] == "unwanted")
                || (i + 2 < tokens.Length && tokens[i] == "not" && tokens[i + 1] == "a" && tokens[i + 2] == "virus");
        }

        return phrase || tokens.Any(UnwantedTokens.Contains) ? ThreatCategory.Pup : null;
    }
}
