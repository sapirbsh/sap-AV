using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.VirusTotal;

namespace SapAV.Engine.VirusTotal;

/// <summary>
/// Turns a VirusTotal answer into what the scan gets (D3):
/// <list type="bullet">
/// <item>Found, at least <see cref="VirusTotalOptions.MaliciousThreshold"/> (5) engines say malicious → <b>Malicious</b>.</item>
/// <item>Found, at least <see cref="VirusTotalOptions.SuspiciousThreshold"/> (2) engines say malicious or suspicious →
/// <b>Suspicious</b>.</item>
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

        var verdict = report.Malicious >= options.MaliciousThreshold ? Verdict.Malicious
            : report.Malicious + report.Suspicious >= options.SuspiciousThreshold ? Verdict.Suspicious
            : (Verdict?)null;
        if (verdict is null)
        {
            return new(null, new ScanNote(ScanNoteLevel.Information,
                $"{result.Detail} Below the detection threshold ({options.SuspiciousThreshold} engines); not counted."));
        }

        string label = report.ThreatLabel is { Length: > 0 } threat ? $", labelled {threat}" : string.Empty;
        string reason = $"VirusTotal: {report.Malicious} of {report.TotalEngines} engines detect this file as malicious" +
            $" ({report.DetectionRatio} flagged it{label}).";
        return new(new Detection(verdict.Value, reason, MitreTechniqueIds.MaliciousFile, DetectionSource.VirusTotal),
            new ScanNote(ScanNoteLevel.Information, result.Detail));
    }
}
