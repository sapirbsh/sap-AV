using SapAV.Core.Alerts;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Text;

namespace SapAV.Engine.Alerts;

/// <summary>Builds the alerts scan jobs raise (B3): file detections and the engine-health alerts.</summary>
/// <remarks>
/// Review X2/B3 M2 (partial): detection reasons come from the sandboxed worker (YARA descriptions, heuristic text) and
/// the Event Log is readable by users, so a compromised worker could use them to leak content of files the engine read
/// as SYSTEM. File alerts therefore keep at most <see cref="MaxWorkerReasons"/> reasons of at most
/// <see cref="MaxWorkerReasonLength"/> characters each. Health-alert text is built here from engine templates only.
/// </remarks>
public static class ScanAlerts
{
    public const int MaxWorkerReasons = 4;
    public const int MaxWorkerReasonLength = 200;

    /// <summary>The file alert for a scan (Suspicious / Malicious), or null when there is nothing to alert.</summary>
    public static Alert? ForFile(FileScanReport report, AlertAction action)
    {
        ArgumentNullException.ThrowIfNull(report);
        var alert = Alert.FromReport(report, action, EngineInfo.Version);
        return alert is null ? null : WithAction(alert, action);
    }

    /// <summary>The same alert (same ID) with another action, and the worker text caps applied.</summary>
    public static Alert WithAction(Alert alert, AlertAction action)
    {
        ArgumentNullException.ThrowIfNull(alert);
        var reasons = alert.Reasons.Take(MaxWorkerReasons).Select(r => SafeText.SingleLine(r, MaxWorkerReasonLength)).ToArray();
        return new Alert(alert.AlertId, alert.Timestamp, alert.Type, alert.Verdict, alert.FilePath, alert.Sha256, alert.SignatureStatus,
            alert.Signer, alert.TechniqueId, alert.SecondaryTechniqueIds, reasons, alert.SourceUrl, action, alert.Trigger, alert.EngineVersion);
    }

    /// <summary>The auto-quarantine rate limit was hit (review B5 M3): the file waits for the user.</summary>
    public static Alert AutoQuarantineBurst(string filePath, ScanTrigger trigger, int maxPerWindow, TimeSpan window, DateTimeOffset now) =>
        Health(AlertType.AutoQuarantineBurst, Verdict.Malicious, filePath, trigger, now, MitreTechniqueIds.MaliciousFile,
            $"More than {maxPerWindow} Malicious files in {window}: automatic quarantine is paused for the rest of the window and " +
            "further files need the user to confirm.", AlertAction.NeedsUserConfirmation);

    /// <summary>No YARA rules, or rule files failed to load (review A M5).</summary>
    public static Alert RulesDegraded(string rulesLocation, string problem, ScanTrigger trigger, DateTimeOffset now) =>
        Health(AlertType.ScanRulesDegraded, Verdict.Suspicious, rulesLocation, trigger, now, MitreTechniqueIds.DisableOrModifyTools,
            problem, AlertAction.None);

    /// <summary>The quarantine store is full (review B2 M4); <paramref name="filePath"/> stayed in place.</summary>
    public static Alert StoreFull(string filePath, Verdict verdict, ScanTrigger trigger, string why, DateTimeOffset now) =>
        Health(AlertType.QuarantineStoreFull, verdict == Verdict.Clean ? Verdict.Suspicious : verdict, filePath, trigger, now,
            MitreTechniqueIds.DisableOrModifyTools, "The quarantine store is full, so a Malicious file was left in place: " + why,
            AlertAction.QuarantineFailed);

    private static Alert Health(
        AlertType type, Verdict verdict, string path, ScanTrigger trigger, DateTimeOffset now, string technique, string reason, AlertAction action) =>
        new(Alert.ComputeAlertId(type, now, path, null, trigger), now, type, verdict, path, null, null, null, technique, [], [reason], null,
            action, trigger, EngineInfo.Version);
}
