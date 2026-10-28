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
    /// <remarks>A persistence alert's reasons were capped by <see cref="ForPersistence"/> (worker text and engine text apart), so they stay.</remarks>
    public static Alert WithAction(Alert alert, AlertAction action)
    {
        ArgumentNullException.ThrowIfNull(alert);
        var reasons = alert.Autostart is not null
            ? alert.Reasons
            : alert.Reasons.Take(MaxWorkerReasons).Select(r => SafeText.SingleLine(r, MaxWorkerReasonLength)).ToArray();
        return new Alert(alert.AlertId, alert.Timestamp, alert.Type, alert.Verdict, alert.FilePath, alert.Sha256, alert.SignatureStatus,
            alert.Signer, alert.TechniqueId, alert.SecondaryTechniqueIds, reasons, alert.SourceUrl, action, alert.Trigger, alert.EngineVersion,
            alert.Autostart);
    }

    /// <summary>Most rule (signal) reasons a persistence alert keeps; they are engine text with the entry's values in them.</summary>
    public const int MaxPersistenceSignalReasons = 8;

    /// <summary>
    /// The alert for a judged autostart entry (C3: 2001 / 2002), or null when it is Clean. Reasons carried over from the
    /// target's or host's scan are worker text and get the file-alert caps (<see cref="MaxWorkerReasons"/> of
    /// <see cref="MaxWorkerReasonLength"/>); the rules' own reasons follow (at most <see cref="MaxPersistenceSignalReasons"/>,
    /// each already capped at <see cref="Core.Persistence.PersistenceSignal.MaxReasonLength"/>).
    /// </summary>
    public static Alert? ForPersistence(Core.Persistence.PersistenceFinding finding, AlertAction action, ScanTrigger trigger, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var alert = Alert.FromPersistence(finding, action, trigger, now, EngineInfo.Version);
        if (alert is null)
        {
            return null;
        }

        var judgement = finding.Judgement;
        var carried = judgement.Detections.Where(d => d.Source != DetectionSource.Persistence)
            .Take(MaxWorkerReasons).Select(d => SafeText.SingleLine(d.Reason, MaxWorkerReasonLength));
        var signals = judgement.Signals.Where(s => s.Score > 0).Take(MaxPersistenceSignalReasons).Select(s => s.Reason);
        string[] reasons = [.. carried, .. signals];
        return new Alert(alert.AlertId, alert.Timestamp, alert.Type, alert.Verdict, alert.FilePath, alert.Sha256, alert.SignatureStatus,
            alert.Signer, alert.TechniqueId, alert.SecondaryTechniqueIds, reasons.Length > 0 ? reasons : alert.Reasons.Take(1).ToArray(),
            alert.SourceUrl, action, alert.Trigger, alert.EngineVersion, alert.Autostart);
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

    /// <summary>
    /// The trigger of engine-health alerts raised outside a scan job (startup, background checks): the always-on engine,
    /// reported as <see cref="ScanTrigger.RealTime"/> (the alert models have no separate "engine" trigger).
    /// </summary>
    public const ScanTrigger EngineTrigger = ScanTrigger.RealTime;

    /// <summary>An engine folder isn't admin-only, so it is scanned instead of excluded (review B H1, ROADMAP D3 M5).</summary>
    public static Alert EngineFolderUntrusted(string folder, string why, DateTimeOffset now) =>
        Health(AlertType.EngineFolderUntrusted, Verdict.Suspicious, folder, EngineTrigger, now, MitreTechniqueIds.DisableOrModifyTools,
            "This sap-AV folder is not protected (" + why + "), so it is scanned instead of excluded. Reinstall sap-AV or let an " +
            "administrator restore its permissions.", AlertAction.None);

    /// <summary>The quarantine store can't be opened (review B M4); <paramref name="why"/> is engine text (the store's own refusal).</summary>
    public static Alert StoreUnavailable(string storeRoot, string why, DateTimeOffset now) =>
        Health(AlertType.QuarantineStoreUnavailable, Verdict.Suspicious, storeRoot, EngineTrigger, now, MitreTechniqueIds.DisableOrModifyTools,
            "The quarantine is unavailable, so Malicious files are left in place; the engine keeps retrying: " + why, AlertAction.None);

    /// <summary>No scan worker could start or load the rules (review B M4 / ROADMAP D3 M-B). Fixed text: worker output never goes here.</summary>
    public static Alert SandboxUnavailable(string workerPath, DateTimeOffset now) =>
        Health(AlertType.SandboxUnavailable, Verdict.Suspicious, workerPath, EngineTrigger, now, MitreTechniqueIds.DisableOrModifyTools,
            "No sandboxed scan worker could start or load the rules, so files are reported NotScanned until it recovers. See the engine log.",
            AlertAction.None);

    /// <summary>The engine pipe can't be created (review B M4 / M5): the name is taken or creating it fails.</summary>
    public static Alert PipeUnavailable(string pipeName, string why, DateTimeOffset now) =>
        Health(AlertType.PipeUnavailable, Verdict.Suspicious, pipeName, EngineTrigger, now, MitreTechniqueIds.DisableOrModifyTools,
            "The engine pipe is unavailable, so the sap-AV app can't connect; the engine keeps retrying: " + why, AlertAction.None);

    /// <summary>The sap-AV log's CustomSD or message DLL isn't what the installer set (review B6 M2).</summary>
    public static Alert EventLogIntegrityDegraded(string logName, string problem, DateTimeOffset now) =>
        Health(AlertType.EventLogIntegrityDegraded, Verdict.Suspicious, logName, EngineTrigger, now, MitreTechniqueIds.DisableOrModifyTools,
            "Log integrity degraded: " + problem + " Run the sap-AV installer (--install-eventlog-source) again to restore it.", AlertAction.None);

    private static Alert Health(
        AlertType type, Verdict verdict, string path, ScanTrigger trigger, DateTimeOffset now, string technique, string reason, AlertAction action) =>
        new(Alert.ComputeAlertId(type, now, path, null, trigger), now, type, verdict, path, null, null, null, technique, [], [reason], null,
            action, trigger, EngineInfo.Version);
}
