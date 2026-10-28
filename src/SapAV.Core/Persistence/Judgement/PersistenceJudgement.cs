using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.Persistence;

/// <summary>How much a <see cref="PersistenceSignal"/> means (ROADMAP C3). Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<PersistenceSignalStrength>))]
public enum PersistenceSignalStrength
{
    /// <summary>
    /// Context that only matters with company (an interpreter host, a per-user app in its own folder). Dropped when the
    /// target is a Microsoft-signed file in an admin-only Windows folder, so standard entries make no noise.
    /// </summary>
    Weak,

    Normal,

    /// <summary>Raises the finding's priority to High (a hijack path for standard users, IFEO on a security tool, ...).</summary>
    Strong,
}

/// <summary>How urgently a finding should be looked at. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<PersistencePriority>))]
public enum PersistencePriority
{
    Low,
    Normal,
    High,
}

/// <summary>Stable IDs of the C3 rules' signals (UI, tests and E4's added rules key on them).</summary>
public static class PersistenceRuleIds
{
    public const string TargetDetection = "target-detection";
    public const string HostDetection = "host-detection";
    public const string TargetNotScanned = "target-not-scanned";
    public const string TargetUserModifiable = "target-user-modifiable";
    public const string TargetFolderUserWritable = "target-folder-user-writable";
    public const string TargetInUserFolder = "target-in-user-folder";
    public const string TargetRiskyFolder = "target-risky-folder";
    public const string TargetUnsigned = "target-unsigned";
    public const string TargetBrokenSignature = "target-broken-signature";
    public const string IfeoDebugger = "ifeo-debugger";
    public const string SilentProcessExitMonitor = "silent-process-exit-monitor";
    public const string WinlogonModified = "winlogon-modified";
    public const string MissingTarget = "missing-target";
    public const string MissingTargetHijackable = "missing-target-hijackable";
    public const string UnquotedPath = "unquoted-path";
    public const string UnquotedPathHijackable = "unquoted-path-hijackable";
    public const string InterpreterHost = "interpreter-host";
    public const string InlineCommand = "inline-command";
    public const string RemotePayload = "remote-payload";
    public const string UserComOverride = "user-com-override";
    public const string RuleFailed = "rule-failed";
}

/// <summary>One thing a persistence rule noticed about an entry, with its score contribution.</summary>
public sealed record PersistenceSignal
{
    public const int MaxReasonLength = 300;

    /// <param name="rule">A stable rule ID (<see cref="PersistenceRuleIds"/>, or an added rule's own).</param>
    /// <param name="score">Points added to the entry's score (0 = information only).</param>
    /// <param name="reason">Engine text; entry values in it are sanitized here (one line, capped).</param>
    /// <param name="techniqueId">The MITRE technique this signal adds (secondary to the entry kind's), or null.</param>
    public PersistenceSignal(string rule, int score, string reason, string? techniqueId = null, PersistenceSignalStrength strength = PersistenceSignalStrength.Normal)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rule);
        ArgumentOutOfRangeException.ThrowIfNegative(score);
        ArgumentNullException.ThrowIfNull(reason);
        if (techniqueId is not null)
        {
            MitreTechniqueIdFormat.EnsureValid(techniqueId, nameof(techniqueId));
        }

        if (!Enum.IsDefined(strength))
        {
            throw new ArgumentOutOfRangeException(nameof(strength), strength, "Undefined strength.");
        }

        string safe = SafeText.SingleLine(reason, MaxReasonLength);
        Rule = rule;
        Score = score;
        Reason = safe.Length == 0 ? rule : safe;
        TechniqueId = techniqueId;
        Strength = strength;
    }

    public string Rule { get; }

    public int Score { get; }

    public string Reason { get; }

    public string? TechniqueId { get; }

    public PersistenceSignalStrength Strength { get; }
}

/// <summary>
/// The verdict on one autostart entry (ROADMAP C3): what the rules noticed, the score, and the detections an alert or
/// a results row is built from.
/// </summary>
/// <remarks>
/// <see cref="Verdict"/> is Malicious only when the target (or host) scan was Malicious (blocklist, YARA, VirusTotal):
/// the entry rules alone give at most Suspicious (score at or over <see cref="Threshold"/>), so false positives stay low.
/// </remarks>
public sealed record PersistenceJudgement
{
    public PersistenceJudgement(
        Verdict verdict, int score, int threshold, PersistencePriority priority, string techniqueId, IReadOnlyList<string> secondaryTechniqueIds,
        IReadOnlyList<PersistenceSignal> signals, IReadOnlyList<Detection> detections)
    {
        if (!Enum.IsDefined(verdict) || !Enum.IsDefined(priority))
        {
            throw new ArgumentOutOfRangeException(nameof(verdict), "Undefined verdict or priority.");
        }

        MitreTechniqueIdFormat.EnsureValid(techniqueId, nameof(techniqueId));
        ArgumentNullException.ThrowIfNull(secondaryTechniqueIds);
        ArgumentNullException.ThrowIfNull(signals);
        ArgumentNullException.ThrowIfNull(detections);
        if ((verdict == Verdict.Clean) != (detections.Count == 0) || (detections.Count > 0 && detections.Max(d => d.Verdict) != verdict))
        {
            throw new ArgumentException("The verdict must be the worst detection's (Clean exactly when there are none).", nameof(verdict));
        }

        Verdict = verdict;
        Score = score;
        Threshold = threshold;
        Priority = priority;
        TechniqueId = techniqueId;
        SecondaryTechniqueIds = Array.AsReadOnly(secondaryTechniqueIds.ToArray());
        Signals = Array.AsReadOnly(signals.ToArray());
        Detections = Array.AsReadOnly(detections.ToArray());
    }

    public Verdict Verdict { get; }

    /// <summary>The sum of the signals' scores.</summary>
    public int Score { get; }

    /// <summary>Score at which the entry is Suspicious.</summary>
    public int Threshold { get; }

    public PersistencePriority Priority { get; }

    /// <summary>
    /// Primary MITRE technique: the worst detection's (a carried target detection keeps its own, e.g. T1204.002), else the
    /// entry kind's (X1, e.g. T1547.001).
    /// </summary>
    public string TechniqueId { get; }

    /// <summary>The other techniques (always including the entry kind's when it isn't primary), distinct.</summary>
    public IReadOnlyList<string> SecondaryTechniqueIds { get; }

    /// <summary>Everything the rules noticed, highest score first (also on a Clean entry: e.g. an unquoted path).</summary>
    public IReadOnlyList<PersistenceSignal> Signals { get; }

    /// <summary>
    /// Worst first: carried Malicious target / host detections, then the entry's own (source Persistence) when the score
    /// reaches the threshold, then carried Suspicious ones. Empty when Clean.
    /// </summary>
    public IReadOnlyList<Detection> Detections { get; }

    /// <summary>Display lines: the detections' reasons, then the scored signals' reasons.</summary>
    public IReadOnlyList<string> Reasons =>
        [.. Detections.Where(d => d.Source != DetectionSource.Persistence).Select(d => d.Reason), .. Signals.Where(s => s.Score > 0).Select(s => s.Reason)];
}

/// <summary>
/// One judged autostart entry (ROADMAP C3): the entry, its judgement and the scan results of its target and host. What
/// flows into alerts (<see cref="Alerts.Alert.FromPersistence"/>) and job results (C4).
/// </summary>
/// <param name="Target">The target's scan result, or null when it wasn't scanned (no target, missing, budget).</param>
/// <param name="Host">The host's scan result (rundll32, powershell, ...), or null.</param>
public sealed record PersistenceFinding(PersistenceEntry Entry, PersistenceJudgement Judgement, ScanResult? Target, ScanResult? Host)
{
    public Verdict Verdict => Judgement.Verdict;

    /// <summary>The alert raised for it, if any.</summary>
    public Guid? AlertId { get; init; }
}
