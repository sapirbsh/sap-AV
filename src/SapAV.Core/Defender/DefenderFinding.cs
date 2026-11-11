using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.Defender;

/// <summary>Stable IDs of the Defender-tampering rules (E5). The UI, tests and E11's "remove exclusion" step key on them.</summary>
public static class DefenderRuleIds
{
    // Exclusions.
    public const string PathExcludesEverything = "exclusion-path-everything";
    public const string PathBroadUserFolder = "exclusion-path-broad";
    public const string PathSystemFolder = "exclusion-path-system-folder";
    public const string PathInUserFolder = "exclusion-path-user-folder";
    public const string ExtensionExcludesEverything = "exclusion-extension-everything";
    public const string ExtensionRisky = "exclusion-extension-risky";
    public const string ProcessExcludesEverything = "exclusion-process-everything";
    public const string ProcessInterpreter = "exclusion-process-interpreter";
    public const string ProcessBroadFolder = "exclusion-process-broad-folder";
    public const string ProcessInUserFolder = "exclusion-process-user-folder";

    /// <summary>More flagged exclusions in one list than are reported one by one (<see cref="DefenderRules.MaxExclusionFindingsPerList"/>).</summary>
    public const string MoreFlaggedExclusions = "exclusion-more-flagged";

    // Protection state.
    public const string AntivirusOff = "antivirus-off";
    public const string RealTimeProtectionOff = "realtime-protection-off";
    public const string BehaviorMonitoringOff = "behavior-monitoring-off";
    public const string IoavProtectionOff = "ioav-protection-off";
    public const string TamperProtectionOff = "tamper-protection-off";
    public const string PassiveWithoutOtherAntivirus = "passive-without-other-antivirus";

    // Tamper signs.
    public const string DefenderMissing = "defender-missing";
    public const string DefenderServiceStopped = "defender-service-stopped";
    public const string ExclusionsHiddenFromSystem = "exclusions-hidden-from-system";
    public const string ExclusionListTruncated = "exclusion-list-truncated";
}

/// <summary>What a <see cref="DefenderFinding"/> is about. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<DefenderFindingKind>))]
public enum DefenderFindingKind
{
    /// <summary>One exclusion entry (see <see cref="DefenderFinding.ExclusionList"/> and <see cref="DefenderFinding.ExclusionItem"/>).</summary>
    Exclusion,

    /// <summary>A protection component is off (real-time, behaviour monitoring, IOAV, antivirus, tamper protection).</summary>
    ProtectionDisabled,

    /// <summary>Signs that Defender itself was removed, stopped or hidden, or its exclusion list was padded.</summary>
    TamperSign,
}

/// <summary>Which of Defender's exclusion lists an entry is in. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<DefenderExclusionKind>))]
public enum DefenderExclusionKind
{
    Path,
    Extension,
    Process,
    IpAddress,
}

/// <summary>
/// One Defender-tampering finding (ROADMAP E5, threat pack "Defender tampering"): Suspicious or Malicious, always
/// <see cref="ThreatCategory.DefenderTampering"/> and T1562.001. A finding about the system, not a file: it is never quarantined,
/// and nothing is changed automatically. The user decides; removing a flagged exclusion is E11's user-confirmed "Remove threat".
/// </summary>
public sealed record DefenderFinding
{
    public const int MaxReasonLength = 900;

    /// <summary>Shown with every finding: what the user can do, and that sap-AV doesn't change Defender on its own.</summary>
    public const string UserDecides =
        "You decide: review it in Windows Security. sap-AV never changes Defender settings on its own.";

    public DefenderFinding(string ruleId, Verdict verdict, DefenderFindingKind kind, string reason,
        DefenderExclusionKind? exclusionList = null, string? exclusionItem = null, DefenderExclusionSource exclusionSource = DefenderExclusionSource.None)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        ArgumentNullException.ThrowIfNull(reason);
        if (verdict is not (Verdict.Suspicious or Verdict.Malicious))
        {
            throw new ArgumentOutOfRangeException(nameof(verdict), verdict, "A Defender finding is Suspicious or Malicious.");
        }

        if (!Enum.IsDefined(kind) || !Enum.IsDefined(exclusionSource) || (exclusionList is { } l && !Enum.IsDefined(l)))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "Undefined kind, list or source.");
        }

        if ((kind == DefenderFindingKind.Exclusion) != exclusionList.HasValue)
        {
            throw new ArgumentException("An exclusion finding names its list, and only an exclusion finding does.", nameof(exclusionList));
        }

        string safe = SafeText.SingleLine(reason, MaxReasonLength);
        RuleId = ruleId;
        Verdict = verdict;
        Kind = kind;
        Reason = safe.Length == 0 ? ruleId : safe;
        ExclusionList = exclusionList;
        ExclusionItem = exclusionItem;
        ExclusionSource = exclusionSource;
    }

    /// <summary>A <see cref="DefenderRuleIds"/> value.</summary>
    public string RuleId { get; }

    /// <summary>Suspicious or Malicious.</summary>
    public Verdict Verdict { get; }

    public DefenderFindingKind Kind { get; }

    /// <summary>What is wrong and why it matters, one line. Exclusion text in it went through <see cref="DefenderExclusionList.ForDisplay"/>.</summary>
    public string Reason { get; }

    /// <summary>The list the flagged entry is in (Exclusion findings only).</summary>
    public DefenderExclusionKind? ExclusionList { get; }

    /// <summary>
    /// The flagged entry exactly as Defender stores it (<see cref="DefenderExclusionList"/>'s raw form), so E11 can remove that exact
    /// entry. Untrusted text: <b>never display or log it</b>; <see cref="Reason"/> carries the display form. Null when not about one entry.
    /// </summary>
    [JsonIgnore]
    public string? ExclusionItem { get; }

    /// <summary>Where the flagged list was read from (WMI or the registry fallback); None when not about a list.</summary>
    public DefenderExclusionSource ExclusionSource { get; }

    /// <summary>Always T1562.001 (Impair Defenses: Disable or Modify Tools).</summary>
    public string TechniqueId => MitreTechniqueIds.DisableOrModifyTools;

    /// <summary>Always <see cref="ThreatCategory.DefenderTampering"/>.</summary>
    public ThreatCategory Category => ThreatCategory.DefenderTampering;

    /// <summary>
    /// The finding as a <see cref="Detection"/> for alerts, results and the Event Log. Source is
    /// <see cref="DetectionSource.Heuristic"/> until a dedicated system-state source exists (E7).
    /// </summary>
    public Detection ToDetection() => new(Verdict, Reason, TechniqueId, DetectionSource.Heuristic, [], Category);
}

/// <summary>What the Defender check came to. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<DefenderOutcome>))]
public enum DefenderOutcome
{
    /// <summary>Everything the rules need was read, and nothing was found.</summary>
    Clean,

    /// <summary>
    /// Nothing was found, but part of the state couldn't be judged (a read failed, a list was hidden, a value was unknown).
    /// Never reported as Clean; <see cref="DefenderAssessment.Unverified"/> says what.
    /// </summary>
    Unverified,

    /// <summary>Defender isn't part of this system (a Server SKU without it): nothing to judge.</summary>
    NotApplicable,

    Suspicious,
    Malicious,
}

/// <summary>The result of <see cref="DefenderRules.Evaluate"/>: findings, plus what couldn't be judged.</summary>
public sealed record DefenderAssessment
{
    public const int MaxUnverifiedReasons = 16;

    public DefenderAssessment(IReadOnlyList<DefenderFinding> findings, IReadOnlyList<string> unverified, bool notApplicable = false)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(unverified);
        Findings = Array.AsReadOnly(findings.OrderByDescending(f => f.Verdict).ToArray());
        Unverified = Array.AsReadOnly(unverified.Select(r => SafeText.SingleLine(r, DefenderFinding.MaxReasonLength))
            .Where(r => r.Length > 0).Distinct(StringComparer.Ordinal).Take(MaxUnverifiedReasons).ToArray());
        NotApplicable = notApplicable;
    }

    /// <summary>Worst first.</summary>
    public IReadOnlyList<DefenderFinding> Findings { get; }

    /// <summary>What couldn't be judged and why (empty when everything was read). Display lines.</summary>
    public IReadOnlyList<string> Unverified { get; }

    public bool NotApplicable { get; }

    /// <summary>The worst finding's verdict; Clean when there are none, which doesn't mean verified: read <see cref="Outcome"/>.</summary>
    public Verdict Verdict => Findings.Count == 0 ? Verdict.Clean : Findings[0].Verdict;

    public DefenderOutcome Outcome => Verdict switch
    {
        Verdict.Malicious => DefenderOutcome.Malicious,
        Verdict.Suspicious => DefenderOutcome.Suspicious,
        _ when Unverified.Count > 0 => DefenderOutcome.Unverified,
        _ when NotApplicable => DefenderOutcome.NotApplicable,
        _ => DefenderOutcome.Clean,
    };

    /// <summary>The findings as detections, worst first.</summary>
    public IReadOnlyList<Detection> Detections => [.. Findings.Select(f => f.ToDetection())];
}
