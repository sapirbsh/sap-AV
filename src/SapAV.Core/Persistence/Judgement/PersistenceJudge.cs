using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;

namespace SapAV.Core.Persistence;

/// <summary>
/// One persistence rule (ROADMAP C3). Pure: it looks at the <see cref="PersistenceRuleContext"/> and adds signals or
/// carried detections; it never opens files or reads the registry. E4 (script-persistence rules) adds its rules through
/// <see cref="PersistenceJudge.WithRules"/>.
/// </summary>
public interface IPersistenceRule
{
    void Evaluate(PersistenceRuleContext context);
}

/// <summary>
/// A rule about one thing the entry runs (not about the entry as a whole): it also runs for each of
/// <see cref="ResolvedCommand.Additional"/> (section C review H4).
/// </summary>
public interface IPersistenceTargetRule : IPersistenceRule
{
}

/// <summary>Settings of the judgement.</summary>
public sealed record PersistenceJudgeOptions
{
    /// <summary>The Windows folder (Winlogon defaults, the Microsoft-signed system target rule). Defaults to this machine's.</summary>
    public string? SystemRoot { get; init; } = NullIfEmpty(Environment.GetFolderPath(Environment.SpecialFolder.Windows));

    /// <summary>Score at which an entry is Suspicious (like the file heuristics: one strong signal, or weak ones together).</summary>
    public int SuspiciousThreshold { get; init; } = PersistenceJudge.DefaultSuspiciousThreshold;

    private static string? NullIfEmpty(string value) => value.Length == 0 ? null : value;
}

/// <summary>
/// Judges one autostart entry from what the collector (C2) found and what the target scan (and the ACLs) say (ROADMAP C3).
/// Pure and thread-safe: the inputs are the entry, the target's and host's <see cref="FileScanReport"/> and an
/// <see cref="IPathWritability"/>; nothing is opened, read or executed here.
/// </summary>
/// <remarks>
/// <para><b>Verdict.</b> Malicious only when the target or host scan is Malicious (its detections are carried over, with
/// the entry kind's technique added as a secondary). Otherwise the rules' scores are summed: at
/// <see cref="PersistenceJudgeOptions.SuspiciousThreshold"/> (60) or more the entry is Suspicious; a Suspicious target
/// scan is carried over as Suspicious too. Below the threshold it has no detection, but its signals are kept for the UI.</para>
/// <para><b>Unverified</b> (section C review H4). An entry whose target or additional commands weren't scanned, and aren't known
/// to be missing, has <see cref="PersistenceOutcome.Unverified"/> as its outcome, whatever its score: only a scanned entry can be
/// Clean. Other commands of the entry (<see cref="ResolvedCommand.Additional"/>) go through the target rules and count the same.</para>
/// <para><b>Rules and points</b> (<see cref="PersistenceRules"/>): see each rule. Signals marked
/// <see cref="PersistenceSignalStrength.Weak"/> are dropped when the target is a Microsoft-signed file in an admin-only
/// Windows folder (and the host, if any, is Microsoft-signed too), so standard Windows entries are Clean with no noise.
/// IFEO, Winlogon and the hijack rules are never weak.</para>
/// <para><b>Priority.</b> High for Malicious, or Suspicious with a <see cref="PersistenceSignalStrength.Strong"/> signal;
/// Normal for other Suspicious and for Unverified; Low for Clean. A disabled entry is one step lower (still judged: it can be switched on).</para>
/// </remarks>
public sealed class PersistenceJudge
{
    public const int DefaultSuspiciousThreshold = 60;

    private readonly IReadOnlyList<IPersistenceRule> _rules;

    public PersistenceJudge(PersistenceJudgeOptions? options = null, IEnumerable<IPersistenceRule>? rules = null)
    {
        Options = options ?? new PersistenceJudgeOptions();
        ArgumentOutOfRangeException.ThrowIfLessThan(Options.SuspiciousThreshold, 1);
        _rules = Array.AsReadOnly((rules ?? PersistenceRules.Default).ToArray());
        if (_rules.Any(r => r is null))
        {
            throw new ArgumentException("Rules must not contain null.", nameof(rules));
        }
    }

    public PersistenceJudgeOptions Options { get; }

    public IReadOnlyList<IPersistenceRule> Rules => _rules;

    /// <summary>A judge with <paramref name="extra"/> rules after these (E4's script-persistence rules).</summary>
    public PersistenceJudge WithRules(params IPersistenceRule[] extra) => new(Options, [.. _rules, .. extra]);

    /// <param name="target">The scan of <see cref="ResolvedCommand.TargetPath"/>, or null if it wasn't scanned.</param>
    /// <param name="host">The scan of <see cref="ResolvedCommand.HostPath"/>, or null.</param>
    /// <param name="writability">Who can write the target and its folders (the engine's ACL check); null = unknown.</param>
    /// <param name="additional">The scans of <see cref="ResolvedCommand.Additional"/> targets, by path; null = none was scanned.</param>
    public PersistenceJudgement Judge(
        PersistenceEntry entry, FileScanReport? target, FileScanReport? host, IPathWritability? writability = null, IReadOnlyDictionary<string, FileScanReport>? additional = null)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var paths = writability ?? UnknownWritability.Instance;
        var context = new PersistenceRuleContext(entry, target, host, paths, Options);
        Evaluate(context, _rules);

        // Everything else this entry runs (the rest of a cmd chain, a shortcut's other targets) counts the same as the target.
        bool allMicrosoft = true;
        foreach (var other in entry.Resolution.Additional)
        {
            var otherTarget = other.TargetPath is { } path ? additional?.GetValueOrDefault(path) : null;
            var otherHost = other.HostPath is { } hostPath ? additional?.GetValueOrDefault(hostPath) ?? host : null;
            var sub = new PersistenceRuleContext(ForCommand(entry, other), otherTarget, otherHost, paths, Options);
            Evaluate(sub, _rules.OfType<IPersistenceTargetRule>());
            allMicrosoft &= sub.IsMicrosoftSystemTarget;
            context.Merge(sub);
        }

        return Decide(context, allMicrosoft);
    }

    private static PersistenceEntry ForCommand(PersistenceEntry entry, ResolvedCommand command) =>
        new(entry.Kind, entry.UserSid, entry.Location, entry.ValueName, entry.CommandLine, command, entry.Enabled, entry.ServiceStart, entry.ComClassId);

    private static void Evaluate(PersistenceRuleContext context, IEnumerable<IPersistenceRule> rules)
    {
        foreach (var rule in rules)
        {
            try
            {
                rule.Evaluate(context);
            }
            catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
            {
                // Rules see attacker-chosen values; one that trips over them must not hide the others' findings.
                context.Add(PersistenceRuleIds.RuleFailed, 0, $"A persistence rule ({rule.GetType().Name}) failed ({ex.GetType().Name}).");
            }
        }
    }

    private PersistenceJudgement Decide(PersistenceRuleContext context, bool additionalAllMicrosoft)
    {
        string kindTechnique = context.KindTechnique;
        bool dropWeak = context.IsMicrosoftSystemTarget && additionalAllMicrosoft;
        var signals = context.Signals
            .Where(s => !(dropWeak && s.Strength == PersistenceSignalStrength.Weak))
            .Select((s, i) => (s, i))
            .OrderByDescending(x => x.s.Score).ThenBy(x => x.i).Select(x => x.s)
            .ToArray();
        int score = signals.Sum(s => s.Score);
        int threshold = Options.SuspiciousThreshold;

        // Worst first: carried Malicious, then carried PotentiallyUnwanted (E1), then the entry's own, then carried Suspicious.
        var detections = new List<Detection>();
        detections.AddRange(context.Carried.Where(d => d.Verdict == Verdict.Malicious));
        detections.AddRange(context.Carried.Where(d => d.Verdict == Verdict.PotentiallyUnwanted));
        if (score >= threshold)
        {
            var scored = signals.Where(s => s.Score > 0).ToArray();
            string reason = $"Autostart entry score {score} (threshold {threshold}): " + string.Join("; ", scored.Select(s => s.Reason));
            var secondaries = scored.Select(s => s.TechniqueId).OfType<string>().Where(t => t != kindTechnique).Distinct(StringComparer.Ordinal).ToArray();
            // E3/E4: the category of the strongest signal that names one (a miner command line, ...); Malware otherwise.
            var category = scored.FirstOrDefault(s => s.Category is not null)?.Category ?? ThreatCategory.Malware;
            detections.Add(new Detection(Verdict.Suspicious, reason, kindTechnique, DetectionSource.Persistence, secondaries,
                ThreatCategories.IsPotentiallyUnwanted(category) ? ThreatCategory.Malware : category));
        }

        detections.AddRange(context.Carried.Where(d => d.Verdict == Verdict.Suspicious));
        var verdict = detections.Count == 0 ? Verdict.Clean : detections.Max(d => d.Verdict);

        string primary = detections.Count > 0 ? detections[0].TechniqueId : kindTechnique;
        var allTechniques = detections.SelectMany(d => d.SecondaryTechniqueIds.Prepend(d.TechniqueId))
            .Concat(signals.Select(s => s.TechniqueId).OfType<string>())
            .Append(kindTechnique)
            .Where(t => t != primary)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var priority = verdict switch
        {
            Verdict.Malicious => PersistencePriority.High,
            Verdict.PotentiallyUnwanted => PersistencePriority.Normal,
            Verdict.Suspicious when signals.Any(s => s.Strength == PersistenceSignalStrength.Strong && s.Score > 0) => PersistencePriority.High,
            Verdict.Suspicious => PersistencePriority.Normal,
            _ when context.UnverifiedReasons.Count > 0 => PersistencePriority.Normal,
            _ => PersistencePriority.Low,
        };

        if (!context.Entry.Enabled && priority > PersistencePriority.Low)
        {
            priority--;
        }

        return new PersistenceJudgement(verdict, score, threshold, priority, primary, allTechniques, signals, detections, context.UnverifiedReasons,
            context.HasCoverageGap ? UnverifiedKind.Coverage : UnverifiedKind.Inherent);
    }
}

/// <summary>
/// What a rule sees (ROADMAP C3): the entry, the target's and host's scan reports, the writability answers (cached per
/// path) and derived facts; and where it puts its signals. One per <see cref="PersistenceJudge.Judge"/> call.
/// </summary>
public sealed class PersistenceRuleContext
{
    private readonly List<PersistenceSignal> _signals = [];
    private readonly List<Detection> _carried = [];
    private readonly List<string> _unverified = [];
    private readonly Dictionary<string, Writability> _modifiable = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Writability> _creatable = new(StringComparer.OrdinalIgnoreCase);
    private readonly IPathWritability _writability;
    private bool? _microsoftSystemTarget;

    internal PersistenceRuleContext(
        PersistenceEntry entry, FileScanReport? target, FileScanReport? host, IPathWritability writability, PersistenceJudgeOptions options)
    {
        Entry = entry;
        Target = target;
        Host = host;
        _writability = writability;
        Options = options;
        KindTechnique = PersistenceKinds.TechniqueId(entry.Kind);
        TargetLocation = entry.Resolution.TargetPath is { } path ? TargetLocations.Classify(path, options.SystemRoot) : TargetLocation.Other;
    }

    public PersistenceEntry Entry { get; }

    public FileScanReport? Target { get; }

    public FileScanReport? Host { get; }

    public PersistenceJudgeOptions Options { get; }

    /// <summary>The entry kind's primary technique (X1).</summary>
    public string KindTechnique { get; }

    public string? TargetPath => Entry.Resolution.TargetPath;

    public string? HostPath => Entry.Resolution.HostPath;

    /// <summary>The host's file name in lower case (<c>rundll32.exe</c>, ...), or null.</summary>
    public string? HostName => HostPath is null ? null : Path.GetFileName(HostPath).ToLowerInvariant();

    public TargetLocation TargetLocation { get; }

    /// <summary>
    /// Runs for every user or as SYSTEM: no user scope (HKLM, all-users Startup, services, IFEO, machine tasks). A standard
    /// user who can change what it runs gets other users' or SYSTEM's rights.
    /// </summary>
    public bool IsMachineWide => Entry.IsMachineScope;

    /// <summary>
    /// The target is confirmed not to exist (section C follow-up review H-B): every candidate the resolver had was probed and
    /// missing, a bare name wasn't on a search order that is fully known for this kind, or the scan found nothing where the
    /// resolver had no later candidate. Anything less is Unverified, not missing.
    /// </summary>
    public bool TargetMissing
    {
        get
        {
            var resolution = Entry.Resolution;
            if (resolution.UnresolvedReason == TargetUnresolvedReason.NotFoundOnSearchPath)
            {
                return SearchOrderKnown(Entry.Kind);
            }

            return resolution.HasFlag(ResolutionFlag.TargetNotFound)
                || (Target?.Hash.FailureReason == HashFailureReason.NotFound && !resolution.HasFlag(ResolutionFlag.LaterCandidates));
        }
    }

    /// <summary>
    /// L1: whether the folders a bare name is looked for in are all known. Services and Winlogon start from System32 (application
    /// and current folder), and tasks from their working directory or System32; Run / RunOnce values, Startup items and IFEO
    /// debuggers start from a launcher whose folder, current folder and App Paths the engine doesn't search.
    /// </summary>
    private static bool SearchOrderKnown(PersistenceKind kind) =>
        kind is PersistenceKind.Service or PersistenceKind.ScheduledTask or PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit;

    /// <summary>
    /// The target is Microsoft-signed (embedded or catalog), lies under the Windows folder (not its Temp), its folder is not
    /// user-writable, and the host (if any) is Microsoft-signed too. Weak signals are dropped for such entries.
    /// </summary>
    public bool IsMicrosoftSystemTarget => _microsoftSystemTarget ??=
        TargetPath is { } path
        && Target?.Result.SignatureStatus == SignatureStatus.Microsoft
        && TargetLocation == TargetLocation.Windows
        && FileCreatable(path) != Writability.UserWritable
        && FileModifiable(path) != Writability.UserWritable
        && (HostPath is null || Host?.Result.SignatureStatus == SignatureStatus.Microsoft);

    public IReadOnlyList<PersistenceSignal> Signals => _signals;

    public IReadOnlyList<Detection> Carried => _carried;

    /// <summary><see cref="IPathWritability.FileModifiable"/>, cached for this entry.</summary>
    public Writability FileModifiable(string path) => Cached(_modifiable, path, _writability.FileModifiable);

    /// <summary><see cref="IPathWritability.FileCreatable"/>, cached for this entry.</summary>
    public Writability FileCreatable(string path) => Cached(_creatable, path, _writability.FileCreatable);

    /// <summary>Why something this entry runs has no scan result (section C review H4).</summary>
    public IReadOnlyList<string> UnverifiedReasons => _unverified;

    /// <summary>
    /// Marks the entry Unverified: without a detection it must never read as Clean. M3: <paramref name="kind"/> says whether it is
    /// how the entry is (<see cref="UnverifiedKind.Inherent"/>) or a gap in the scan (<see cref="UnverifiedKind.Coverage"/>, the default).
    /// </summary>
    public void AddUnverified(string reason, UnverifiedKind kind = UnverifiedKind.Coverage)
    {
        ArgumentNullException.ThrowIfNull(reason);
        _unverified.Add(reason);
        if (kind == UnverifiedKind.Coverage || !Enum.IsDefined(kind))
        {
            HasCoverageGap = true;
        }
    }

    /// <summary>M3: some <see cref="AddUnverified"/> was a coverage gap.</summary>
    public bool HasCoverageGap { get; private set; }

    /// <summary>Takes over what the rules found about another command of this entry (the same signal counts once).</summary>
    internal void Merge(PersistenceRuleContext other)
    {
        foreach (var signal in other.Signals.Where(s => !(other.IsMicrosoftSystemTarget && s.Strength == PersistenceSignalStrength.Weak)))
        {
            if (!_signals.Any(s => s.Rule == signal.Rule && s.Reason == signal.Reason))
            {
                _signals.Add(signal);
            }
        }

        _carried.AddRange(other.Carried);
        _unverified.AddRange(other.UnverifiedReasons);
        HasCoverageGap |= other.HasCoverageGap;
    }

    public void Add(PersistenceSignal signal)
    {
        ArgumentNullException.ThrowIfNull(signal);
        _signals.Add(signal);
    }

    public void Add(
        string rule, int score, string reason, string? techniqueId = null, PersistenceSignalStrength strength = PersistenceSignalStrength.Normal,
        ThreatCategory? category = null) =>
        Add(new PersistenceSignal(rule, score, reason, techniqueId, strength, category));

    /// <summary>Carries a target / host detection over to the entry, with the entry kind's technique added as a secondary.</summary>
    public void Carry(Detection detection, bool fromHost)
    {
        ArgumentNullException.ThrowIfNull(detection);
        var secondaries = detection.SecondaryTechniqueIds.Append(KindTechnique)
            .Where(t => t != detection.TechniqueId).Distinct(StringComparer.Ordinal).ToArray();
        _carried.Add(detection with
        {
            Reason = (fromHost ? "Autostart host: " : "Autostart target: ") + detection.Reason,
            SecondaryTechniqueIds = secondaries,
        });
    }

    /// <summary>A short display name for the target (its file name), or the command line when there is none.</summary>
    public string TargetName => TargetPath is { } path ? Path.GetFileName(ExactPath.StripPrefix(path)) : Shorten(Entry.CommandLine);

    internal static string Shorten(string text, int max = 120) => text.Length <= max ? text : string.Concat(text.AsSpan(0, max - 1), "…");

    private static Writability Cached(Dictionary<string, Writability> cache, string path, Func<string, Writability> probe)
    {
        if (!cache.TryGetValue(path, out var value))
        {
            value = probe(path);
            cache[path] = Enum.IsDefined(value) ? value : Writability.Unknown;
            value = cache[path];
        }

        return value;
    }
}
