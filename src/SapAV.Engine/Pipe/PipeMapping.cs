using SapAV.Core.Pipe;
using SapAV.Core.Text;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Pipe;

/// <summary>
/// Engine objects → wire DTOs (B4 output safety). Free text goes through <see cref="SafeText.Display"/> (one line, bidi and
/// invisible format characters → U+FFFD, capped); paths go out exact as <see cref="WirePath"/> for the UI to isolate.
/// Scan-worker free text never reaches a client (review B3 L3): a result's detail is sent only when the engine wrote it
/// (an action outcome), otherwise a fixed template from the status; quarantine reasons (rule names from the scan) are capped hard.
/// </summary>
internal static class PipeMapping
{
    public const int MaxDetailLength = 300;
    public const int MaxReasonLength = 200;
    public const int MaxReasons = 8;
    public const int MaxWarnings = 50;

    public static JobState Map(ScanJobState state) => Enum.Parse<JobState>(state.ToString());

    public static FileAction Map(ScanFileAction action) => Enum.Parse<FileAction>(action.ToString());

    public static QuarantineOutcome Map(QuarantineStatus status) => Enum.Parse<QuarantineOutcome>(status.ToString());

    public static RestoreOutcome Map(RestoreStatus status) => Enum.Parse<RestoreOutcome>(status.ToString());

    public static QuarantineIntegrity Map(QuarantineEntryIntegrity integrity) => Enum.Parse<QuarantineIntegrity>(integrity.ToString());

    public static string Text(string? value, int maxLength = MaxDetailLength) =>
        string.IsNullOrEmpty(value) ? string.Empty : SafeText.Display(value, maxLength);

    public static JobSummary Summary(ScanJob job, bool ownedByCaller) =>
        new(job.Id, Map(job.State), job.Request.Trigger, job.CreatedAt, job.Request.Paths.Select(WirePath.From).ToArray(), ownedByCaller);

    public static JobProgressInfo Progress(ScanJobProgress p) =>
        new(p.JobId, Map(p.State), p.FilesFound, p.FilesTotal, p.FilesDone, p.BytesDone, p.BytesTotal,
            p.CurrentFile is null ? null : WirePath.From(p.CurrentFile), p.Eta, p.Elapsed,
            new JobCountersInfo(p.Counters.Clean, p.Counters.Suspicious, p.Counters.Malicious, p.Counters.NotScanned, p.Counters.Excluded,
                p.Counters.Quarantined, p.Counters.NeedsUserConfirmation, p.Counters.QuarantineFailed, p.Counters.Cached),
            p.Phase is { } phase ? new ScanPhaseProgressInfo(Text(phase.Name, MaxPhaseNameLength), phase.Index, phase.Count) : null);

    public const int MaxSignerLength = 128;
    public const int MaxUrlLength = 512;

    /// <summary>
    /// One result for a client (C1: what the results screen needs). <paramref name="forAdmin"/>: the client is an
    /// administrator, so it gets the scanner's own reason text; everyone else gets engine templates (review B5 M2 / B3 L3:
    /// a compromised worker must not be able to pass text to standard users). The hash only when the requester could read
    /// the file; a result the requester couldn't read carries nothing about the file at all.
    /// </summary>
    public static JobFileResultInfo Result(int resultId, ScanJobFileResult r, bool forAdmin = false)
    {
        var ordered = r.Detections.OrderByDescending(d => d.Verdict).ToArray();
        return new(resultId, WirePath.From(r.Path), r.Status, r.Verdict, Map(r.Action), ResultDetail(r),
            r.RequesterCouldRead ? r.Sha256 : null, r.QuarantineItemId, r.AlertId, r.CanQuarantine,
            Reasons: ordered.Take(MaxReasons).Select(d => forAdmin ? Text(d.Reason, MaxReasonLength) : ReasonTemplate(d)).ToArray(),
            TechniqueIds: TechniqueIds(ordered),
            SignatureStatus: r.SignatureStatus,
            Signer: forAdmin ? (r.Signer is null ? null : Text(r.Signer, MaxSignerLength)) : SignerForUser(r),
            SourceUrl: forAdmin ? (r.SourceUrl is null ? null : Text(r.SourceUrl, MaxUrlLength)) : SourceHostForUser(r.SourceUrl),
            NotScannedReason: r.SkipReason is { } skip ? Map(skip) : null,
            FromCache: r.FromCache);
    }

    /// <summary>
    /// Review C1 M1: the signer name and the URL are scan-worker text, and worker slots are shared by every requester, so a
    /// compromised worker could use them to pass other scans' content to a standard user, or spoof them in the UI. A standard
    /// user gets the fixed word "Microsoft" for a Microsoft signature and nothing otherwise (the status enum still says
    /// OtherTrusted / UnsignedOrInvalid).
    /// </summary>
    internal static string? SignerForUser(ScanJobFileResult r) =>
        r.SignatureStatus == Core.Signatures.SignatureStatus.Microsoft ? "Microsoft" : null;

    /// <summary>
    /// Review C1 M1: a standard user gets only the download host, IDN-normalised to punycode, lowercase, and only if it is
    /// 1-253 characters of a-z, 0-9, '.' and '-'; anything else (IP literals with brackets, odd hosts) is left out.
    /// </summary>
    internal static string? SourceHostForUser(string? url)
    {
        if (url is null || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return null;
        }

        string host;
        try
        {
            host = uri.IdnHost.ToLowerInvariant();
        }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException or ArgumentException)
        {
            return null;
        }

        return host.Length is >= 1 and <= 253 && host.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '-') ? host : null;
    }

    public static NotScannedReason Map(ScanSkipReason reason) => Enum.Parse<NotScannedReason>(reason.ToString());

    /// <summary>Engine text for an action; a template for anything else (the stored detail may quote the scan worker).</summary>
    internal static string? ResultDetail(ScanJobFileResult r) =>
        r.Action != ScanFileAction.None ? Text(r.Detail)
        : r.Status == Core.Models.ScanStatus.Scanned ? null
        : r.SkipReason is { } skip ? SkipText(skip)
        : $"Not scanned ({r.Status}).";

    /// <summary>A detection as engine text only: verdict, source kind and the (format-checked) MITRE technique.</summary>
    internal static string ReasonTemplate(Core.Models.Detection d)
    {
        string source = d.Source switch
        {
            Core.Models.DetectionSource.Blocklist => "its SHA-256 is on the local blocklist",
            Core.Models.DetectionSource.Yara => "a YARA rule matched",
            Core.Models.DetectionSource.Heuristic => "heuristic analysis flagged it",
            Core.Models.DetectionSource.VirusTotal => "VirusTotal reports it",
            Core.Models.DetectionSource.Persistence => "a persistence check flagged it",
            _ => "a detection matched",
        };
        string technique = Core.Mitre.MitreCatalog.TryGet(d.TechniqueId, out var t) ? $"{t.Id} {t.Name}" : d.TechniqueId;
        return $"{d.Verdict}: {source} (MITRE ATT&CK {technique}).";
    }

    private static string[] TechniqueIds(Core.Models.Detection[] ordered) =>
        ordered.SelectMany(d => d.SecondaryTechniqueIds.Prepend(d.TechniqueId))
            .Where(Core.Mitre.MitreTechniqueIdFormat.IsValid)
            .Distinct(StringComparer.Ordinal)
            .Take(MaxReasons)
            .ToArray();

    private static string SkipText(ScanSkipReason reason) => reason switch
    {
        ScanSkipReason.NoAccess => "Not scanned: you can't read this file, or it couldn't be checked.",
        ScanSkipReason.AccessDenied => "Not scanned: the engine was denied access to the file.",
        ScanSkipReason.Locked => "Not scanned: another program has the file locked.",
        ScanSkipReason.TooLarge => "Not scanned: the file is over the size limit.",
        ScanSkipReason.Offline => "Not scanned: the file is offline or cloud-only, so it wasn't downloaded to scan it.",
        ScanSkipReason.NotFound => "Not scanned: the file is gone.",
        ScanSkipReason.NotRegularFile => "Not scanned: not a regular file (or reached through a link).",
        ScanSkipReason.RemoteFile => "Not scanned: the file is on a network share; remote files aren't scanned.",
        ScanSkipReason.DifferentFile => "Not scanned: opening it reached a different file, so it wasn't judged.",
        ScanSkipReason.ChangedDuringScan => "Not scanned: the file changed while it was being scanned.",
        ScanSkipReason.BlockedByAntivirus => "Not scanned: another antivirus blocked access to the file.",
        _ => "Not scanned: an error occurred.",
    };

    public static QuarantineItemInfo Item(QuarantineEntry e) =>
        new(e.Id, Map(e.Integrity), e.State, e.OriginalPath is null ? null : WirePath.From(e.OriginalPath), e.SizeBytes, e.Sha256, e.Verdict,
            e.Reasons.Take(MaxReasons).Select(r => Text(r, MaxReasonLength)).ToArray(),
            e.TechniqueIds.Take(MaxReasons).Select(t => Text(t, 32)).ToArray(), e.QuarantinedAtUtc, e.AlertId, e.HasMarkOfTheWeb);

    public static RestoreReply Restore(RestoreResult r) =>
        new(Map(r.Status), Text(r.Reason), r.RestoredPath is null ? null : WirePath.From(r.RestoredPath),
            r.Notes.Take(MaxReasons).Select(n => Text(n)).ToArray());

    // ---- C4: phases and findings ----

    public const int MaxPhaseNameLength = 64;
    public const int MaxPhaseNotes = 12;
    public const int MaxRuleIdLength = 64;

    public static ScanPhaseInfo Phase(Scanning.Checks.ScanPhaseSummary p) =>
        new(Text(p.Name, MaxPhaseNameLength), Enum.Parse<PhaseState>(p.State.ToString()), p.Duration, p.Files, p.Findings,
            p.Notes.Take(MaxPhaseNotes).Select(n => Text(n)).ToArray());

    /// <summary>
    /// One finding for a client (C4). Entry text (registry values, task files, shortcut targets) is attacker-controlled, so
    /// <paramref name="forAdmin"/> decides what goes out, as for file results: administrators get the judgement's reasons
    /// (sanitised, capped), the command line and the user SID; everyone else gets engine templates (verdict, source,
    /// MITRE, rule identifiers) and no command line. Paths always go out exact as <see cref="WirePath"/> for the UI to
    /// isolate. Quick Scan results are administrator-only today (the pipe refuses Quick Scan to standard users), so the
    /// non-admin form is defense in depth for later finding sources.
    /// </summary>
    public static ScanFindingInfo Finding(int findingId, Scanning.Checks.ScanFinding f, bool forAdmin)
    {
        var techniques = f.SecondaryTechniqueIds.Prepend(f.TechniqueId).Where(Core.Mitre.MitreTechniqueIdFormat.IsValid)
            .Distinct(StringComparer.Ordinal).Take(MaxReasons).ToArray();
        PersistenceFindingInfo? persistence = null;
        IReadOnlyList<string> reasons = [];
        if (f.Persistence is { } p)
        {
            var judgement = p.Judgement;
            var rules = judgement.Signals.Where(s => s.Score > 0).Select(s => s.Rule).Where(IsRuleId).Distinct(StringComparer.Ordinal)
                .Take(MaxReasons).ToArray();
            reasons = forAdmin
                ? judgement.Reasons.Take(MaxReasons).Select(r => Text(r, MaxReasonLength)).ToArray()
                : judgement.Detections.Where(d => d.Source != Core.Models.DetectionSource.Persistence).Select(ReasonTemplate)
                    .Concat(rules.Select(r => $"{f.Verdict}: the autostart check '{r}' scored."))
                    .Take(MaxReasons).ToArray();
            var entry = p.Entry;
            persistence = new PersistenceFindingInfo(entry.Kind, entry.IsMachineScope, forAdmin ? entry.UserSid : null, WirePath.From(entry.Location),
                entry.ValueName is null ? null : WirePath.From(entry.ValueName),
                forAdmin ? WirePath.From(entry.CommandLine) : null,
                entry.Resolution.TargetPath is { } target ? WirePath.From(target) : null,
                entry.Enabled, rules, p.Target?.Verdict);
        }

        return new ScanFindingInfo(findingId, Enum.Parse<FindingCategory>(f.Category.ToString()), f.Verdict, techniques, reasons, f.AlertId, persistence);
    }

    /// <summary>An engine rule identifier: 1-64 of a-z, 0-9 and '-'. Anything else is never sent.</summary>
    internal static bool IsRuleId(string? rule) =>
        rule is { Length: > 0 and <= MaxRuleIdLength } && rule.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');
}
