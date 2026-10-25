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
                p.Counters.Quarantined, p.Counters.NeedsUserConfirmation, p.Counters.QuarantineFailed));

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
            Signer: r.Signer is null ? null : Text(r.Signer, MaxSignerLength),
            SourceUrl: r.SourceUrl is null ? null : Text(r.SourceUrl, MaxUrlLength),
            NotScannedReason: r.SkipReason is { } skip ? Map(skip) : null);
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
}
