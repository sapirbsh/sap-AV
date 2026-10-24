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

    public static JobFileResultInfo Result(int resultId, ScanJobFileResult r) =>
        new(resultId, WirePath.From(r.Path), r.Status, r.Verdict, Map(r.Action), ResultDetail(r), r.Sha256, r.QuarantineItemId, r.AlertId,
            r.CanQuarantine);

    /// <summary>Engine text for an action; a template for anything else (the stored detail may quote the scan worker).</summary>
    internal static string? ResultDetail(ScanJobFileResult r) =>
        r.Action != ScanFileAction.None ? Text(r.Detail)
        : r.Status != Core.Models.ScanStatus.Scanned ? $"Not scanned ({r.Status})."
        : null;

    public static QuarantineItemInfo Item(QuarantineEntry e) =>
        new(e.Id, Map(e.Integrity), e.State, e.OriginalPath is null ? null : WirePath.From(e.OriginalPath), e.SizeBytes, e.Sha256, e.Verdict,
            e.Reasons.Take(MaxReasons).Select(r => Text(r, MaxReasonLength)).ToArray(),
            e.TechniqueIds.Take(MaxReasons).Select(t => Text(t, 32)).ToArray(), e.QuarantinedAtUtc, e.AlertId, e.HasMarkOfTheWeb);

    public static RestoreReply Restore(RestoreResult r) =>
        new(Map(r.Status), Text(r.Reason), r.RestoredPath is null ? null : WirePath.From(r.RestoredPath),
            r.Notes.Take(MaxReasons).Select(n => Text(n)).ToArray());
}
