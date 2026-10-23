using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Text;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Scanning;

/// <summary>What the post-scan step (alert + quarantine decision) did with a report.</summary>
internal sealed record ScanVerdictOutcome(ScanFileAction Action, string? Detail = null, string? QuarantineItemId = null, Guid? AlertId = null)
{
    public static ScanVerdictOutcome Nothing { get; } = new(ScanFileAction.None);
}

/// <summary>
/// Runs after a file is scanned, while the scan's handle is still open: alerts and the quarantine decision. Fake it in tests.
/// </summary>
internal interface IScanVerdictHandler
{
    /// <param name="opened">The scan's own handle (null if the file couldn't be opened). Not closed here.</param>
    Task<ScanVerdictOutcome> HandleAsync(FileScanReport report, OpenedScanFile? opened, CancellationToken cancellationToken);

    /// <summary>The job ended (any final state): e.g. emit the alert summary.</summary>
    void JobFinished(ScanJob job);
}

/// <summary>
/// One file through a scan job: open (hardened, on the calling dedicated thread), exclusion check on the handle's final
/// path, the sandboxed scan (<see cref="IScanBroker.ScanOpenedAsync"/>), then <see cref="IScanVerdictHandler"/>.
/// </summary>
/// <remarks>
/// Review A M4: any exception from a step becomes NotScanned (Error) for this file and the job goes on; it is treated as a
/// cancel only when the <b>job's own</b> token is cancelled (an OperationCanceledException from anywhere else, e.g. a
/// timed-out HTTP call inside a step, is just an error).
/// </remarks>
internal sealed class ScanFilePipeline(IScanBroker broker, FolderSet excluded, IScanVerdictHandler? handler, TimeProvider time, ILogger logger)
{
    /// <summary>Longest <see cref="ScanJobFileResult.Detail"/> kept.</summary>
    public const int MaxDetailLength = 512;

    /// <summary>
    /// Scans one file; null if it turned out to be in an excluded folder (nothing scanned). Throws only
    /// <see cref="OperationCanceledException"/> for <paramref name="jobToken"/>.
    /// </summary>
    public async Task<ScanJobFileResult?> ProcessAsync(
        string path, ScanTrigger trigger, Action<long> bytesScanned, CancellationToken jobToken)
    {
        string step = "open";
        try
        {
            var item = new ScanItem(path, trigger);
            var notes = new List<ScanNote>();
            using var opened = ScanFileOpener.Open(item, notes, time, out var failure); // blocking: we are on a dedicated thread
            if (opened is not null && excluded.Contains(opened.Identity?.FinalPath))
            {
                return null; // e.g. reached through an 8.3 name: the final path is an engine folder
            }

            step = "scan";
            var report = opened is null ? failure! : await broker.ScanOpenedAsync(item, opened, notes, jobToken).ConfigureAwait(false);
            bytesScanned(report.Hash.Length ?? 0);

            step = "post-scan";
            var outcome = handler is null ? ScanVerdictOutcome.Nothing : await handler.HandleAsync(report, opened, jobToken).ConfigureAwait(false);
            return ToResult(report, outcome);
        }
        catch (OperationCanceledException) when (jobToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogWarning(ex, "Scan job step '{Step}' failed for {Path}; the file is NotScanned (Error).", step, path);
            return new ScanJobFileResult(path, ScanStatus.Error, null, ScanFileAction.None,
                $"Not scanned (Error): the {step} step failed ({ex.GetType().Name}).", null, null, null);
        }
    }

    private static ScanJobFileResult ToResult(FileScanReport report, ScanVerdictOutcome outcome)
    {
        var result = report.Result;
        string? detail = outcome.Detail;
        if (detail is null && result.Status != ScanStatus.Scanned)
        {
            detail = report.Notes.LastOrDefault(n => n.Level == ScanNoteLevel.Warning)?.Message ?? $"Not scanned ({result.Status}).";
        }

        return new ScanJobFileResult(result.Item.Path, result.Status, result.Verdict, outcome.Action,
            detail is null ? null : SafeText.SingleLine(detail, MaxDetailLength), result.Sha256, outcome.QuarantineItemId, outcome.AlertId);
    }
}
