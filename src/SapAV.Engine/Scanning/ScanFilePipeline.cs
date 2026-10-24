using SapAV.Core.Hashing;
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
        string path, ScanTrigger trigger, Action<long> bytesScanned, CancellationToken jobToken, IScanAccessCheck? access = null)
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

            if (DifferentFile(item, opened) is { } different)
            {
                logger.LogWarning("Scan of {Path}: {Why}", path, different);
                return new ScanJobFileResult(path, ScanStatus.Error, null, ScanFileAction.None, different, null, null, null);
            }

            if (access is not null && opened is not null && !access.CanRead(opened.Handle))
            {
                // B4: checked on the scan's own handle, so it is the scanned object; nothing about the file is reported.
                return new ScanJobFileResult(path, ScanStatus.AccessDenied, null, ScanFileAction.None,
                    "Not scanned: the user who requested the scan can't read this file.", null, null, null);
            }

            item = Canonical(item, opened);

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

    /// <summary>
    /// The requested path, exact (only "." / ".." resolved, trailing dots and spaces kept) with 8.3 parts expanded, in the
    /// drive / UNC form the handle's final path uses; null if it can't be computed.
    /// </summary>
    private static string? ExactLongPath(string path)
    {
        var exact = ExactPath.ToExtended(path);
        if (exact is null)
        {
            return null;
        }

        return ExactPath.StripPrefix(Native.ScanNative.TryGetLongPath(exact) ?? exact);
    }

    /// <summary>
    /// B3 review H1: the open must have reached the file that was asked for. If the handle's final file name differs from
    /// the requested name (after 8.3 expansion), something translated the name, e.g. a plain <c>evil.exe.</c> opening the
    /// harmless <c>evil.exe</c> next to it, and judging that file would hide the real one. Null when the names agree (or the
    /// file system can't report a final path; the quarantine refuses those anyway).
    /// </summary>
    internal static string? DifferentFile(ScanItem item, OpenedScanFile? opened)
    {
        string? finalPath = opened?.Identity?.FinalPath;
        if (finalPath is null)
        {
            return null;
        }

        string? requested = ExactLongPath(item.Path);
        string requestedName = requested is null ? Path.GetFileName(item.Path) : requested[(requested.LastIndexOf('\\') + 1)..];
        string finalName = finalPath[(finalPath.LastIndexOf('\\') + 1)..];
        return string.Equals(requestedName, finalName, StringComparison.OrdinalIgnoreCase)
            ? null
            : $"Not scanned (Error): opening '{requestedName}' reached a different file ('{finalName}'); it was not judged.";
    }

    /// <summary>
    /// Review B2 follow-up Low: <c>Path.GetFullPath</c> doesn't expand 8.3 names (e.g. <c>C:\Users\RUNNER~1\...</c>), so
    /// the quarantine would see a "redirect" for a plain short-name spelling. If the exact requested path with its 8.3 parts
    /// expanded is the handle's final path, the job continues with the final path (same object, same folders, only the
    /// canonical spelling; in <c>\\?\</c> form if a name ends in a dot or space, so it stays exact). Anything else (a
    /// junction on the way) keeps the requested path, so the quarantine's redirect check still refuses it.
    /// </summary>
    internal static ScanItem Canonical(ScanItem item, OpenedScanFile? opened)
    {
        string? finalPath = opened?.Identity?.FinalPath;
        if (finalPath is null)
        {
            return item;
        }

        string? longPath = string.Equals(item.Path, finalPath, StringComparison.Ordinal) ? finalPath : ExactLongPath(item.Path);
        if (longPath is null || !string.Equals(longPath, finalPath, StringComparison.OrdinalIgnoreCase))
        {
            return item;
        }

        string canonical = ExactPath.NeedsExtended(finalPath) ? ExactPath.ToExtended(finalPath) ?? item.Path : finalPath;
        return item with { Path = canonical };
    }

    private static ScanJobFileResult ToResult(FileScanReport report, ScanVerdictOutcome outcome)
    {
        var result = report.Result;
        string? detail = outcome.Detail;
        if (detail is null && result.Status != ScanStatus.Scanned)
        {
            detail = report.Notes.LastOrDefault(n => n.Level == ScanNoteLevel.Warning)?.Message ?? $"Not scanned ({result.Status}).";
        }

        bool keepReport = result.Status == ScanStatus.Scanned && result.Verdict is { } verdict && verdict != Verdict.Clean
            && outcome.Action != ScanFileAction.Quarantined && report.Identity is not null;
        return new ScanJobFileResult(result.Item.Path, result.Status, result.Verdict, outcome.Action,
            detail is null ? null : SafeText.SingleLine(detail, MaxDetailLength), result.Sha256, outcome.QuarantineItemId, outcome.AlertId)
        {
            Report = keepReport ? report : null,
        };
    }
}
