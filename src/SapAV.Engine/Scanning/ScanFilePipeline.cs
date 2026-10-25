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
internal sealed class ScanFilePipeline(
    IScanBroker broker, ExclusionSet excluded, IScanVerdictHandler? handler, TimeProvider time, ILogger logger, IRemoteFileProbe? remote = null)
{
    /// <summary>Longest <see cref="ScanJobFileResult.Detail"/> kept.</summary>
    public const int MaxDetailLength = 512;

    /// <summary>
    /// Scans one file; null if it turned out to be in an excluded folder (nothing scanned). Throws only
    /// <see cref="OperationCanceledException"/> for <paramref name="jobToken"/>.
    /// </summary>
    /// <param name="folder">The listed folder the file was found in (the caller keeps its reference), so the file is opened
    /// relative to that handle; null = reach <paramref name="path"/> component by component (<see cref="SafeTree"/>).</param>
    /// <param name="name">The file's name in <paramref name="folder"/>.</param>
    /// <param name="priority">Who the scan is for, for the next free worker (review B H3).</param>
    public async Task<ScanJobFileResult?> ProcessAsync(
        string path, ScanTrigger trigger, Action<long> bytesScanned, CancellationToken jobToken, IScanAccessCheck? access = null,
        SharedFolder? folder = null, string? name = null, ScanPriority priority = ScanPriority.Normal, bool allowRemote = false)
    {
        string step = "open";
        try
        {
            var item = new ScanItem(path, trigger);
            var notes = new List<ScanNote>();

            // Blocking: we are on a dedicated thread. Review B H2: every job (standard user, administrator, engine) opens
            // without following links, relative to the folder handle the walker listed when there is one (review B4 M2).
            // C1 / B4 L3: the requester's read access is checked inside the open, before anything else about the file
            // (exclusion, different file, lock, size, remote) can show in the result.
            using var opened = SafeScanOpen.Open(item, notes, time, out var failure, out var skip, new ScanOpenChecks(access, allowRemote, remote),
                folder, name);
            if (skip == ScanSkipReason.NoAccess)
            {
                return NoAccessResult(path);
            }

            if (opened is not null && excluded.Contains(opened.Identity?.FinalPath))
            {
                return null; // e.g. reached through an 8.3 name: the final path is an engine folder
            }

            if (DifferentFile(item, opened) is { } different)
            {
                logger.LogWarning("Scan of {Path}: {Why}", path, different);
                return new ScanJobFileResult(path, ScanStatus.Error, null, ScanFileAction.None, different, null, null, null)
                {
                    SkipReason = ScanSkipReason.DifferentFile,
                };
            }

            item = Canonical(item, opened);

            step = "scan";
            var report = opened is null ? failure! : await broker.ScanOpenedAsync(item, opened, notes, priority, jobToken).ConfigureAwait(false);
            bytesScanned(report.Hash.Length ?? 0);

            step = "post-scan";
            var outcome = handler is null ? ScanVerdictOutcome.Nothing : await handler.HandleAsync(report, opened, jobToken).ConfigureAwait(false);
            var result = ToResult(report, outcome);
            return skip is { } why ? result with { SkipReason = why } : result;
        }
        catch (OperationCanceledException) when (jobToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogWarning(ex, "Scan job step '{Step}' failed for {Path}; the file is NotScanned (Error).", step, path);
            if (access is not null && step == "open")
            {
                return NoAccessResult(path); // B4 L3: nothing was checked yet, so nothing is told
            }

            return new ScanJobFileResult(path, ScanStatus.Error, null, ScanFileAction.None,
                $"Not scanned (Error): the {step} step failed ({ex.GetType().Name}).", null, null, null)
            {
                SkipReason = ScanSkipReason.Error,
            };
        }
    }

    /// <summary>B4 L3: the requester can't read the file: AccessDenied, with nothing about the file (no hash, no reason).</summary>
    private static ScanJobFileResult NoAccessResult(string path) =>
        new(path, ScanStatus.AccessDenied, null, ScanFileAction.None, "Not scanned: you can't read this file, or it couldn't be checked.",
            null, null, null)
        {
            SkipReason = ScanSkipReason.NoAccess,
            RequesterCouldRead = false,
        };

    /// <summary>
    /// True if the requested path names the same location as the handle's final path (drive-letter form): equal exactly
    /// (only "." / ".." resolved, trailing dots and spaces kept, case-insensitive), or equal once each 8.3 component of the
    /// request matches the short name of that component of the final path. Short names are read from handles opened through
    /// <see cref="SafeTree"/> (review B H2: no path lookup that could follow a link, unlike <c>GetLongPathNameW</c>).
    /// </summary>
    /// <param name="shortNameOf">Test seam: the short name of a final-path prefix.</param>
    internal static bool SameLocation(string requestedPath, string finalPath, Func<string, string?>? shortNameOf = null)
    {
        if (ExactPath.ToExtended(requestedPath) is not { } exact)
        {
            return false;
        }

        string requested = ExactPath.StripPrefix(exact).TrimEnd('\\');
        if (string.Equals(requested, finalPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var wanted = requested.Split('\\');
        var actual = finalPath.Split('\\');
        if (wanted.Length != actual.Length)
        {
            return false;
        }

        for (int i = 0; i < wanted.Length; i++)
        {
            if (string.Equals(wanted[i], actual[i], StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (i == 0 || !wanted[i].Contains('~', StringComparison.Ordinal)
                || !string.Equals((shortNameOf ?? ShortNameOf)(string.Join('\\', actual, 0, i + 1)), wanted[i], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static string? ShortNameOf(string path)
    {
        using var handle = SafeTree.Open(path, Quarantine.Native.QuarantineNative.FileReadAttributes, SafeTree.ShareAll, 0, out _, out _);
        return handle is null ? null : Native.ScanNative.TryGetShortName(handle);
    }

    /// <summary>
    /// B3 review H1 / review B H2: the open must have reached the file that was asked for. If the handle's final path differs
    /// from the requested path (after 8.3 expansion), something redirected or translated it: a plain <c>evil.exe.</c> opening
    /// the harmless <c>evil.exe</c> next to it, or a parent folder renamed or replaced between the listing and the open.
    /// Judging that file would hide the real one, so it isn't. Null when they agree (or the file system can't report a final
    /// path; the quarantine refuses those anyway). The message names files only, never the other folder.
    /// </summary>
    internal static string? DifferentFile(ScanItem item, OpenedScanFile? opened)
    {
        string? finalPath = opened?.Identity?.FinalPath;
        if (finalPath is null || SameLocation(item.Path, finalPath))
        {
            return null;
        }

        string requested = ExactPath.ToExtended(item.Path) is { } exact ? ExactPath.StripPrefix(exact) : item.Path;
        string requestedName = requested[(requested.LastIndexOf('\\') + 1)..];
        string finalName = finalPath[(finalPath.LastIndexOf('\\') + 1)..];
        return string.Equals(requestedName, finalName, StringComparison.OrdinalIgnoreCase)
            ? $"Not scanned (Error): opening '{requestedName}' reached a file of that name in a different folder; it was not judged."
            : $"Not scanned (Error): opening '{requestedName}' reached a different file ('{finalName}'); it was not judged.";
    }

    /// <summary>
    /// Review B2 follow-up Low: <c>Path.GetFullPath</c> doesn't expand 8.3 names (e.g. <c>C:\Users\RUNNER~1\...</c>), so
    /// the quarantine would see a "redirect" for a plain short-name spelling. If the requested path is the handle's final
    /// path (<see cref="SameLocation"/>), the job continues with the final path (same object, same folders, only the
    /// canonical spelling; in <c>\\?\</c> form if a name ends in a dot or space, so it stays exact). Anything else keeps the
    /// requested path, so the quarantine's redirect check still refuses it.
    /// </summary>
    internal static ScanItem Canonical(ScanItem item, OpenedScanFile? opened)
    {
        string? finalPath = opened?.Identity?.FinalPath;
        if (finalPath is null || !SameLocation(item.Path, finalPath))
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
            Detections = result.Detections,
            SignatureStatus = result.SignatureStatus,
            Signer = result.Signer,
            SourceUrl = Core.Motw.MarkOfTheWeb.SanitizeUrlForLog(report.SourceUrl),
            SkipReason = result.Status == ScanStatus.Scanned ? null : SkipReasonOf(report.Hash.FailureReason, result.Status),
        };
    }

    /// <summary>The engine's classification of a not-scanned report (from the enum the hasher / opener set, never from text).</summary>
    internal static ScanSkipReason SkipReasonOf(HashFailureReason reason, ScanStatus status) => reason switch
    {
        HashFailureReason.AccessDenied => ScanSkipReason.AccessDenied,
        HashFailureReason.Locked => ScanSkipReason.Locked,
        HashFailureReason.TooLarge => ScanSkipReason.TooLarge,
        HashFailureReason.Offline => ScanSkipReason.Offline,
        HashFailureReason.NotFound => ScanSkipReason.NotFound,
        HashFailureReason.NotRegularFile or HashFailureReason.Directory or HashFailureReason.InvalidPath => ScanSkipReason.NotRegularFile,
        HashFailureReason.ChangedDuringHashing => ScanSkipReason.ChangedDuringScan,
        HashFailureReason.BlockedByAntivirus => ScanSkipReason.BlockedByAntivirus,
        _ => status switch
        {
            ScanStatus.Locked => ScanSkipReason.Locked,
            ScanStatus.SkippedTooLarge => ScanSkipReason.TooLarge,
            ScanStatus.SkippedOffline => ScanSkipReason.Offline,
            ScanStatus.AccessDenied => ScanSkipReason.AccessDenied,
            _ => ScanSkipReason.Error,
        },
    };
}
