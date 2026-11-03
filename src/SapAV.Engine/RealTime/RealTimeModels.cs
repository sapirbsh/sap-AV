using SapAV.Engine.Scanning;

namespace SapAV.Engine.RealTime;

/// <summary>What real-time monitoring did with one file.</summary>
internal enum RealTimeOutcome
{
    /// <summary>Went through the scan pipeline; see <see cref="RealTimeFileResult.Scan"/> (it may still be NotScanned).</summary>
    Scanned,

    /// <summary>In an excluded folder (engine folders, configured exclusions).</summary>
    Excluded,

    /// <summary>Deleted or renamed before it was looked at (normal for temporary files).</summary>
    Gone,

    /// <summary>A junction / symlink, or reached through one: never followed.</summary>
    SkippedLink,

    /// <summary>Over <see cref="RealTimeOptions.MaxFileSizeBytes"/>: not sent to the scan worker.</summary>
    TooLarge,

    /// <summary>Another antivirus blocked it first (ERROR_VIRUS_INFECTED / DELETED). Reported as such, not as an error.</summary>
    BlockedByAntivirus,

    /// <summary>An in-progress download name still open for writing when the wait ran out; its finishing rename is scanned.</summary>
    StillLocked,

    /// <summary>A folder appeared (created or moved in): its files were queued by a bounded rescan.</summary>
    FolderQueued,

    Error,
}

/// <summary>One file's real-time outcome (for the log, the status, tests, and later the GUI).</summary>
/// <param name="Path">The file's path (plain form unless a name needs <c>\\?\</c>).</param>
/// <param name="Scan">The pipeline's result when <paramref name="Outcome"/> is Scanned.</param>
/// <param name="Detail">Engine text: why, for anything but a plain scan.</param>
internal sealed record RealTimeFileResult(string Path, RealTimeOutcome Outcome, ScanJobFileResult? Scan = null, string? Detail = null)
{
    /// <summary>The writer kept the file open past <see cref="RealTimeOptions.MaxLockWait"/>; it was scanned anyway (shared, with the change-journal check) or reported.</summary>
    public bool LockWaitExpired { get; init; }
}

/// <summary>A snapshot of real-time monitoring (counters since start).</summary>
/// <param name="WatchedFolders">Folders watched right now.</param>
/// <param name="RefusedFolders">Configured or default folders not watched right now (a link, missing, not local, ...).</param>
/// <param name="Pending">Files waiting in any state.</param>
/// <param name="Ready">Files due and waiting for a scan thread.</param>
/// <param name="Dropped">Events dropped because the queue was full (their folders are rescanned).</param>
/// <param name="RescansIncomplete">Rescans that hit a cap: some changed files may not have been looked at (a Quick Scan covers them).</param>
internal sealed record RealTimeStatus(
    int WatchedFolders, int RefusedFolders, int Pending, int Ready, long Events, long Coalesced, long Dropped, long Overflows, long Rescans,
    long RescansIncomplete, long Scanned, long Flagged, long Quarantined, long LockRetries, long LockWaitsExpired, long BlockedByAntivirus,
    long Gone, long Links, long TooLarge, long Errors);
