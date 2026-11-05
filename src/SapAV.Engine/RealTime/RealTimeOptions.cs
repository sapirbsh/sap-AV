namespace SapAV.Engine.RealTime;

/// <summary>Real-time file monitoring settings (<c>appsettings.json</c> section <c>RealTime</c>, ROADMAP D1).</summary>
public sealed class RealTimeOptions
{
    public const string SectionName = "RealTime";

    /// <summary>Watch folders and scan new or changed files (default on).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Watch every profile's Downloads, Desktop, Documents, TEMP and Startup folders, the machine TEMP, the Public profile and
    /// the all-users Startup folder (default on). Off = only <see cref="ExtraFolders"/>.
    /// </summary>
    public bool WatchDefaultFolders { get; set; } = true;

    /// <summary>More folders to watch (an administrator setting; local fixed drives only, links are never followed).</summary>
    public List<string> ExtraFolders { get; set; } = [];

    /// <summary>Most folders watched at once; further ones are left out with a note.</summary>
    public int MaxWatchedFolders { get; set; } = 256;

    /// <summary>Bigger files are not scanned in real time (reported TooLarge); the scan worker never sees them.</summary>
    public long MaxFileSizeBytes { get; set; } = Core.Hashing.Sha256Hasher.DefaultMaxSizeBytes;

    /// <summary>
    /// Dedicated background-mode scan threads (1-4). Each waits for one sandboxed worker at a time, at High priority, so
    /// (review D1 M3) at most WorkerCount − 1 are used when there is more than one worker (<see cref="EffectiveScanThreads"/>):
    /// one worker always stays free for user and administrator jobs.
    /// </summary>
    public int ScanThreads { get; set; } = 1;

    /// <summary>
    /// Review D1 H2: each watched folder may hold at most 1/<c>FolderShareDivisor</c> of <see cref="MaxPendingFiles"/> and of
    /// <see cref="MaxPendingPathChars"/>; past that, only that folder goes into "rescan later".
    /// </summary>
    public int FolderShareDivisor { get; set; } = 8;

    /// <summary>Review D1 H2: an event name longer than this isn't queued; its folder is rescanned later instead.</summary>
    public int MaxQueuedNameLength { get; set; } = 2048;

    /// <summary>Review D1 H2: a file is scanned again at most this often, however often it is rewritten.</summary>
    public TimeSpan MinRescanInterval { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Review D1 H1: a real-time thread stuck in an open longer than this gets its synchronous I/O cancelled.</summary>
    public TimeSpan StuckOpenTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Review D1 H1: the pipeline call (worker scan, alert, quarantine) is overdue after this; its synchronous I/O is cancelled.</summary>
    public TimeSpan StuckScanTimeout { get; set; } = TimeSpan.FromMinutes(3);

    /// <summary>The scan threads actually used with <paramref name="workerCount"/> sandboxed workers (review D1 M3).</summary>
    internal int EffectiveScanThreads(int workerCount) => workerCount > 1 ? Math.Min(ScanThreads, workerCount - 1) : 1;

    /// <summary>
    /// Most files waiting at once (settling, ready or waiting for a writer). Past it, events are dropped and the folder is
    /// marked for a bounded rescan of recently changed files once the queue drains (storm mode).
    /// </summary>
    public int MaxPendingFiles { get; set; } = 10_000;

    /// <summary>Most path characters held by waiting files together (caps queue memory however long the names are).</summary>
    public long MaxPendingPathChars { get; set; } = 4_000_000;

    /// <summary>Quiet time after the last event for a file before it is looked at (coalesces bursts of events for one file).</summary>
    public TimeSpan SettleDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>A file that keeps getting events is looked at no later than this after its first event.</summary>
    public TimeSpan MaxSettleDelay { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>First wait while a writer still has the file open; doubles up to <see cref="LockRetryMax"/>.</summary>
    public TimeSpan LockRetryInitial { get; set; } = TimeSpan.FromMilliseconds(250);

    public TimeSpan LockRetryMax { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long to wait for the writer to close the file. After that the file is scanned anyway with the change-journal
    /// check (or reported Locked), except in-progress download names (<see cref="InProgressExtensions"/>), which are left to
    /// the rename that completes them.
    /// </summary>
    public TimeSpan MaxLockWait { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Browser in-progress download names. They are watched and waited for like any file, but when the wait runs out they are
    /// not scanned half-written: the browser renames the finished file, and that rename is scanned.
    /// </summary>
    public List<string> InProgressExtensions { get; set; } = [".crdownload", ".part", ".partial", ".opdownload", ".download"];

    /// <summary>The watcher's notification buffer per folder (FileSystemWatcher's default is 8 KiB; raised to cut overflows).</summary>
    public int WatcherBufferBytes { get; set; } = 64 * 1024;

    /// <summary>After an overflow or a storm, files changed at most this long before it are rescanned.</summary>
    public TimeSpan RescanLookback { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Most files one rescan queues; the rest is reported (a Quick Scan covers them).</summary>
    public int MaxRescanFiles { get; set; } = 5_000;

    /// <summary>Most directory entries one rescan lists.</summary>
    public long MaxRescanEntries { get; set; } = 200_000;

    /// <summary>Deepest folder a rescan descends into, below the folder it starts from.</summary>
    public int MaxRescanDepth { get; set; } = 32;

    /// <summary>Folder rescans waiting at once (new folders moved in, storms); more collapse into one per watched folder.</summary>
    public int MaxPendingRescans { get; set; } = 256;

    /// <summary>How often the watched folders are re-resolved and re-checked (new profiles, a folder replaced by a link).</summary>
    public TimeSpan RevalidateInterval { get; set; } = TimeSpan.FromMinutes(5);

    internal bool IsInProgressName(string name)
    {
        string extension = Path.GetExtension(name);
        return extension.Length > 0 && InProgressExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxWatchedFolders, 1, nameof(MaxWatchedFolders));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxWatchedFolders, 4096, nameof(MaxWatchedFolders));
        ArgumentOutOfRangeException.ThrowIfNegative(MaxFileSizeBytes, nameof(MaxFileSizeBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(ScanThreads, 1, nameof(ScanThreads));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ScanThreads, 4, nameof(ScanThreads));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingFiles, 4, nameof(MaxPendingFiles));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxPendingFiles, 1_000_000, nameof(MaxPendingFiles));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingPathChars, 1024, nameof(MaxPendingPathChars));
        ArgumentOutOfRangeException.ThrowIfLessThan(FolderShareDivisor, 1, nameof(FolderShareDivisor));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(FolderShareDivisor, 1024, nameof(FolderShareDivisor));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxQueuedNameLength, 64, nameof(MaxQueuedNameLength));
        ArgumentOutOfRangeException.ThrowIfNegative(MinRescanInterval.Ticks, nameof(MinRescanInterval));
        ArgumentOutOfRangeException.ThrowIfNegative(SettleDelay.Ticks, nameof(SettleDelay));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxSettleDelay, SettleDelay, nameof(MaxSettleDelay));
        ArgumentOutOfRangeException.ThrowIfLessThan(LockRetryInitial, TimeSpan.FromMilliseconds(1), nameof(LockRetryInitial));
        ArgumentOutOfRangeException.ThrowIfLessThan(LockRetryMax, LockRetryInitial, nameof(LockRetryMax));
        ArgumentOutOfRangeException.ThrowIfNegative(MaxLockWait.Ticks, nameof(MaxLockWait));
        ArgumentOutOfRangeException.ThrowIfLessThan(WatcherBufferBytes, 4096, nameof(WatcherBufferBytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(WatcherBufferBytes, 1024 * 1024, nameof(WatcherBufferBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(RescanLookback, TimeSpan.FromSeconds(1), nameof(RescanLookback));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRescanFiles, 1, nameof(MaxRescanFiles));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRescanEntries, 1, nameof(MaxRescanEntries));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRescanDepth, 0, nameof(MaxRescanDepth));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxRescanDepth, Scanning.ScanTreeWalker.MaxDepth, nameof(MaxRescanDepth));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingRescans, 1, nameof(MaxPendingRescans));
        ArgumentOutOfRangeException.ThrowIfLessThan(RevalidateInterval, TimeSpan.FromSeconds(1), nameof(RevalidateInterval));
    }
}
