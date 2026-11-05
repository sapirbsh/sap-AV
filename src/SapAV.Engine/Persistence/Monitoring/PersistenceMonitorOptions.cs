namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>Real-time persistence monitoring settings (<c>appsettings.json</c> section <c>PersistenceMonitor</c>, ROADMAP D4).</summary>
public sealed class PersistenceMonitorOptions
{
    public const string SectionName = "PersistenceMonitor";

    /// <summary>Watch the autostart locations and judge new or changed entries (default on).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Wait after the engine starts before the first collection (the scan workers and the rules load first).</summary>
    public TimeSpan StartDelay { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>Quiet time after the last change of a scope before it is collected again (coalesces bursts, e.g. an installer).</summary>
    public TimeSpan SettleDelay { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>A scope that keeps changing is collected no later than this after its first change.</summary>
    public TimeSpan MaxSettleDelay { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>A scope is collected at most this often, however often it changes (the storm cap per scope and user).</summary>
    public TimeSpan MinInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The services scope at most this often: the Services tree also holds service state that Windows writes often (the
    /// Background Activity Moderator writes under <c>Services\bam</c> on process starts), and only administrators can add services.
    /// </summary>
    public TimeSpan ServicesMinInterval { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>A scope with entries still waiting for judgement (a storm, or the initial baseline) is taken up again after this, behind other users.</summary>
    public TimeSpan ContinuationDelay { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Everything is collected again this often (background priority): catches what no notification reported.</summary>
    public TimeSpan SafetyRescanInterval { get; set; } = TimeSpan.FromMinutes(45);

    /// <summary>How often the loaded user hives under HKEY_USERS are listed (a logon loads one, a logoff unloads it).</summary>
    public TimeSpan HiveCheckInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How often what is watched is re-resolved and re-checked (a folder replaced by a link, a redirected Startup folder).</summary>
    public TimeSpan RevalidateInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Most entries judged in one pass (each new target file is scanned); the rest wait for the scope's next turn.</summary>
    public int MaxJudgedPerPass { get; set; } = 64;

    /// <summary>
    /// Review H1: an entry whose target the judgement couldn't reach (time, a cap, a failed open or scan) stays unjudged and is
    /// tried again after this, doubling per attempt up to <see cref="CoverageRetryMax"/>.
    /// </summary>
    public TimeSpan CoverageRetryBase { get; set; } = TimeSpan.FromSeconds(30);

    public TimeSpan CoverageRetryMax { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Review H1: after this many attempts in a row a Warning says the entry still can't be verified (it is still retried).</summary>
    public int CoverageWarnAfter { get; set; } = 5;

    /// <summary>Review H4: a key judged less than this ago that changes again waits until then (a key rewritten over and over can't use the worker up).</summary>
    public TimeSpan RejudgeMinInterval { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Review H5: a scope cut short (a cap or a budget) this many passes in a row raises a Warning.</summary>
    public int TruncationWarnAfter { get; set; } = 3;

    /// <summary>
    /// Section D review H2: a pass still running after this has its synchronous I/O cancelled (CancelSynchronousIo), again every
    /// second, so an open stuck behind an oplock break the holder never acknowledges can't freeze the monitor thread.
    /// </summary>
    public TimeSpan PassWatchdog { get; set; } = TimeSpan.FromMinutes(3);

    /// <summary>The time budget of one pass's collection (the whole collection's budget is never exceeded).</summary>
    public TimeSpan CollectionTimeBudget { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>No new target scan starts after this within one pass; the rest are judged without a scan.</summary>
    public TimeSpan ScanTimeBudget { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Most entries named one by one in the log per pass (new, changed, removed); the rest are counted.</summary>
    public int MaxLoggedChangesPerPass { get; set; } = 50;

    /// <summary>The watcher buffer per watched folder (Startup folders, the Tasks folder).</summary>
    public int WatcherBufferBytes { get; set; } = 16 * 1024;

    /// <summary>The baseline folder; null = <c>%ProgramData%\sap-AV\Persistence</c>.</summary>
    public string? Folder { get; set; }

    internal string ResolvedFolder => string.IsNullOrWhiteSpace(Folder) ? Path.Combine(Scanning.EngineDataFolders.ProgramDataRoot, "Persistence") : Folder;

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegative(StartDelay.Ticks, nameof(StartDelay));
        ArgumentOutOfRangeException.ThrowIfNegative(SettleDelay.Ticks, nameof(SettleDelay));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxSettleDelay, SettleDelay, nameof(MaxSettleDelay));
        ArgumentOutOfRangeException.ThrowIfNegative(MinInterval.Ticks, nameof(MinInterval));
        ArgumentOutOfRangeException.ThrowIfNegative(ServicesMinInterval.Ticks, nameof(ServicesMinInterval));
        ArgumentOutOfRangeException.ThrowIfNegative(ContinuationDelay.Ticks, nameof(ContinuationDelay));
        ArgumentOutOfRangeException.ThrowIfLessThan(SafetyRescanInterval, TimeSpan.FromMinutes(1), nameof(SafetyRescanInterval));
        ArgumentOutOfRangeException.ThrowIfLessThan(HiveCheckInterval, TimeSpan.FromSeconds(1), nameof(HiveCheckInterval));
        ArgumentOutOfRangeException.ThrowIfLessThan(RevalidateInterval, TimeSpan.FromSeconds(1), nameof(RevalidateInterval));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxJudgedPerPass, 1, nameof(MaxJudgedPerPass));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxJudgedPerPass, 4096, nameof(MaxJudgedPerPass));
        ArgumentOutOfRangeException.ThrowIfLessThan(CollectionTimeBudget, TimeSpan.FromSeconds(1), nameof(CollectionTimeBudget));
        ArgumentOutOfRangeException.ThrowIfLessThan(PassWatchdog, TimeSpan.FromMilliseconds(100), nameof(PassWatchdog));
        ArgumentOutOfRangeException.ThrowIfLessThan(ScanTimeBudget, TimeSpan.FromSeconds(1), nameof(ScanTimeBudget));
        ArgumentOutOfRangeException.ThrowIfNegative(MaxLoggedChangesPerPass, nameof(MaxLoggedChangesPerPass));
        ArgumentOutOfRangeException.ThrowIfLessThan(CoverageRetryBase, TimeSpan.FromMilliseconds(1), nameof(CoverageRetryBase));
        ArgumentOutOfRangeException.ThrowIfLessThan(CoverageRetryMax, CoverageRetryBase, nameof(CoverageRetryMax));
        ArgumentOutOfRangeException.ThrowIfLessThan(CoverageWarnAfter, 1, nameof(CoverageWarnAfter));
        ArgumentOutOfRangeException.ThrowIfNegative(RejudgeMinInterval.Ticks, nameof(RejudgeMinInterval));
        ArgumentOutOfRangeException.ThrowIfLessThan(TruncationWarnAfter, 1, nameof(TruncationWarnAfter));
        ArgumentOutOfRangeException.ThrowIfLessThan(WatcherBufferBytes, 4096, nameof(WatcherBufferBytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(WatcherBufferBytes, 1024 * 1024, nameof(WatcherBufferBytes));
    }
}
