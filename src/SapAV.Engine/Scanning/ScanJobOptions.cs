namespace SapAV.Engine.Scanning;

/// <summary>Scan job settings (<c>appsettings.json</c> section <c>ScanJobs</c>).</summary>
public sealed class ScanJobOptions
{
    public const string SectionName = "ScanJobs";

    /// <summary>Files waiting between the enumerator and the scan threads of one job. A full queue pauses enumeration (back-pressure).</summary>
    public int QueueCapacity { get; set; } = 256;

    /// <summary>Dedicated scan threads per job (each opens one file and waits for the sandboxed worker). 1-8.</summary>
    public int ThreadsPerJob { get; set; } = 2;

    /// <summary>Jobs that may run at the same time; starting one more is refused (B4 reports it).</summary>
    public int MaxConcurrentJobs { get; set; } = 2;

    /// <summary>
    /// Review B H3: standard-user jobs (all users together) that may run or be paused at once. At most
    /// <see cref="MaxConcurrentJobs"/> - 1, so at least one slot is always kept for administrator and engine jobs.
    /// </summary>
    public int MaxRunningStandardUserJobs { get; set; } = 1;

    /// <summary>Review B H3: a job paused for longer than this is cancelled (a paused job still holds a slot).</summary>
    public TimeSpan MaxPauseTime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Finished jobs kept for status queries; the oldest finished job is forgotten first.</summary>
    public int MaxRetainedJobs { get; set; } = 16;

    /// <summary>Per-job time budget (review A L5): a job still running after this ends as TimedOut with partial results.</summary>
    public TimeSpan TimeBudget { get; set; } = TimeSpan.FromHours(8);

    /// <summary>Per-file results kept per job (every non-clean file is kept first; counters are always exact).</summary>
    public int MaxRecordedResults { get; set; } = 5000;

    /// <summary>Most Malicious files auto-quarantined per <see cref="AutoQuarantineWindow"/>; the rest need the user (review B5 M3).</summary>
    public int AutoQuarantineMaxPerWindow { get; set; } = 20;

    public TimeSpan AutoQuarantineWindow { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Alerts waiting for the single Event Log writer; when full, new alerts are dropped and counted in the summary.</summary>
    public int AlertQueueCapacity { get; set; } = 256;

    /// <summary>Window for alert aggregation: one alert per type + hash + path per window, and at most <see cref="MaxAlertsPerWindow"/> in total.</summary>
    public TimeSpan AlertWindow { get; set; } = TimeSpan.FromMinutes(10);

    public int MaxAlertsPerWindow { get; set; } = 200;

    /// <summary>Extra folders never scanned or auto-quarantined (the engine's own data folders are always excluded).</summary>
    public List<string> ExcludedFolders { get; set; } = [];

    /// <summary>
    /// Extra folders where auto-quarantine is refused and the user must confirm. Windows, Program Files (both) are always
    /// protected, as are files owned by SYSTEM or TrustedInstaller.
    /// </summary>
    public List<string> ProtectedFolders { get; set; } = [];

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(QueueCapacity, 1, nameof(QueueCapacity));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(QueueCapacity, 100_000, nameof(QueueCapacity));
        ArgumentOutOfRangeException.ThrowIfLessThan(ThreadsPerJob, 1, nameof(ThreadsPerJob));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ThreadsPerJob, 8, nameof(ThreadsPerJob));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxConcurrentJobs, 1, nameof(MaxConcurrentJobs));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRunningStandardUserJobs, 1, nameof(MaxRunningStandardUserJobs));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxRunningStandardUserJobs, Math.Max(1, MaxConcurrentJobs - 1), nameof(MaxRunningStandardUserJobs));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPauseTime, TimeSpan.FromSeconds(1), nameof(MaxPauseTime));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRetainedJobs, 1, nameof(MaxRetainedJobs));
        ArgumentOutOfRangeException.ThrowIfLessThan(TimeBudget, TimeSpan.FromSeconds(1), nameof(TimeBudget));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRecordedResults, 1, nameof(MaxRecordedResults));
        ArgumentOutOfRangeException.ThrowIfLessThan(AutoQuarantineMaxPerWindow, 0, nameof(AutoQuarantineMaxPerWindow));
        ArgumentOutOfRangeException.ThrowIfLessThan(AutoQuarantineWindow, TimeSpan.FromSeconds(1), nameof(AutoQuarantineWindow));
        ArgumentOutOfRangeException.ThrowIfLessThan(AlertQueueCapacity, 1, nameof(AlertQueueCapacity));
        ArgumentOutOfRangeException.ThrowIfLessThan(AlertWindow, TimeSpan.FromSeconds(1), nameof(AlertWindow));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxAlertsPerWindow, 1, nameof(MaxAlertsPerWindow));
    }
}
