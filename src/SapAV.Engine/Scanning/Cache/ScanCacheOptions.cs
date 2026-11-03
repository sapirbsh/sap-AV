namespace SapAV.Engine.Scanning.Cache;

/// <summary>Scan cache settings (<c>appsettings.json</c> section <c>ScanCache</c>, ROADMAP C5).</summary>
public sealed class ScanCacheOptions
{
    public const string SectionName = "ScanCache";

    /// <summary>Use the cache (default on). Off = every file is scanned every time.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The cache folder; default <c>%ProgramData%\sap-AV\Cache</c> (created with the protected SYSTEM + Administrators ACL).
    /// The database is <c>scan.db</c> inside it.
    /// </summary>
    public string? Folder { get; set; }

    /// <summary>Most rows kept; past it the least recently used ones are pruned (to 90 %).</summary>
    public int MaxEntries { get; set; } = 200_000;

    /// <summary>Rows not used (looked up or stored) for this long are pruned.</summary>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromDays(60);

    /// <summary>
    /// A verdict older than this is never used, however recently it was looked up (<see cref="MaxAge"/> is an idle age, and
    /// unchanged metadata can be faked by anyone who can write the file on a volume whose journal was reset).
    /// </summary>
    public TimeSpan MaxVerdictAge { get; set; } = TimeSpan.FromDays(14);

    /// <summary>Largest stored report (the scan worker's wire form, notes stripped); bigger ones aren't cached.</summary>
    public int MaxReportBytes { get; set; } = 32 * 1024;

    /// <summary>
    /// D1 (review C5 L1): the database file's size cap (<c>PRAGMA max_page_count</c>), so its disk use is bounded in bytes, not
    /// only in rows (real-time monitoring stores a row for every changed file). When full, the least recently used quarter is
    /// pruned and the store retried once; freed pages are reused, so no VACUUM is needed to stay under the cap.
    /// </summary>
    public long MaxDatabaseBytes { get; set; } = 512L * 1024 * 1024;

    /// <summary>D1 (review C5 L1): files with a longer exact path aren't cached (a deep, long-named tree can't inflate rows).</summary>
    public int MaxPathLength { get; set; } = 1024;

    /// <summary>The page size the cap is counted in (SQLite's default, set when the database is created).</summary>
    internal const int PageSize = 4096;

    internal long MaxPageCount => Math.Max(1, MaxDatabaseBytes / PageSize);

    /// <summary>How long a database call waits for a lock held by another connection.</summary>
    public TimeSpan BusyTimeout { get; set; } = TimeSpan.FromSeconds(5);

    internal string ResolvedFolder => string.IsNullOrWhiteSpace(Folder) ? Path.Combine(EngineDataFolders.ProgramDataRoot, "Cache") : Folder;

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxEntries, 100, nameof(MaxEntries));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxEntries, 5_000_000, nameof(MaxEntries));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxAge, TimeSpan.FromHours(1), nameof(MaxAge));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxVerdictAge, TimeSpan.FromHours(1), nameof(MaxVerdictAge));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxReportBytes, 1024, nameof(MaxReportBytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxReportBytes, 256 * 1024, nameof(MaxReportBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(BusyTimeout, TimeSpan.FromMilliseconds(100), nameof(BusyTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxDatabaseBytes, 1024L * 1024, nameof(MaxDatabaseBytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxDatabaseBytes, 64L * 1024 * 1024 * 1024, nameof(MaxDatabaseBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPathLength, 1, nameof(MaxPathLength));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxPathLength, short.MaxValue, nameof(MaxPathLength));
    }
}
