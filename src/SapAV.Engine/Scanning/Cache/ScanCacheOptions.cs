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

    /// <summary>Largest stored report (the scan worker's wire form, notes stripped); bigger ones aren't cached.</summary>
    public int MaxReportBytes { get; set; } = 32 * 1024;

    /// <summary>How long a database call waits for a lock held by another connection.</summary>
    public TimeSpan BusyTimeout { get; set; } = TimeSpan.FromSeconds(5);

    internal string ResolvedFolder => string.IsNullOrWhiteSpace(Folder) ? Path.Combine(EngineDataFolders.ProgramDataRoot, "Cache") : Folder;

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxEntries, 100, nameof(MaxEntries));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxEntries, 5_000_000, nameof(MaxEntries));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxAge, TimeSpan.FromHours(1), nameof(MaxAge));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxReportBytes, 1024, nameof(MaxReportBytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxReportBytes, 256 * 1024, nameof(MaxReportBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(BusyTimeout, TimeSpan.FromMilliseconds(100), nameof(BusyTimeout));
    }
}
