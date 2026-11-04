namespace SapAV.Engine.VirusTotal;

/// <summary>VirusTotal wiring settings (<c>appsettings.json</c> section <c>VirusTotal</c>). On/off and the key are set over the pipe.</summary>
public sealed class VirusTotalOptions
{
    public const string SectionName = "VirusTotal";

    /// <summary>
    /// A VirusTotal answer with at least this many engines saying "malicious" makes the file <b>Malicious</b> (and so
    /// auto-quarantined, reversibly). Default 5: one or two engines alone are often false positives.
    /// </summary>
    public int MaliciousThreshold { get; set; } = 5;

    /// <summary>
    /// Below <see cref="MaliciousThreshold"/> (or for a PUP / HackTool label), at least this many engines saying "malicious" make
    /// the file <b>Suspicious</b> (alert only, never quarantined). Engines saying only "suspicious" don't count (review D3 L2).
    /// Default 3. Fewer is only a scan note. Must not be above <see cref="MaliciousThreshold"/>.
    /// </summary>
    public int SuspiciousThreshold { get; set; } = 3;

    /// <summary>
    /// How long a real-time scan may wait for a free request slot (4 per minute). Default zero: never wait, the file is
    /// reported "VirusTotal not checked" in a note, so a burst of downloads never holds up local detection.
    /// </summary>
    public TimeSpan RealTimeMaxWait { get; set; } = TimeSpan.Zero;

    /// <summary>The same for scan jobs (Suspicious files only). Default zero; at most 2 minutes.</summary>
    public TimeSpan ScanMaxWait { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// Review D3 M3: requests per UTC day kept for scan jobs and autostart targets, which real time can't use. Default 100 of 500,
    /// so real time stops at 400 requests a day.
    /// </summary>
    public int ScanReserve { get; set; } = 100;

    /// <summary>
    /// Review D3 M3: one owner's real-time files may use at most 1/<c>RealTimeOwnerShare</c> of the daily budget. Default 4
    /// (125 of 500). Machine-wide, SYSTEM- and admin-owned files share the engine's own share of the same size.
    /// </summary>
    public int RealTimeOwnerShare { get; set; } = 4;

    /// <summary>After the protected folder or the cache couldn't be opened, how long until the next try.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMinutes(5);

    // ---- Internal (never bound from configuration) ----

    /// <summary>Test seam: the folder for the key, cache, usage counter and settings (default <c>%ProgramData%\sap-AV\VirusTotal</c>).</summary>
    internal string? Folder { get; set; }

    internal string ResolvedFolder => Folder ?? Scanning.EngineDataFolders.VirusTotal;

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(SuspiciousThreshold, 1, nameof(SuspiciousThreshold));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaliciousThreshold, SuspiciousThreshold, nameof(MaliciousThreshold)); // review D3 L2
        ArgumentOutOfRangeException.ThrowIfNegative(ScanReserve, nameof(ScanReserve));
        ArgumentOutOfRangeException.ThrowIfLessThan(RealTimeOwnerShare, 1, nameof(RealTimeOwnerShare));
        ArgumentOutOfRangeException.ThrowIfNegative(RealTimeMaxWait.Ticks, nameof(RealTimeMaxWait));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(RealTimeMaxWait, TimeSpan.FromMinutes(2), nameof(RealTimeMaxWait));
        ArgumentOutOfRangeException.ThrowIfNegative(ScanMaxWait.Ticks, nameof(ScanMaxWait));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ScanMaxWait, TimeSpan.FromMinutes(2), nameof(ScanMaxWait));
        ArgumentOutOfRangeException.ThrowIfLessThan(RetryDelay, TimeSpan.FromSeconds(1), nameof(RetryDelay));
    }
}
