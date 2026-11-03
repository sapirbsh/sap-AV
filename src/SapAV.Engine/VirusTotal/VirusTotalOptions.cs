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
    /// Below <see cref="MaliciousThreshold"/>, at least this many engines saying "malicious" or "suspicious" make the file
    /// <b>Suspicious</b> (alert only, never quarantined). Default 2. Fewer is only a scan note.
    /// </summary>
    public int SuspiciousThreshold { get; set; } = 2;

    /// <summary>
    /// How long a real-time scan may wait for a free request slot (4 per minute). Default zero: never wait, the file is
    /// reported "VirusTotal not checked" in a note, so a burst of downloads never holds up local detection.
    /// </summary>
    public TimeSpan RealTimeMaxWait { get; set; } = TimeSpan.Zero;

    /// <summary>The same for scan jobs (Suspicious files only). Default zero; at most 2 minutes.</summary>
    public TimeSpan ScanMaxWait { get; set; } = TimeSpan.Zero;

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
        ArgumentOutOfRangeException.ThrowIfLessThan(MaliciousThreshold, 1, nameof(MaliciousThreshold));
        ArgumentOutOfRangeException.ThrowIfNegative(RealTimeMaxWait.Ticks, nameof(RealTimeMaxWait));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(RealTimeMaxWait, TimeSpan.FromMinutes(2), nameof(RealTimeMaxWait));
        ArgumentOutOfRangeException.ThrowIfNegative(ScanMaxWait.Ticks, nameof(ScanMaxWait));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ScanMaxWait, TimeSpan.FromMinutes(2), nameof(ScanMaxWait));
        ArgumentOutOfRangeException.ThrowIfLessThan(RetryDelay, TimeSpan.FromSeconds(1), nameof(RetryDelay));
    }
}
