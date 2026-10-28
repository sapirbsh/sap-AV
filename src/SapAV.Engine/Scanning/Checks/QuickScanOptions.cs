namespace SapAV.Engine.Scanning.Checks;

/// <summary>Quick Scan settings (<c>appsettings.json</c> section <c>QuickScan</c>). Arrays, so a configured list replaces the default.</summary>
public sealed class QuickScanOptions
{
    public const string SectionName = "QuickScan";

    /// <summary>Running-time budget of a whole Quick Scan (ROADMAP: under 3 minutes); over it the scan stops, marked incomplete.</summary>
    public TimeSpan TimeBudget { get; set; } = TimeSpan.FromMinutes(3);

    /// <summary>"Recent" = created, written or changed within this many days (phases 3 and 4).</summary>
    public int RecentDays { get; set; } = 7;

    /// <summary>Folder depth walked below each high-risk folder (phase 3) and each profile / ProgramData (phase 4).</summary>
    public int MaxDepth { get; set; } = 10;

    /// <summary>Larger files are left to Full Scan (counted, not scanned).</summary>
    public long MaxFileSizeBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>
    /// Phase 3 scans these in the high-risk folders (plus any recent file), queued in this priority: executables and
    /// scripts first, then archives / disk images, then Office files that can hold macros; files with a Mark-of-the-Web
    /// (downloaded) before all others.
    /// </summary>
    public string[] ExecutableExtensions { get; set; } =
    [
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".drv", ".ocx", ".msi", ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle",
        ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".wsc", ".hta", ".sct", ".jar", ".lnk", ".url",
        ".reg", ".inf", ".chm", ".application", ".appref-ms", ".settingcontent-ms", ".library-ms", ".py", ".pyw",
    ];

    public string[] ArchiveExtensions { get; set; } =
        [".zip", ".rar", ".7z", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".arj", ".ace", ".lzh", ".z"];

    public string[] OfficeMacroExtensions { get; set; } =
        [".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".xla", ".xlsb", ".pptm", ".potm", ".ppam", ".ppsm", ".sldm", ".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".rtf", ".one"];

    /// <summary>
    /// Big, constantly changing caches under each profile that are not walked (relative to the profile; <c>*</c> = one
    /// folder name). Browser caches hold fetched web content, not saved downloads.
    /// </summary>
    public string[] SkippedProfileFolders { get; set; } =
    [
        @"AppData\Local\Google\Chrome\User Data\*\Cache",
        @"AppData\Local\Google\Chrome\User Data\*\Code Cache",
        @"AppData\Local\Google\Chrome\User Data\*\GPUCache",
        @"AppData\Local\Google\Chrome\User Data\*\Service Worker\CacheStorage",
        @"AppData\Local\Microsoft\Edge\User Data\*\Cache",
        @"AppData\Local\Microsoft\Edge\User Data\*\Code Cache",
        @"AppData\Local\Microsoft\Edge\User Data\*\GPUCache",
        @"AppData\Local\Microsoft\Edge\User Data\*\Service Worker\CacheStorage",
        @"AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cache",
        @"AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Code Cache",
        @"AppData\Local\Mozilla\Firefox\Profiles\*\cache2",
        @"AppData\Local\Microsoft\Windows\INetCache",
        @"AppData\Local\Microsoft\Windows\WebCache",
        @"AppData\Local\Microsoft\Windows\Explorer",
        @"AppData\Local\Packages\*\AC\INetCache",
        @"AppData\Local\D3DSCache",
        @"AppData\Local\NVIDIA\DXCache",
        @"AppData\Local\NVIDIA\GLCache",
        @"AppData\Local\AMD\DxCache",
        @"AppData\Roaming\Code\Cache",
        @"AppData\Roaming\Code\CachedData",
        @"AppData\Roaming\Code\Code Cache",
    ];

    /// <summary>Folders under ProgramData not walked by the recent-files phase (Defender's and the search index's own data).</summary>
    public string[] SkippedProgramDataFolders { get; set; } =
    [
        @"Microsoft\Windows Defender",
        @"Microsoft\Windows Defender Advanced Threat Protection",
        @"Microsoft\Search\Data",
        @"Microsoft\Diagnosis",
        @"Microsoft\Windows\Caches",
    ];

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(TimeBudget, TimeSpan.FromSeconds(10), nameof(TimeBudget));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(TimeBudget, TimeSpan.FromHours(4), nameof(TimeBudget));
        ArgumentOutOfRangeException.ThrowIfLessThan(RecentDays, 1, nameof(RecentDays));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(RecentDays, 365, nameof(RecentDays));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxDepth, 1, nameof(MaxDepth));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxDepth, ScanTreeWalker.MaxDepth, nameof(MaxDepth));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxFileSizeBytes, 1, nameof(MaxFileSizeBytes));
        ArgumentNullException.ThrowIfNull(ExecutableExtensions);
        ArgumentNullException.ThrowIfNull(ArchiveExtensions);
        ArgumentNullException.ThrowIfNull(OfficeMacroExtensions);
        ArgumentNullException.ThrowIfNull(SkippedProfileFolders);
        ArgumentNullException.ThrowIfNull(SkippedProgramDataFolders);
    }
}
