namespace SapAV.Engine.Scanning.Checks;

/// <summary>Full Scan settings (<c>appsettings.json</c> section <c>FullScan</c>, ROADMAP C6).</summary>
public sealed class FullScanOptions
{
    public const string SectionName = "FullScan";

    /// <summary>What "no time budget" means: a Full Scan runs to completion (or until cancelled); this only keeps the job's arithmetic finite.</summary>
    public static readonly TimeSpan NoBudget = TimeSpan.FromDays(365);

    /// <summary>Running-time budget; null (default) = none, the scan runs to completion unless cancelled.</summary>
    public TimeSpan? TimeBudget { get; set; }

    /// <summary>Deepest folder nesting walked below a drive root (review B3 M2); deeper folders are counted, not walked.</summary>
    public int MaxDepth { get; set; } = 200;

    /// <summary>Most directory entries one Full Scan lists over all drives (review B3 M2); past it the scan stops, marked incomplete.</summary>
    public long MaxEntries { get; set; } = 25_000_000;

    /// <summary>Folders below each drive root that are not walked (system-owned snapshot data).</summary>
    public string[] SkippedRootFolders { get; set; } = ["System Volume Information"];

    /// <summary>
    /// Files at each drive root that the system keeps open exclusively (paging, hibernation, swap, crash dump); they are
    /// skipped and counted instead of being reported Locked one by one.
    /// </summary>
    public string[] SkippedRootFiles { get; set; } = ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "DumpStack.log.tmp", "DumpStack.log"];

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        if (TimeBudget is { } budget)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(budget, TimeSpan.FromMinutes(1), nameof(TimeBudget));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(budget, NoBudget, nameof(TimeBudget));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(MaxDepth, 1, nameof(MaxDepth));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxDepth, ScanTreeWalker.MaxDepth - 1, nameof(MaxDepth));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxEntries, 1, nameof(MaxEntries));
        ArgumentNullException.ThrowIfNull(SkippedRootFolders);
        ArgumentNullException.ThrowIfNull(SkippedRootFiles);
    }
}
