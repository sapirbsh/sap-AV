using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>
/// Quick Scan phase 2 (C4): every autostart location. <see cref="IPersistenceCollector.Collect"/> (read-only; M6: a budget of
/// min(60 s, about a quarter of the job's remaining time), the job's pause / cancel / budget checked between sources), then
/// <see cref="IPersistenceScanner.ScanAsync"/> with:
/// <list type="bullet">
/// <item><b>Parallelism 1 and the job's inline scan</b> (<see cref="IScanCheckContext.ScanNow"/>) as the target scanner,
/// so every open stays on the job's background-mode thread (C3 note), pause and the budget apply per target, and a target
/// that is also a running program isn't scanned twice (the job keeps phase 1's reports);</item>
/// <item>the job's verdict handler on each target (through the job pipeline): a Malicious target gets the normal file alert
/// and auto-quarantine policy, protected locations included;</item>
/// <item>persistence alerts 2001 / 2002 through the dispatcher under the engine's budget for the trigger;</item>
/// <item>no removal (Block &amp; remove is D5, user-confirmed).</item>
/// </list>
/// Suspicious / Malicious entries become job findings. When the job budget is nearly used up, the remaining targets are
/// judged without a scan and the phase is Incomplete.
/// </summary>
internal sealed class PersistenceCheck(IPersistenceCollector collector, IPersistenceScanner scanner) : IScanCheck
{
    /// <summary>Budget kept for judging the entries once target scanning stops.</summary>
    public static readonly TimeSpan BudgetReserve = TimeSpan.FromSeconds(5);

    public string Name => "Autostart entries";

    public double Weight => 1.5;

    public bool NeedsEarlierReports => true;

    /// <summary>Most of a job's remaining time the collection may take (M6); the scans of the targets and the later phases need the rest.</summary>
    public const double CollectionShare = 0.25;

    /// <summary>The shortest collection budget given, however little of the job is left.</summary>
    public static readonly TimeSpan MinCollectionBudget = TimeSpan.FromSeconds(1);

    /// <summary>M6: min(the collector's own limit, about a quarter of the job's remaining time), never under <see cref="MinCollectionBudget"/>.</summary>
    internal static TimeSpan CollectionBudget(TimeSpan remaining, TimeSpan limit)
    {
        var share = remaining <= TimeSpan.Zero ? TimeSpan.Zero
            : remaining >= TimeSpan.FromDays(1) ? limit // no job budget to speak of (Full Scan)
            : TimeSpan.FromTicks((long)(remaining.Ticks * CollectionShare));
        var budget = share < limit ? share : limit;
        return budget < MinCollectionBudget ? MinCollectionBudget : budget;
    }

    public void Run(IScanCheckContext context)
    {
        var collection = collector.Collect(context.CancellationToken, new PersistenceCollectOptions
        {
            TimeBudget = CollectionBudget(context.RemainingBudget, new PersistenceLimits().TimeBudget),
            Checkpoint = context.Checkpoint, // pause, cancel and the job's budget between sources
        });
        context.Checkpoint();
        int skippedByBudget = 0;
        var options = new PersistenceScanOptions
        {
            Trigger = context.Trigger,
            Parallelism = 1,
            TimeBudget = TimeSpan.MaxValue, // the job's running-time budget decides (paused time doesn't count)
            RaiseAlerts = true,
            AlertBudget = null, // the engine's budget for the trigger
            ScanTarget = (path, _) =>
            {
                if (context.RemainingBudget < BudgetReserve)
                {
                    skippedByBudget++;
                    return Task.FromResult(NotScanned(path, context));
                }

                return Task.FromResult(context.ScanNow(path));
            },
        };

        var result = scanner.ScanAsync(collection, options, context.CancellationToken).GetAwaiter().GetResult();
        foreach (var finding in result.Ranked)
        {
            context.AddFinding(ScanFinding.From(finding));
        }

        int detections = result.Findings.Count(f => f.Verdict != Verdict.Clean);
        int unverified = result.Findings.Count(f => f.Outcome == PersistenceOutcome.Unverified);
        int inherent = result.Findings.Count(f => f.Outcome == PersistenceOutcome.Unverified && f.Judgement.UnverifiedKind == UnverifiedKind.Inherent);
        context.CountUnverified(inherent);
        context.Note($"{result.Findings.Count} autostart entries, {detections} flagged, {unverified} unverified ({inherent} by how they are written: "
            + $"inline commands, network or device paths, no file), {result.FilesScanned} target files scanned.");
        foreach (var group in result.Issues.GroupBy(i => i.Reason).OrderBy(g => g.Key))
        {
            context.Note($"{group.Count()} location(s) not fully collected: {group.Key}.");
        }

        // Section C review M3: anything not collected makes the phase Incomplete, except what is simply how the machine is
        // (a user who isn't logged on has no loaded hive).
        var incomplete = result.Issues.Where(i => i.Reason is not PersistenceIssueReason.HiveNotLoaded).Select(i => i.Reason).Distinct().Order().ToArray();
        if (incomplete.Length > 0)
        {
            context.MarkIncomplete($"Some autostart locations weren't fully collected: {string.Join(", ", incomplete)}.");
        }

        // M3: only a gap in the scan makes the phase Incomplete; an entry that is unverifiable by how it is written (OneDrive's own
        // Run values, inline commands) is counted above and the phase stays Completed. Also a flagged entry can have a gap.
        int gaps = result.Findings.Count(f => f.Judgement.UnverifiedKind == UnverifiedKind.Coverage);
        if (gaps > 0)
        {
            context.MarkIncomplete($"{gaps} autostart entries run something the scan didn't reach (time, a cap, a locked, denied or placeholder file, a resolver limit).");
        }

        if (skippedByBudget > 0)
        {
            context.MarkIncomplete($"{skippedByBudget} autostart target(s) were judged without a scan: the time budget was nearly used up.");
        }
    }

    private static FileScanReport NotScanned(string path, IScanCheckContext context) =>
        ScanFileOpener.NotOpenedReport(new ScanItem(path, context.Trigger),
            HashResult.NotHashed(HashFailureReason.IoError, "Not scanned: the scan's time budget was nearly used up."), [], context.Time.GetUtcNow());
}
