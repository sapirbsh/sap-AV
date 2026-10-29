using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>
/// Quick Scan phase 2 (C4): every autostart location. <see cref="IPersistenceCollector.Collect"/> (read-only, its own
/// 30 s budget), then <see cref="IPersistenceScanner.ScanAsync"/> with:
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

    public void Run(IScanCheckContext context)
    {
        var collection = collector.Collect(context.CancellationToken);
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
        foreach (var finding in result.Findings.Where(f => f.Verdict != Verdict.Clean))
        {
            context.AddFinding(ScanFinding.From(finding));
        }

        int detections = result.Findings.Count(f => f.Verdict != Verdict.Clean);
        context.Note($"{result.Findings.Count} autostart entries, {detections} flagged, {result.FilesScanned} target files scanned.");
        foreach (var group in result.Issues.GroupBy(i => i.Reason).OrderBy(g => g.Key))
        {
            context.Note($"{group.Count()} location(s) not fully collected: {group.Key}.");
        }

        if (result.Issues.Any(i => i.Reason is PersistenceIssueReason.TimeBudgetExceeded or PersistenceIssueReason.LimitReached))
        {
            context.MarkIncomplete("The autostart collection hit its time budget or a cap.");
        }

        if (skippedByBudget > 0)
        {
            context.MarkIncomplete($"{skippedByBudget} autostart target(s) were judged without a scan: the time budget was nearly used up.");
        }
    }

    private static FileScanReport NotScanned(string path, IScanCheckContext context) =>
        ScanFileOpener.NotOpenedReport(new ScanItem(path, context.Trigger),
            HashResult.NotHashed(HashFailureReason.IoError, "Not scanned: the Quick Scan time budget was nearly used up."), [], context.Time.GetUtcNow());
}
