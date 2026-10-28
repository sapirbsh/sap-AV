using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Engine.Alerts;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Persistence;

/// <summary>Settings of one <see cref="IPersistenceScanner.ScanAsync"/> run.</summary>
internal sealed record PersistenceScanOptions
{
    /// <summary>The trigger the target scans and alerts carry (C4 passes QuickScan / FullScan).</summary>
    public ScanTrigger Trigger { get; init; } = ScanTrigger.Persistence;

    /// <summary>Priority for the next free scan worker (review B H3); the engine's own scans are High.</summary>
    public ScanPriority Priority { get; init; } = ScanPriority.High;

    /// <summary>No new target scan starts after this; the rest are judged without a scan (and an issue says so).</summary>
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Most distinct files (targets + hosts) scanned in one run; the rest are judged without a scan.</summary>
    public int MaxTargets { get; init; } = 4096;

    /// <summary>Target scans in flight at once (1 = one after another on the calling thread).</summary>
    public int Parallelism { get; init; } = 2;

    /// <summary>Post Suspicious / Malicious findings as alerts (2001 / 2002).</summary>
    public bool RaiseAlerts { get; init; } = true;

    /// <summary>Whose alert budget the alerts count against (section B M2); null = the engine's budget for <see cref="Trigger"/>.</summary>
    public AlertBudget? AlertBudget { get; init; }

    /// <summary>The scan budget handed to the optional target handler (C4: alerts + auto-quarantine of the target file).</summary>
    public ScanBudget? TargetBudget { get; init; }
}

/// <summary>The outcome of judging a collection: one finding per entry, plus what couldn't be collected, scanned or judged.</summary>
/// <param name="Findings">One per collected entry, in collection order (Clean ones too, for the results screen).</param>
/// <param name="Issues">The collection's issues, plus scan-budget / target-cap issues of this run.</param>
/// <param name="FilesScanned">Distinct target / host files the broker scanned (status Scanned).</param>
/// <param name="FilesSkipped">Distinct files not scanned because of the time budget or <see cref="PersistenceScanOptions.MaxTargets"/>.</param>
internal sealed record PersistenceScanResult(
    IReadOnlyList<PersistenceFinding> Findings, IReadOnlyList<PersistenceIssue> Issues, int FilesScanned, int FilesSkipped, TimeSpan Duration)
{
    /// <summary>The Suspicious / Malicious findings, worst and highest priority first.</summary>
    public IEnumerable<PersistenceFinding> Detections =>
        Findings.Where(f => f.Verdict != Verdict.Clean).OrderByDescending(f => f.Verdict).ThenByDescending(f => f.Judgement.Priority);
}

/// <summary>
/// Judges every entry of a <see cref="PersistenceCollection"/> (ROADMAP C3). The API Quick Scan (C4), Full Scan (C6) and
/// real-time persistence monitoring (D4) call. Fake it in tests.
/// </summary>
internal interface IPersistenceScanner
{
    /// <summary>
    /// Scans each distinct target / host file once, judges each entry and raises an alert per Suspicious / Malicious
    /// finding. Never throws for a file or entry problem (those become not-scanned targets or issues).
    /// </summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    Task<PersistenceScanResult> ScanAsync(PersistenceCollection collection, PersistenceScanOptions? options = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// The engine's persistence judgement (ROADMAP C3). For a collection:
/// <list type="number">
/// <item>the distinct target and host paths are collected (case-insensitive; a target the resolver already found missing
/// isn't opened), capped at <see cref="PersistenceScanOptions.MaxTargets"/>;</item>
/// <item>each is opened with <see cref="SafeScanOpen"/> (no link followed, no remote file, writers denied or a change-journal
/// check) and scanned by the sandboxed broker (<see cref="IScanBroker.ScanOpenedAsync(ScanItem, OpenedScanFile, IReadOnlyList{ScanNote}, ScanPriority, CancellationToken)"/>):
/// the SYSTEM engine never parses the file and never executes anything. No new scan starts after the time budget;</item>
/// <item>writability comes from the ACLs (<see cref="AclPathWritability"/>, a fresh cache per run);</item>
/// <item>each entry is judged by <see cref="PersistenceJudge"/> and Suspicious / Malicious findings are alerted
/// (<see cref="AlertType.MaliciousPersistence"/> 2001, <see cref="AlertType.SuspiciousPersistence"/> 2002) with action
/// None: nothing is removed or blocked here (Block &amp; remove is D5, always user-confirmed).</item>
/// </list>
/// </summary>
/// <param name="targetHandler">
/// Optional (C4): runs for each scanned target while its scan handle is still open, e.g. the scan job's
/// <see cref="IScanVerdictHandler"/> for the file alert and the auto-quarantine decision on exactly that file. Null in C3.
/// </param>
internal sealed class PersistenceScanner(
    IScanBroker broker, IAlertDispatcher? alerts, TimeProvider time, ILogger? logger = null, PersistenceJudge? judge = null,
    Func<IPathWritability>? writability = null, IScanVerdictHandler? targetHandler = null) : IPersistenceScanner
{
    private readonly IScanBroker _broker = broker ?? throw new ArgumentNullException(nameof(broker));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ILogger _logger = logger ?? NullLogger.Instance;
    private readonly PersistenceJudge _judge = judge ?? new PersistenceJudge(new PersistenceJudgeOptions());
    private readonly Func<IPathWritability> _writability = writability ?? (() => new AclPathWritability());

    public async Task<PersistenceScanResult> ScanAsync(
        PersistenceCollection collection, PersistenceScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(collection);
        options ??= new PersistenceScanOptions();
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MaxTargets, 0);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Parallelism, 1);
        var clock = Stopwatch.StartNew();
        var issues = new List<PersistenceIssue>(collection.Issues);

        var paths = DistinctFiles(collection.Entries);
        var toScan = paths.Take(options.MaxTargets).ToArray();
        if (paths.Count > toScan.Length)
        {
            issues.Add(new PersistenceIssue(null, null, "persistence targets", PersistenceIssueReason.LimitReached,
                $"More than {options.MaxTargets} autostart target files; {paths.Count - toScan.Length} were judged without a scan."));
        }

        var reports = new ConcurrentDictionary<string, FileScanReport>(StringComparer.OrdinalIgnoreCase);
        int skippedByBudget = 0;
        async ValueTask ScanOne(string path, CancellationToken token)
        {
            if (clock.Elapsed > options.TimeBudget)
            {
                Interlocked.Increment(ref skippedByBudget);
                return;
            }

            reports[path] = await ScanFileAsync(path, options, token).ConfigureAwait(false);
        }

        if (options.Parallelism == 1)
        {
            foreach (var path in toScan)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await ScanOne(path, cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            await Parallel.ForEachAsync(toScan, new ParallelOptions { MaxDegreeOfParallelism = options.Parallelism, CancellationToken = cancellationToken },
                ScanOne).ConfigureAwait(false);
        }

        if (skippedByBudget > 0)
        {
            issues.Add(new PersistenceIssue(null, null, "persistence targets", PersistenceIssueReason.TimeBudgetExceeded,
                $"The target scans stopped after {options.TimeBudget.TotalSeconds:0.#} s; {skippedByBudget} files were judged without a scan."));
        }

        var acl = _writability();
        var now = _time.GetUtcNow();
        var findings = new List<PersistenceFinding>(collection.Entries.Count);
        foreach (var entry in collection.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            findings.Add(Judge(entry, reports, acl, options, now));
        }

        int skipped = paths.Count - reports.Count;
        int scanned = reports.Values.Count(r => r.Result.Status == ScanStatus.Scanned);
        _logger.LogInformation("Persistence judgement: {Entries} entries, {Files} files scanned, {Skipped} not scanned, {Detections} detections in {Milliseconds} ms",
            findings.Count, scanned, skipped, findings.Count(f => f.Verdict != Verdict.Clean), clock.ElapsedMilliseconds);
        return new PersistenceScanResult(findings, issues, scanned, skipped, clock.Elapsed);
    }

    /// <summary>Target and host paths in first-seen order, each once (case-insensitive); targets known to be missing are left out.</summary>
    internal static IReadOnlyList<string> DistinctFiles(IEnumerable<PersistenceEntry> entries)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var entry in entries)
        {
            var resolution = entry.Resolution;
            if (resolution.TargetPath is { } target && !resolution.HasFlag(ResolutionFlag.TargetNotFound) && seen.Add(target))
            {
                result.Add(target);
            }

            if (resolution.HostPath is { } host && seen.Add(host))
            {
                result.Add(host);
            }
        }

        return result;
    }

    private PersistenceFinding Judge(
        PersistenceEntry entry, ConcurrentDictionary<string, FileScanReport> reports, IPathWritability acl, PersistenceScanOptions options, DateTimeOffset now)
    {
        var target = entry.Resolution.TargetPath is { } t ? reports.GetValueOrDefault(t) : null;
        var host = entry.Resolution.HostPath is { } h ? reports.GetValueOrDefault(h) : null;
        var judgement = _judge.Judge(entry, target, host, acl);
        var finding = new PersistenceFinding(entry, judgement, target?.Result, host?.Result);
        if (!options.RaiseAlerts || alerts is null || judgement.Verdict == Verdict.Clean)
        {
            return finding;
        }

        try
        {
            if (ScanAlerts.ForPersistence(finding, AlertAction.None, options.Trigger, now) is { } alert)
            {
                if (options.AlertBudget is { } budget)
                {
                    alerts.Post(alert, budget);
                }
                else
                {
                    alerts.Post(alert);
                }

                return finding with { AlertId = alert.AlertId };
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            _logger.LogWarning(ex, "The persistence alert for {Location} couldn't be built", entry.Location);
        }

        return finding;
    }

    /// <summary>One file through the hardened open and the sandboxed broker; a problem becomes a not-scanned report.</summary>
    private async Task<FileScanReport> ScanFileAsync(string path, PersistenceScanOptions options, CancellationToken cancellationToken)
    {
        var item = new ScanItem(path, options.Trigger);
        var notes = new List<ScanNote>();
        try
        {
            using var opened = SafeScanOpen.Open(item, notes, _time, out var failure, out _, ScanOpenChecks.None);
            if (opened is null)
            {
                return failure!;
            }

            if (ScanFilePipeline.DifferentFile(item, opened) is { } different)
            {
                _logger.LogWarning("Persistence target {Path}: {Why}", path, different);
                return ScanFileOpener.NotOpenedReport(item, HashResult.NotHashed(HashFailureReason.NotRegularFile, different), notes, _time.GetUtcNow());
            }

            var report = await _broker.ScanOpenedAsync(ScanFilePipeline.Canonical(item, opened), opened, notes, options.Priority, cancellationToken)
                .ConfigureAwait(false);
            if (targetHandler is not null)
            {
                try
                {
                    await targetHandler.HandleAsync(report, opened, options.TargetBudget, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
                {
                    _logger.LogWarning(ex, "The target handler failed for {Path}; the scan result is kept", path);
                }
            }

            return report; // stored under the entry's own spelling of the path, whatever the broker canonicalized
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Persistence target scan failed for {Path}; it is judged without a verdict", path);
            return ScanFileOpener.NotOpenedReport(item, HashResult.NotHashed(HashFailureReason.IoError, $"The scan failed ({ex.GetType().Name})."),
                notes, _time.GetUtcNow());
        }
    }
}
