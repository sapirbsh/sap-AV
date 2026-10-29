using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>
/// One phase of a multi-phase scan job (ROADMAP C4): Quick Scan is processes → persistence → high-risk folders → recent
/// files, and the threat pack (E7) adds its own checks (Defender exclusions, proxy / hosts, miner command lines, ...) to
/// Quick and Full Scan without changing the job. A check runs on the job's enumerator thread (a dedicated thread in
/// background mode) and works only through <see cref="IScanCheckContext"/>: it queues files (scanned by the job's scan
/// threads, deduped across phases), scans single files inline when it needs the report, and adds findings that aren't
/// about one file. Pause, cancel and the job's time budget apply at every <see cref="IScanCheckContext.Checkpoint"/>.
/// </summary>
internal interface IScanCheck
{
    /// <summary>The phase name shown in progress and the summary (engine text, e.g. "Running programs").</summary>
    string Name { get; }

    /// <summary>Expected share of the job's time (any positive number; the job normalizes), for the ETA across phases.</summary>
    double Weight { get; }

    /// <summary>
    /// True if this check reads earlier phases' reports through <see cref="IScanCheckContext.ScanNow"/> (persistence reuses
    /// the scans of running programs), so the job keeps them until this check has run.
    /// </summary>
    bool NeedsEarlierReports => false;

    /// <summary>Runs the phase. Throws only <see cref="OperationCanceledException"/> (job cancelled / out of budget) by design.</summary>
    void Run(IScanCheckContext context);
}

/// <summary>What a <see cref="IScanCheck"/> can do inside its job. Not thread-safe: call it from the check's own thread only.</summary>
internal interface IScanCheckContext
{
    CancellationToken CancellationToken { get; }

    TimeProvider Time { get; }

    /// <summary>The job's trigger (QuickScan, FullScan); scans and alerts carry it.</summary>
    ScanTrigger Trigger { get; }

    /// <summary>The job's running time left (paused time doesn't count).</summary>
    TimeSpan RemainingBudget { get; }

    /// <summary>Blocks while the job is paused; throws <see cref="OperationCanceledException"/> once it is cancelled or out of budget.</summary>
    void Checkpoint();

    /// <summary>
    /// Queues one file by path for the job's scan threads (opened later through SafeTree, no link followed). False if it
    /// was already queued or scanned in this job, or is in an excluded folder.
    /// </summary>
    bool QueueFile(string path);

    /// <summary>
    /// Walks <paramref name="roots"/> handle-bound (<see cref="ScanTreeWalker"/> with <paramref name="filter"/>) and queues
    /// the files, deduped. With <paramref name="rank"/>, files are buffered (bounded) and queued lowest rank first.
    /// Review C4 M1: each root gets its own share of the phase's time left (over this call's roots left plus
    /// <paramref name="laterRoots"/> the check will pass in later calls), so one huge root can't starve the others; a root
    /// whose share runs out stops queuing and the phase is marked incomplete.
    /// </summary>
    /// <returns>The roots walked to the end (not cut short by their share).</returns>
    IReadOnlyList<string> QueueTree(IReadOnlyList<string> roots, ScanWalkFilter filter, Func<ScanTreeEntry, int>? rank = null, int laterRoots = 0);

    /// <summary>
    /// Scans one file now, on this thread, through the job's pipeline: SafeScanOpen, the sandboxed broker, then the job's
    /// verdict handler (alert, auto-quarantine policy). Deduped like every other file: a file this job already scanned
    /// returns the earlier report when it was kept (<see cref="IScanCheck.NeedsEarlierReports"/>), else a not-scanned report.
    /// </summary>
    FileScanReport ScanNow(string path);

    /// <summary>
    /// C6: the bytes this phase expects to read (e.g. the used space of the drives it walks), so progress and the ETA can
    /// be estimated before the walk has counted everything. Optional; 0 or less = unknown.
    /// </summary>
    void ExpectBytes(long bytes);

    /// <summary>Blocks until every file this job queued so far is handled (the job also does this at the end of each phase).</summary>
    void WaitForQueuedFiles();

    /// <summary>Files quarantined since this phase started (valid after <see cref="WaitForQueuedFiles"/>).</summary>
    long QuarantinedInPhase { get; }

    /// <summary>Adds a finding that isn't a single file's result (capped per job; the rest are counted).</summary>
    void AddFinding(ScanFinding finding);

    /// <summary>Adds an engine-text line to this phase's summary (capped).</summary>
    void Note(string message);

    /// <summary>This phase couldn't cover everything (its own cap or budget); the job summary says so.</summary>
    void MarkIncomplete(string why);
}

/// <summary>What a finding is about (E adds Defender, proxy / hosts, process behaviour ...).</summary>
public enum ScanFindingCategory
{
    /// <summary>An autostart entry (C2 / C3), <see cref="ScanFinding.Persistence"/> set.</summary>
    Persistence,
}

/// <summary>
/// A job finding that isn't a single file's scan result (C4): verdict, MITRE technique and the alert, plus the payload of
/// its category. Text inside a payload is untrusted (registry values, task files): the pipe maps it with
/// <see cref="Core.Text.SafeText"/> and engine templates (<see cref="Pipe.PipeMapping"/>).
/// </summary>
public sealed record ScanFinding(ScanFindingCategory Category, Verdict Verdict, string TechniqueId, IReadOnlyList<string> SecondaryTechniqueIds, Guid? AlertId)
{
    /// <summary>The judged autostart entry (<see cref="ScanFindingCategory.Persistence"/>).</summary>
    public PersistenceFinding? Persistence { get; init; }

    public static ScanFinding From(PersistenceFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return new ScanFinding(ScanFindingCategory.Persistence, finding.Verdict, finding.Judgement.TechniqueId, finding.Judgement.SecondaryTechniqueIds,
            finding.AlertId)
        {
            Persistence = finding,
        };
    }
}

/// <summary>Where a phase of a multi-phase job is.</summary>
public enum ScanPhaseState
{
    Pending,
    Running,

    /// <summary>The phase covered everything it should.</summary>
    Completed,

    /// <summary>The phase stopped part-way (time budget, cancel, a cap, an error): see its notes.</summary>
    Incomplete,

    /// <summary>The job ended before the phase started.</summary>
    NotRun,
}

/// <summary>One phase of a multi-phase job (C4), for progress and the "complete or not" summary. Engine text only.</summary>
/// <param name="Duration">Running time spent in the phase (paused time excluded), including waiting for its queued files.</param>
/// <param name="Files">Files queued or scanned inline by the phase (after dedupe).</param>
/// <param name="Findings">Findings the phase added.</param>
public sealed record ScanPhaseSummary(string Name, ScanPhaseState State, TimeSpan Duration, long Files, int Findings, IReadOnlyList<string> Notes);
