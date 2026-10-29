using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Text;
using SapAV.Engine.Scanning.Checks;

namespace SapAV.Engine.Scanning;

/// <summary>
/// C4: multi-phase jobs (<see cref="ScanJobRequest.Checks"/>). The enumerator thread runs the checks in order; after each
/// one it waits until the files that phase queued are scanned (a barrier), so phase timings are real, the ETA can weigh the
/// phases, and a later phase (persistence) can reuse an earlier phase's reports. One <see cref="ScanDedupe"/> per job
/// makes it one scan per file across phases. Pause, cancel and the time budget work as for any job; when the budget runs
/// out, the running phase is Incomplete, the rest NotRun, and a warning says so.
/// </summary>
public sealed partial class ScanJob
{
    /// <summary>Findings kept per job (the rest are counted in <see cref="FindingsOmitted"/>).</summary>
    public const int MaxRecordedFindings = 2000;

    /// <summary>Most files a ranked walk buffers before queuing the best-ranked ones.</summary>
    internal const int MaxRankedBuffer = 4096;

    private const int MaxPhaseNotes = 12;
    private const int MaxNoteLength = 300;

    private readonly ManualResetEventSlim _drained = new(initialState: true);
    private readonly List<ScanFinding> _findings = [];
    private PhaseState[]? _phases;
    private ScanDedupe? _dedupe;
    private int _phaseIndex = -1;
    private long _findingsOmitted;

    private sealed class PhaseState(IScanCheck check)
    {
        public IScanCheck Check { get; } = check;

        public ScanPhaseState State { get; set; } = ScanPhaseState.Pending;

        public TimeSpan Started { get; set; }

        /// <summary>Running time at which a walk in this phase stops queuing (its weighted share of the budget left).</summary>
        public TimeSpan Deadline { get; set; } = TimeSpan.MaxValue;

        public TimeSpan Duration { get; set; }

        public long Files { get; set; }

        public int Findings { get; set; }

        public List<string> Notes { get; } = [];

        public bool Incomplete { get; set; }

        public bool WalkDone { get; set; }

        public bool ShareNoted { get; set; }

        public long FoundAtStart { get; set; }

        public long DoneAtStart { get; set; }

        public long QuarantinedAtStart { get; set; }

        public long BytesDoneAtStart { get; set; }

        /// <summary>C6: the bytes the phase expects to read (e.g. the used space of the drives), 0 = unknown.</summary>
        public long ExpectedBytes { get; set; }

        public ScanPhaseSummary Snapshot(TimeSpan now) =>
            new(Check.Name, State, State == ScanPhaseState.Running ? now - Started : Duration, Files, Findings, Notes.ToArray());
    }

    /// <summary>Findings that aren't single-file results (persistence entries, later the threat pack's), in the order found.</summary>
    public IReadOnlyList<ScanFinding> Findings
    {
        get
        {
            lock (_lock)
            {
                return _findings.ToArray();
            }
        }
    }

    /// <summary>Findings not kept because of <see cref="MaxRecordedFindings"/>.</summary>
    public long FindingsOmitted
    {
        get
        {
            lock (_lock)
            {
                return _findingsOmitted;
            }
        }
    }

    /// <summary>The phases of a multi-phase job; empty for a plain file / folder job.</summary>
    public IReadOnlyList<ScanPhaseSummary> Phases
    {
        get
        {
            lock (_lock)
            {
                var now = ElapsedLocked();
                return _phases?.Select(p => p.Snapshot(now)).ToArray() ?? [];
            }
        }
    }

    /// <summary>Files not scanned again because this job already had them (C4 dedupe).</summary>
    public long Duplicates => _dedupe?.Duplicates ?? 0;

    /// <summary>True once the job Completed and every phase covered everything it should.</summary>
    public bool IsComplete
    {
        get
        {
            lock (_lock)
            {
                return _state == ScanJobState.Completed && (_phases?.All(p => p.State == ScanPhaseState.Completed) ?? true);
            }
        }
    }

    private void InitChecks(ScanJobRequest request)
    {
        if (request.Checks is { Count: > 0 } checks)
        {
            _phases = checks.Select(c => new PhaseState(c)).ToArray();
            _dedupe = new ScanDedupe();
        }
    }

    // ---- Enumerator thread: the phases ----

    private void RunChecks(IReadOnlyList<IScanCheck> checks, CancellationToken token)
    {
        var context = new CheckContext(this, token);
        for (int i = 0; i < checks.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            var phase = _phases![i];
            lock (_lock)
            {
                _phaseIndex = i;
                phase.State = ScanPhaseState.Running;
                phase.Started = ElapsedLocked();
                phase.Deadline = phase.Started + ShareOfRemaining(checks, i, _budget - phase.Started);
                phase.FoundAtStart = _filesFound;
                phase.DoneAtStart = _filesDone;
                phase.QuarantinedAtStart = _quarantined;
                phase.BytesDoneAtStart = _bytesDone;
                ProgressChangedLocked();
            }

            _dedupe!.KeepReports = checks.Skip(i).Any(c => c.NeedsEarlierReports);
            context.Phase = phase;
            try
            {
                checks[i].Run(context);
                lock (_lock)
                {
                    phase.WalkDone = true;
                }

                WaitForQueued(token);
                EndPhase(phase, phase.Incomplete ? ScanPhaseState.Incomplete : ScanPhaseState.Completed);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                EndPhase(phase, ScanPhaseState.Incomplete);
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // One failing check must not stop the scan: its phase is Incomplete, the next one runs.
                _logger.LogError(ex, "Scan job {JobId}: the '{Phase}' check failed; going on with the next phase.", Id, phase.Check.Name);
                context.MarkIncomplete($"The check failed ({ex.GetType().Name}); the scan went on with the next phase.");
                AddWarning($"The '{phase.Check.Name}' phase failed ({ex.GetType().Name}); its results may be incomplete.");
                try
                {
                    WaitForQueued(token);
                }
                finally
                {
                    EndPhase(phase, ScanPhaseState.Incomplete);
                }
            }
        }
    }

    /// <summary>
    /// A phase's share of the budget left: its weight over the weights of it and every later phase. Walks (folder phases)
    /// stop queuing when their share is used up, so one huge folder tree can't starve the later phases; whatever an
    /// earlier phase didn't use goes to the later ones. The last phase gets everything left.
    /// </summary>
    internal static TimeSpan ShareOfRemaining(IReadOnlyList<IScanCheck> checks, int index, TimeSpan remaining)
    {
        double rest = checks.Skip(index).Sum(c => Math.Max(c.Weight, 0));
        if (remaining <= TimeSpan.Zero || rest <= 0 || index == checks.Count - 1)
        {
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        return TimeSpan.FromTicks((long)(remaining.Ticks * Math.Max(checks[index].Weight, 0) / rest));
    }

    /// <summary>Review C4 M1: one root's deadline in a walk phase (now + the phase's time left over the roots left).</summary>
    internal static TimeSpan RootDeadlineOf(TimeSpan now, TimeSpan phaseDeadline, int rootsLeft) => CheckContext.RootDeadline(now, phaseDeadline, rootsLeft);

    /// <summary>Thrown by a walk's emit once its phase's share is used up; caught in <see cref="CheckContext.QueueTree"/>.</summary>
    private sealed class PhaseShareUsedUpException : Exception
    {
    }

    /// <summary>The barrier at the end of a phase: every file queued so far is handled. A parked wait for pause purposes.</summary>
    private void WaitForQueued(CancellationToken token)
    {
        while (true)
        {
            lock (_lock)
            {
                if (_filesDone >= _filesFound)
                {
                    return;
                }

                _drained.Reset();
            }

            Idle(() => _drained.Wait(token));
        }
    }

    private void EndPhase(PhaseState phase, ScanPhaseState state)
    {
        ScanPhaseSummary summary;
        lock (_lock)
        {
            if (phase.State != ScanPhaseState.Running)
            {
                return;
            }

            phase.State = state;
            phase.Duration = ElapsedLocked() - phase.Started;
            summary = phase.Snapshot(phase.Duration);
            ProgressChangedLocked();
        }

        _logger.LogInformation("Scan job {JobId} phase '{Phase}' {State} in {Milliseconds} ms: {Files} files, {Findings} findings.",
            Id, summary.Name, summary.State, (long)summary.Duration.TotalMilliseconds, summary.Files, summary.Findings);
    }

    /// <summary>At the end of the job: unfinished phases are Incomplete / NotRun, and an incomplete scan says so in a warning.</summary>
    private void FinishPhases(ScanJobState final)
    {
        if (_phases is null)
        {
            return;
        }

        string[] notDone;
        lock (_lock)
        {
            foreach (var phase in _phases)
            {
                if (phase.State == ScanPhaseState.Running)
                {
                    phase.State = ScanPhaseState.Incomplete;
                    phase.Duration = _runningBefore - phase.Started;
                }
                else if (phase.State == ScanPhaseState.Pending)
                {
                    phase.State = ScanPhaseState.NotRun;
                }
            }

            notDone = _phases.Where(p => p.State != ScanPhaseState.Completed).Select(p => $"{p.Check.Name} ({p.State})").ToArray();
        }

        foreach (var phase in Phases)
        {
            _logger.LogInformation("Scan job {JobId} phase summary: '{Phase}' {State}, {Milliseconds} ms, {Files} files, {Findings} findings.",
                Id, phase.Name, phase.State, (long)phase.Duration.TotalMilliseconds, phase.Files, phase.Findings);
        }

        if (notDone.Length > 0)
        {
            string why = final switch
            {
                ScanJobState.TimedOut => $"its time budget of {_budget.TotalMinutes:0.#} min ran out",
                ScanJobState.Cancelled => "it was cancelled",
                ScanJobState.Failed => "an internal error stopped it",
                _ => "some phases could not cover everything",
            };
            AddWarning($"The scan is incomplete because {why}. Not fully covered: {string.Join(", ", notDone)}.");
        }
    }

    private ScanPhaseProgress? CurrentPhaseLocked() =>
        _phases is null || _phaseIndex < 0 ? null : new ScanPhaseProgress(_phases[_phaseIndex].Check.Name, _phaseIndex, _phases.Length);

    private TimeSpan? PhasedEtaLocked()
    {
        if (_phases is null || _phaseIndex < 0)
        {
            return null;
        }

        var elapsed = ElapsedLocked();
        var eta = EstimateAcrossPhases(_phases.Select(p => p.Check.Weight).ToArray(), _phaseIndex, PhaseFractionLocked(_phases[_phaseIndex]), elapsed,
            _budget - elapsed);
        return eta > MaxShownEta ? null : eta; // C6: a Full Scan has no budget, so "the budget left" is no estimate
    }

    /// <summary>Longest ETA reported; beyond it the ETA is unknown (null).</summary>
    internal static readonly TimeSpan MaxShownEta = TimeSpan.FromDays(7);

    /// <summary>
    /// The running phase's own fraction done. C6: a phase that announced the bytes it expects (<see cref="IScanCheckContext.ExpectBytes"/>,
    /// the drives' used space) uses bytes scanned over that, at most 99 % until its walk is done; otherwise files handled
    /// over files queued, halved while it is still queuing.
    /// </summary>
    private double PhaseFractionLocked(PhaseState current)
    {
        if (current.ExpectedBytes > 0 && !current.WalkDone)
        {
            return Math.Clamp((double)(_bytesDone - current.BytesDoneAtStart) / current.ExpectedBytes, 0, 0.99);
        }

        long found = _filesFound - current.FoundAtStart;
        long done = _filesDone - current.DoneAtStart;
        return found <= 0 ? 0 : Math.Clamp((double)done / found, 0, 1) * (current.WalkDone ? 1.0 : 0.5);
    }

    /// <summary>C6: the job's estimated percent done across phases (null for a plain job until its total is known).</summary>
    private double? PercentLocked()
    {
        if (ScanJobStateMachine.IsTerminal(_state))
        {
            return _state == ScanJobState.Completed ? 100 : null;
        }

        if (_phases is null)
        {
            return _enumerationDone && _bytesFound > 0 ? Math.Clamp(100.0 * _bytesDone / _bytesFound, 0, 100) : null;
        }

        if (_phaseIndex < 0)
        {
            return 0;
        }

        return 100 * ProgressAcrossPhases(_phases.Select(p => p.Check.Weight).ToArray(), _phaseIndex, PhaseFractionLocked(_phases[_phaseIndex]));
    }

    /// <summary>The weights of the finished phases plus the running phase's weight times its fraction, over the total weight.</summary>
    internal static double ProgressAcrossPhases(IReadOnlyList<double> weights, int current, double currentFraction)
    {
        double total = weights.Sum(w => Math.Max(w, 0));
        if (total <= 0 || current < 0 || current >= weights.Count)
        {
            return 0;
        }

        double before = weights.Take(current).Sum(w => Math.Max(w, 0));
        return Math.Clamp((before + Math.Max(weights[current], 0) * Math.Clamp(currentFraction, 0, 1)) / total, 0, 1);
    }

    /// <summary>
    /// The ETA across phases: progress = the weights of the finished phases plus the running phase's weight times its own
    /// fraction (files handled / queued, halved while it is still queuing), over the total weight; time left =
    /// elapsed × (1 − progress) / progress, never more than the budget left. Null while there's too little to go on.
    /// </summary>
    internal static TimeSpan? EstimateAcrossPhases(IReadOnlyList<double> weights, int current, double currentFraction, TimeSpan elapsed, TimeSpan budgetLeft)
    {
        double total = weights.Sum(w => Math.Max(w, 0));
        if (total <= 0 || current < 0 || current >= weights.Count)
        {
            return null;
        }

        double before = weights.Take(current).Sum(w => Math.Max(w, 0));
        double progress = (before + Math.Max(weights[current], 0) * Math.Clamp(currentFraction, 0, 1)) / total;
        if (progress < 0.01 || elapsed <= TimeSpan.Zero)
        {
            return budgetLeft > TimeSpan.Zero ? budgetLeft : TimeSpan.Zero;
        }

        var eta = TimeSpan.FromTicks((long)(elapsed.Ticks * (1 - progress) / progress));
        var cap = budgetLeft > TimeSpan.Zero ? budgetLeft : TimeSpan.Zero;
        return eta < cap ? eta : cap;
    }

    // ---- What a check sees ----

    private sealed class CheckContext(ScanJob job, CancellationToken token) : IScanCheckContext
    {
        public PhaseState Phase { get; set; } = null!;

        public CancellationToken CancellationToken => token;

        public TimeProvider Time => job._time;

        public ScanTrigger Trigger => job.Request.Trigger;

        public TimeSpan RemainingBudget
        {
            get
            {
                lock (job._lock)
                {
                    return job._budget - job.ElapsedLocked();
                }
            }
        }

        public long QuarantinedInPhase
        {
            get
            {
                lock (job._lock)
                {
                    return job._quarantined - Phase.QuarantinedAtStart;
                }
            }
        }

        public void Checkpoint()
        {
            job.Gate(token);
            job.CheckBudget();
            token.ThrowIfCancellationRequested();
        }

        public bool QueueFile(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            Checkpoint();
            string shown = ExactPath.ToExtended(path) is { } exact ? ExactPath.ForOpening(exact) : path;
            if (!job._dedupe!.TryAddPath(shown))
            {
                return false;
            }

            // Opened later by path, component by component without following links (SafeScanOpen through SafeTree); an
            // excluded final path is dropped by the pipeline.
            Emit(new ScanTreeEntry(shown, ScanTreeEntryKind.File));
            return true;
        }

        /// <summary>The running root's deadline (review C4 M1): its share of the phase's time left.</summary>
        private TimeSpan _rootDeadline = TimeSpan.MaxValue;

        public IReadOnlyList<string> QueueTree(IReadOnlyList<string> roots, ScanWalkFilter filter, Func<ScanTreeEntry, int>? rank = null, int laterRoots = 0)
        {
            ArgumentNullException.ThrowIfNull(roots);
            ArgumentNullException.ThrowIfNull(filter);
            var completed = new List<string>();
            var stoppedRoots = QueueRound(roots, filter, rank, Math.Max(0, laterRoots), completed);

            // Nothing comes after this call: what the finished roots didn't use goes to the ones that stopped (a second round;
            // the path dedupe skips what they already queued).
            if (laterRoots <= 0 && stoppedRoots.Count > 0 && stoppedRoots.Count < roots.Count)
            {
                stoppedRoots = QueueRound(stoppedRoots, filter, rank, 0, completed);
            }

            int stopped = stoppedRoots.Count;
            _rootDeadline = TimeSpan.MaxValue;
            if (stopped > 0 && !Phase.ShareNoted)
            {
                Phase.ShareNoted = true;
                MarkIncomplete($"{stopped} folder(s) stopped queuing after their share of the time budget; the rest is left to Full Scan.");
            }

            return completed;
        }

        /// <summary>One pass over <paramref name="roots"/>, each with its share; returns the roots that stopped early.</summary>
        private List<string> QueueRound(
            IReadOnlyList<string> roots, ScanWalkFilter filter, Func<ScanTreeEntry, int>? rank, int laterRoots, List<string> completed)
        {
            var stopped = new List<string>();
            for (int r = 0; r < roots.Count; r++)
            {
                Checkpoint();
                lock (job._lock)
                {
                    _rootDeadline = RootDeadline(job.ElapsedLocked(), Phase.Deadline, roots.Count - r + laterRoots);
                }

                (QueueRoot(roots[r], filter, rank) ? completed : stopped).Add(roots[r]);
            }

            return stopped;
        }

        /// <summary>A root's deadline: now plus the phase's time left over the roots left (no deadline without a phase deadline).</summary>
        internal static TimeSpan RootDeadline(TimeSpan now, TimeSpan phaseDeadline, int rootsLeft)
        {
            if (phaseDeadline == TimeSpan.MaxValue)
            {
                return TimeSpan.MaxValue;
            }

            var left = phaseDeadline - now;
            return left <= TimeSpan.Zero ? now : now + left / Math.Max(1, rootsLeft);
        }

        /// <summary>Walks one root; false if its share ran out before the walk ended.</summary>
        private bool QueueRoot(string root, ScanWalkFilter filter, Func<ScanTreeEntry, int>? rank)
        {
            var buffer = rank is null ? null : new List<(ScanTreeEntry Entry, int Rank, int Order)>();
            int order = 0;
            try
            {
                job._walker.Walk([root], entry =>
                {
                    if (entry.Kind == ScanTreeEntryKind.File && job._dedupe!.SeenPath(entry.Path))
                    {
                        entry.Folder?.Release(); // already queued or scanned in this job
                        return;
                    }

                    if (entry.Kind != ScanTreeEntryKind.File || buffer is null)
                    {
                        Emit(entry, inWalk: true);
                        return;
                    }

                    if (buffer.Count >= MaxRankedBuffer)
                    {
                        Flush(buffer); // before taking the entry over: if this throws, the walker still owns (and releases) it
                    }

                    buffer.Add((entry, SafeRank(rank!, entry), order++));
                }, token, job.Request.Access, job.Request.AllowRemoteFiles, filter);

                if (buffer is not null)
                {
                    Flush(buffer);
                }

                return true;
            }
            catch (PhaseShareUsedUpException)
            {
                // Best-ranked files are already queued; the rest of this root is left to Full Scan.
                return false;
            }
            finally
            {
                foreach (var (entry, _, _) in buffer ?? [])
                {
                    entry.Folder?.Release(); // buffered but never queued (cancelled, out of budget)
                }
            }
        }

        public FileScanReport ScanNow(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            Checkpoint();
            job._dedupe!.Remember(path);
            int slot = job._current.Length - 1;
            lock (job._lock)
            {
                job._filesFound++;
                job._current[slot] = path;
                Phase.Files++;
            }

            long bytes = 0;
            ScanPipelineOutcome? outcome = null;
            try
            {
                outcome = job._pipeline.ProcessDetailedAsync(path, Trigger, b => bytes = b, token, job.Request.Access, null, null,
                        PriorityOf(job.Request.Origin), job.Request.AllowRemoteFiles, job._budgets, job._dedupe)
                    .GetAwaiter().GetResult();
            }
            finally
            {
                lock (job._lock)
                {
                    job._current[slot] = null;
                    job._bytesFound += bytes;
                    if (outcome is null)
                    {
                        job._filesDone++; // cancelled mid-scan: balanced for the phase barrier, not counted
                    }
                    else
                    {
                        job.FileDoneLocked(outcome, bytes);
                    }
                }
            }

            return outcome.Report ?? NotScanned(path, outcome.Duplicate
                ? "This file was already handled earlier in this scan."
                : "The file is in one of sap-AV's own folders, or it wasn't scanned.");
        }

        public void WaitForQueuedFiles() => job.WaitForQueued(token);

        public void ExpectBytes(long bytes)
        {
            lock (job._lock)
            {
                Phase.ExpectedBytes = Math.Max(0, bytes);
            }
        }

        public void AddFinding(ScanFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);
            lock (job._lock)
            {
                Phase.Findings++;
                if (job._findings.Count < MaxRecordedFindings)
                {
                    job._findings.Add(finding);
                }
                else
                {
                    job._findingsOmitted++;
                }
            }
        }

        public void Note(string message)
        {
            ArgumentNullException.ThrowIfNull(message);
            lock (job._lock)
            {
                if (Phase.Notes.Count < MaxPhaseNotes)
                {
                    Phase.Notes.Add(SafeText.SingleLine(message, MaxNoteLength));
                }
            }
        }

        public void MarkIncomplete(string why)
        {
            lock (job._lock)
            {
                Phase.Incomplete = true;
            }

            Note(why);
        }

        private void Emit(ScanTreeEntry entry, bool inWalk = false)
        {
            if (inWalk && entry.Kind == ScanTreeEntryKind.File)
            {
                lock (job._lock)
                {
                    if (job.ElapsedLocked() > Phase.Deadline || job.ElapsedLocked() > _rootDeadline)
                    {
                        throw new PhaseShareUsedUpException();
                    }
                }

                // Recorded only now that it is queued: a file a ranked walk buffered but never queued (its share ran out)
                // stays open for a later phase (review C4 M2).
                job._dedupe!.Remember(entry.Path);
            }

            job.Emit(entry, token);
            if (entry.Kind == ScanTreeEntryKind.File)
            {
                lock (job._lock)
                {
                    Phase.Files++;
                }
            }
        }

        /// <summary>Queues the buffer best rank first (stable); whatever wasn't queued stays in it for the caller to release.</summary>
        private void Flush(List<(ScanTreeEntry Entry, int Rank, int Order)> buffer)
        {
            var sorted = buffer.OrderBy(b => b.Rank).ThenBy(b => b.Order).ToList();
            buffer.Clear();
            int i = 0;
            try
            {
                for (; i < sorted.Count; i++)
                {
                    Emit(sorted[i].Entry, inWalk: true);
                }
            }
            finally
            {
                buffer.AddRange(sorted.Skip(i));
            }
        }

        private int SafeRank(Func<ScanTreeEntry, int> rank, ScanTreeEntry entry)
        {
            try
            {
                return rank(entry);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                job._logger.LogDebug(ex, "Ranking {Path} failed; it is queued last.", entry.Path);
                return int.MaxValue;
            }
        }

        private FileScanReport NotScanned(string path, string why) =>
            ScanFileOpener.NotOpenedReport(new ScanItem(path, Trigger), HashResult.NotHashed(HashFailureReason.IoError, why), [], job._time.GetUtcNow());
    }
}
