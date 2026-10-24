using System.Threading.Channels;
using SapAV.Core.Models;

namespace SapAV.Engine.Scanning;

/// <summary>Runs before a job enumerates anything (e.g. the rules check); returns job-level warnings.</summary>
internal interface IScanJobPreflight
{
    Task<IReadOnlyList<string>> CheckAsync(ScanJob job, CancellationToken cancellationToken);
}

/// <summary>
/// One scan job (B3): "scan these files/folders", with progress, ETA, pause / resume / cancel and a time budget.
/// </summary>
/// <remarks>
/// <para><b>Threads.</b> One enumerator thread walks the paths (<see cref="ScanTreeWalker"/>) into a bounded channel of
/// <see cref="ScanJobOptions.QueueCapacity"/> files; when it is full the enumerator blocks (back-pressure), so a huge tree
/// never piles up in memory. <see cref="ScanJobOptions.ThreadsPerJob"/> scan threads take files from the channel, open
/// each one (blocking, on that thread) and wait for the sandboxed worker. All are dedicated threads in background mode
/// (<see cref="BackgroundThread"/>), never thread-pool threads.</para>
/// <para><b>States</b> (<see cref="ScanJobStateMachine"/>): Created → Running ⇄ Pausing → Paused; Running/Pausing/Paused →
/// Cancelling → Cancelled; Running → Completed / TimedOut / Failed. Pause lets files already being scanned finish; the job
/// is Paused once every job thread is parked (at the pause gate, or waiting on the channel with the other side parked),
/// so no progress happens while Paused. Cancel cancels the job token: in-flight scans end, queued files are dropped and
/// the results so far are kept.</para>
/// <para><b>Time budget</b> (review A L5): running time only (paused time doesn't count), checked before every file;
/// a single file is bounded by the worker's own request timeout. Over budget → TimedOut.</para>
/// <para><b>Events</b> (<see cref="StateChanged"/>, <see cref="FileCompleted"/>, <see cref="ProgressChanged"/>) are
/// delivered in order on one dispatcher task, never on the scan threads, so a slow subscriber can't stall scanning.
/// <see cref="FileCompleted"/> is raised for every recorded result (everything except Clean files). <see cref="Completion"/>
/// completes after the final state change was delivered.</para>
/// </remarks>
public sealed class ScanJob : IDisposable
{
    private readonly ScanJobOptions _options;
    private readonly ScanFilePipeline _pipeline;
    private readonly ScanTreeWalker _walker;
    private readonly IScanJobPreflight? _preflight;
    private readonly IScanVerdictHandler? _handler;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly ManualResetEventSlim _resume = new(initialState: true);
    private readonly Channel<ScanTreeEntry> _queue;
    private readonly Channel<Action> _events = Channel.CreateUnbounded<Action>(new UnboundedChannelOptions { SingleReader = true });
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ThroughputEstimator _estimator;
    private readonly List<ScanJobFileResult> _results = [];
    private readonly List<ScanJobWarning> _warnings = [];
    private readonly string?[] _current;
    private readonly TimeSpan _budget;

    private ScanJobState _state = ScanJobState.Created;
    private int _busy;
    private int _alive;
    private bool _enumerationDone;
    private bool _timedOut;
    private Exception? _failure;
    private long _filesFound, _filesDone, _bytesFound, _bytesDone;
    private long _clean, _suspicious, _malicious, _notScanned, _excluded, _quarantined, _needsConfirmation, _quarantineFailed;
    private long _skippedLinks, _unreadableFolders, _resultsOmitted;
    private bool _progressPending;
    private TimeSpan _runningBefore;
    private DateTimeOffset? _runningSince;

    internal ScanJob(
        Guid id, ScanJobRequest request, ScanJobOptions options, ScanFilePipeline pipeline, ScanTreeWalker walker,
        IScanVerdictHandler? handler, IScanJobPreflight? preflight, TimeProvider time, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Validate();
        Id = id;
        Request = request;
        _options = options;
        _pipeline = pipeline;
        _walker = walker;
        _handler = handler;
        _preflight = preflight;
        _time = time;
        _logger = logger;
        _budget = request.TimeBudget ?? options.TimeBudget;
        _estimator = new ThroughputEstimator(time);
        _current = new string?[options.ThreadsPerJob];
        _queue = Channel.CreateBounded<ScanTreeEntry>(new BoundedChannelOptions(options.QueueCapacity)
        {
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        CreatedAt = time.GetUtcNow();
        _ = Task.Run(DispatchEventsAsync);
    }

    public Guid Id { get; }

    public ScanJobRequest Request { get; }

    public DateTimeOffset CreatedAt { get; }

    public ScanJobState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>Every state change, in order. Handlers run on the job's event task and must not block for long.</summary>
    public event Action<ScanJobStateChange>? StateChanged;

    /// <summary>Every recorded file result (all but Clean files).</summary>
    public event Action<ScanJobFileResult>? FileCompleted;

    /// <summary>Like <see cref="FileCompleted"/>, with the result ID (its index in <see cref="Results"/>, stable: results are only appended).</summary>
    internal event Action<int, ScanJobFileResult>? FileRecorded;

    /// <summary>The recorded result with this ID, or null.</summary>
    internal ScanJobFileResult? ResultAt(int resultId)
    {
        lock (_lock)
        {
            return resultId >= 0 && resultId < _results.Count ? _results[resultId] : null;
        }
    }

    /// <summary>Progress changed (coalesced: at most one pending notification at a time).</summary>
    public event Action<ScanJobProgress>? ProgressChanged;

    /// <summary>Completes once the job reached a final state and every event was delivered.</summary>
    public Task Completion => _completion.Task;

    /// <summary>Test seam: the enumerator found the queue full and is about to block.</summary>
    internal Action? EnumeratorBlocked { get; set; }

    /// <summary>Recorded results (not Clean), in completion order, capped at <see cref="ScanJobOptions.MaxRecordedResults"/>.</summary>
    public IReadOnlyList<ScanJobFileResult> Results
    {
        get
        {
            lock (_lock)
            {
                return _results.ToArray();
            }
        }
    }

    /// <summary>Results not kept because of the cap (still counted in the counters).</summary>
    public long ResultsOmitted
    {
        get
        {
            lock (_lock)
            {
                return _resultsOmitted;
            }
        }
    }

    public IReadOnlyList<ScanJobWarning> Warnings
    {
        get
        {
            lock (_lock)
            {
                return _warnings.ToArray();
            }
        }
    }

    /// <summary>Junctions / symlinks skipped and folders that couldn't be listed.</summary>
    public (long SkippedLinks, long UnreadableFolders) Skipped
    {
        get
        {
            lock (_lock)
            {
                return (_skippedLinks, _unreadableFolders);
            }
        }
    }

    public ScanJobProgress GetProgress()
    {
        lock (_lock)
        {
            return ProgressLocked();
        }
    }

    /// <summary>Starts the threads. False unless the job is Created.</summary>
    internal bool Start()
    {
        lock (_lock)
        {
            if (_state != ScanJobState.Created)
            {
                return false;
            }

            TransitionLocked(ScanJobState.Running);
            _runningSince = _time.GetUtcNow();
            _estimator.Restart();
            _alive = _busy = _options.ThreadsPerJob + 1;
        }

        string prefix = $"sap-AV scan {Id.ToString("N")[..8]}";
        BackgroundThread.Start(prefix + " enumerator", EnumeratorLoop);
        for (int i = 0; i < _options.ThreadsPerJob; i++)
        {
            int index = i;
            BackgroundThread.Start($"{prefix} #{index}", () => ScanLoop(index));
        }

        return true;
    }

    /// <summary>Requests a pause (Running only). The job is Paused once in-flight files are done.</summary>
    public bool Pause()
    {
        lock (_lock)
        {
            if (_state != ScanJobState.Running)
            {
                return false;
            }

            _resume.Reset();
            TransitionLocked(ScanJobState.Pausing);
            ParkedCheckLocked();
            return true;
        }
    }

    /// <summary>Resumes a Pausing or Paused job.</summary>
    public bool Resume()
    {
        lock (_lock)
        {
            if (_state is not (ScanJobState.Pausing or ScanJobState.Paused))
            {
                return false;
            }

            if (_state == ScanJobState.Paused)
            {
                _runningSince = _time.GetUtcNow();
                _estimator.Restart();
            }

            TransitionLocked(ScanJobState.Running);
            _resume.Set();
            return true;
        }
    }

    /// <summary>Cancels the job (any non-final state). The results so far are kept.</summary>
    public bool Cancel()
    {
        lock (_lock)
        {
            if (_state == ScanJobState.Created)
            {
                TransitionLocked(ScanJobState.Cancelled);
                FinishEventsLocked();
                return true;
            }

            if (_state is not (ScanJobState.Running or ScanJobState.Pausing or ScanJobState.Paused))
            {
                return false;
            }

            TransitionLocked(ScanJobState.Cancelling);
        }

        _cts.Cancel();
        return true;
    }

    /// <summary>Running time so far (paused time excluded).</summary>
    public TimeSpan Elapsed
    {
        get
        {
            lock (_lock)
            {
                return ElapsedLocked();
            }
        }
    }

    internal void AddWarning(string message)
    {
        lock (_lock)
        {
            if (_warnings.Count < 100)
            {
                _warnings.Add(new ScanJobWarning(_time.GetUtcNow(), message));
            }
        }

        _logger.LogWarning("Scan job {JobId}: {Warning}", Id, message);
    }

    /// <summary>Cancels the job. The token source is not disposed: job threads may still be unwinding on it.</summary>
    public void Dispose() => Cancel();

    // ---- Enumerator thread ----

    private void EnumeratorLoop()
    {
        var token = _cts.Token;
        try
        {
            RunPreflight(token);
            _walker.Walk(Request.Paths, entry => Emit(entry, token), token, Request.Access);
            lock (_lock)
            {
                _enumerationDone = true;
                ProgressChangedLocked();
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // cancelled or timed out
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Fail(ex, "enumeration");
        }
        finally
        {
            _queue.Writer.TryComplete();
            ThreadExited();
        }
    }

    private void RunPreflight(CancellationToken token)
    {
        if (_preflight is null)
        {
            return;
        }

        try
        {
            foreach (var warning in _preflight.CheckAsync(this, token).GetAwaiter().GetResult())
            {
                AddWarning(warning);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            AddWarning($"The pre-scan checks failed ({ex.GetType().Name}); scanning anyway.");
        }
    }

    private void Emit(ScanTreeEntry entry, CancellationToken token)
    {
        Gate(token);
        CheckBudget();
        token.ThrowIfCancellationRequested();
        switch (entry.Kind)
        {
            case ScanTreeEntryKind.File:
                if (!_queue.Writer.TryWrite(entry))
                {
                    EnumeratorBlocked?.Invoke();
                    Idle(() => _queue.Writer.WriteAsync(entry, token).AsTask().GetAwaiter().GetResult());
                }

                lock (_lock)
                {
                    _filesFound++;
                    _bytesFound += entry.Length;
                }

                break;

            case ScanTreeEntryKind.Excluded:
                lock (_lock)
                {
                    _excluded++;
                }

                break;

            case ScanTreeEntryKind.SkippedLink:
                lock (_lock)
                {
                    _skippedLinks++;
                }

                break;

            case ScanTreeEntryKind.Unreadable:
                long unreadable;
                lock (_lock)
                {
                    unreadable = ++_unreadableFolders;
                }

                if (unreadable <= 10)
                {
                    AddWarning($"A folder could not be listed ({entry.Detail}): {entry.Path}");
                }

                break;
        }
    }

    // ---- Scan threads ----

    private void ScanLoop(int index)
    {
        var token = _cts.Token;
        try
        {
            while (true)
            {
                Gate(token);
                bool more = false;
                Idle(() => more = _queue.Reader.WaitToReadAsync(token).AsTask().GetAwaiter().GetResult());
                if (!more)
                {
                    break;
                }

                if (!_queue.Reader.TryRead(out var entry))
                {
                    continue;
                }

                Gate(token); // a pause that arrived while waiting for work
                CheckBudget();
                token.ThrowIfCancellationRequested();
                ScanOne(index, entry, token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // cancelled or timed out
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Fail(ex, "scan thread");
        }
        finally
        {
            lock (_lock)
            {
                _current[index] = null;
            }

            ThreadExited();
        }
    }

    private void ScanOne(int index, ScanTreeEntry entry, CancellationToken token)
    {
        lock (_lock)
        {
            _current[index] = entry.Path;
        }

        long scannedBytes = 0;
        var result = _pipeline.ProcessAsync(entry.Path, Request.Trigger, b => scannedBytes = b, token, Request.Access).GetAwaiter().GetResult();
        lock (_lock)
        {
            _current[index] = null;
            _filesDone++;
            _bytesDone += scannedBytes > 0 ? scannedBytes : entry.Length;
            _estimator.Record(scannedBytes > 0 ? scannedBytes : entry.Length, 1);
            CountLocked(result);
            ProgressChangedLocked();
        }
    }

    private void CountLocked(ScanJobFileResult? result)
    {
        if (result is null)
        {
            _excluded++;
            return;
        }

        if (result.Status != ScanStatus.Scanned)
        {
            _notScanned++;
        }
        else if (result.Verdict == Verdict.Malicious)
        {
            _malicious++;
        }
        else if (result.Verdict == Verdict.Suspicious)
        {
            _suspicious++;
        }
        else
        {
            _clean++;
        }

        switch (result.Action)
        {
            case ScanFileAction.Quarantined:
                _quarantined++;
                break;
            case ScanFileAction.NeedsUserConfirmation:
                _needsConfirmation++;
                break;
            case ScanFileAction.QuarantineFailed or ScanFileAction.StoreFull:
                _quarantineFailed++;
                break;
        }

        if (result.Status == ScanStatus.Scanned && result.Verdict == Verdict.Clean)
        {
            return; // only counted
        }

        if (_results.Count >= _options.MaxRecordedResults)
        {
            _resultsOmitted++;
            return;
        }

        _results.Add(result);
        int resultId = _results.Count - 1;
        Post(() =>
        {
            FileCompleted?.Invoke(result);
            FileRecorded?.Invoke(resultId, result);
        });
    }

    // ---- Pause gate, budget, completion ----

    /// <summary>Blocks while the job is pausing / paused; the thread counts as parked meanwhile.</summary>
    private void Gate(CancellationToken token)
    {
        if (_resume.IsSet)
        {
            return;
        }

        Idle(() => _resume.Wait(token));
    }

    /// <summary>Runs a wait during which this thread can't make progress on its own (parked for the pause check).</summary>
    private void Idle(Action wait)
    {
        lock (_lock)
        {
            _busy--;
            ParkedCheckLocked();
        }

        try
        {
            wait();
        }
        finally
        {
            lock (_lock)
            {
                _busy++;
            }
        }
    }

    private void ParkedCheckLocked()
    {
        if (_state == ScanJobState.Pausing && _busy == 0)
        {
            _runningBefore = ElapsedLocked();
            _runningSince = null;
            TransitionLocked(ScanJobState.Paused);
            ProgressChangedLocked();
        }
    }

    private void CheckBudget()
    {
        bool over;
        lock (_lock)
        {
            over = !_timedOut && ElapsedLocked() > _budget;
            _timedOut |= over;
        }

        if (over)
        {
            AddWarning($"The job's time budget ({_budget}) ran out; it stopped with partial results.");
            _cts.Cancel();
        }
    }

    private void Fail(Exception ex, string where)
    {
        _logger.LogError(ex, "Scan job {JobId} failed in the {Where}.", Id, where);
        lock (_lock)
        {
            _failure ??= ex;
        }

        AddWarning($"The job stopped because of an internal error in the {where} ({ex.GetType().Name}).");
        _cts.Cancel();
    }

    private void ThreadExited()
    {
        bool last;
        lock (_lock)
        {
            _busy--;
            last = --_alive == 0;
            if (!last)
            {
                ParkedCheckLocked();
            }
        }

        if (last)
        {
            Finish();
        }
    }

    private void Finish()
    {
        ScanJobState final;
        lock (_lock)
        {
            final = _failure is not null ? ScanJobState.Failed
                : _timedOut ? ScanJobState.TimedOut
                : _state == ScanJobState.Cancelling ? ScanJobState.Cancelled
                : _cts.IsCancellationRequested ? ScanJobState.Cancelled
                : ScanJobState.Completed;
            _runningBefore = ElapsedLocked();
            _runningSince = null;
        }

        try
        {
            _handler?.JobFinished(this);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Scan job {JobId}: the end-of-job step failed.", Id);
        }

        lock (_lock)
        {
            if (!ScanJobStateMachine.CanTransition(_state, final))
            {
                final = ScanJobStateMachine.CanTransition(_state, ScanJobState.Cancelled) ? ScanJobState.Cancelled : ScanJobState.Failed;
            }

            TransitionLocked(final);
            ProgressChangedLocked();
            FinishEventsLocked();
        }

        _logger.LogInformation("Scan job {JobId} {State}: {Done} files ({Malicious} malicious, {Suspicious} suspicious, {NotScanned} not scanned).",
            Id, final, _filesDone, _malicious, _suspicious, _notScanned);
    }

    // ---- State, progress, events ----

    private void TransitionLocked(ScanJobState to)
    {
        var from = _state;
        if (!ScanJobStateMachine.CanTransition(from, to))
        {
            throw new InvalidOperationException($"Scan job state {from} -> {to} is not allowed.");
        }

        _state = to;
        var change = new ScanJobStateChange(Id, from, to, _time.GetUtcNow());
        Post(() => StateChanged?.Invoke(change));
    }

    private TimeSpan ElapsedLocked() => _runningBefore + (_runningSince is { } since ? _time.GetUtcNow() - since : TimeSpan.Zero);

    private ScanJobProgress ProgressLocked()
    {
        long? filesTotal = _enumerationDone ? _filesFound : null;
        long? bytesTotal = _enumerationDone ? _bytesFound : null;
        TimeSpan? eta = _enumerationDone && !ScanJobStateMachine.IsTerminal(_state)
            ? _estimator.Estimate(Math.Max(0, _bytesFound - _bytesDone), Math.Max(0, _filesFound - _filesDone))
            : null;
        return new ScanJobProgress(Id, _state, _filesFound, filesTotal, _filesDone, _bytesDone, bytesTotal,
            _current.FirstOrDefault(c => c is not null), eta, ElapsedLocked(),
            new ScanJobCounters(_clean, _suspicious, _malicious, _notScanned, _excluded, _quarantined,
                _needsConfirmation, _quarantineFailed));
    }

    private void ProgressChangedLocked()
    {
        if (_progressPending)
        {
            return;
        }

        _progressPending = true;
        Post(() =>
        {
            ScanJobProgress progress;
            lock (_lock)
            {
                _progressPending = false;
                progress = ProgressLocked();
            }

            ProgressChanged?.Invoke(progress);
        });
    }

    private void Post(Action raise) => _events.Writer.TryWrite(raise);

    private void FinishEventsLocked() => _events.Writer.TryComplete();

    private async Task DispatchEventsAsync()
    {
        await foreach (var raise in _events.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            try
            {
                raise();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                _logger.LogWarning(ex, "A scan job {JobId} event handler threw.", Id);
            }
        }

        _completion.TrySetResult();
    }
}
