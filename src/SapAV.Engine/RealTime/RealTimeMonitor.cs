using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.RealTime;

/// <summary>
/// Real-time file monitoring (ROADMAP D1). Watches the configured folders (<see cref="IWatchedFolderSource"/>), waits until
/// a new or changed file is no longer being written (<see cref="UnlockProbe"/>), and scans it through the engine's own scan
/// pipeline (<see cref="ScanFilePipeline"/>: hardened open, exclusions, the C5 cache rules, the sandboxed worker, then the
/// shared verdict handler: alert to the Event Log sinks, auto-quarantine of Malicious files only, never PUP or Suspicious).
/// </summary>
/// <remarks>
/// <para><b>Never redirected.</b> Each watched folder is opened through <see cref="SafeTree"/> (no reparse point followed on
/// the way, name surrogates refused, local fixed drives only, the remote-file check on the handle) and watched through that
/// handle (<see cref="NativeDirectoryWatch"/>, not a path-based FileSystemWatcher). Every event is resolved relative to the
/// watched folder's handle, component by component (<see cref="RelativeOpen"/>), and the file is opened relative to its
/// parent folder's handle, in exact <c>\\?\</c> names. A folder that is (or becomes) a junction or symlink is refused at
/// revalidation and its watch stops; events already in flight still lead only into the original folder object.</para>
/// <para><b>Bounded.</b> The queue holds at most <see cref="RealTimeOptions.MaxPendingFiles"/> files (and a path-character
/// budget), one entry per file however many events arrive. When it is full (an event storm, e.g. extracting 50,000 files)
/// or the watcher's buffer overflows, the folder is marked for a rescan of recently changed files, run once the queue has
/// drained to a quarter, with back-pressure and its own caps (files, entries, depth); a capped rescan is reported.</para>
/// <para><b>Background.</b> The scheduler, the scan threads and the rescan thread are dedicated threads in background mode
/// (<see cref="BackgroundThread"/>: low CPU, I/O and memory priority). Watcher completions only parse and enqueue.</para>
/// <para><b>Budgets.</b> Alerts, auto-quarantines and the quarantine quota count against the engine's own real-time budget
/// (<c>engine:RealTime:&lt;owner SID&gt;</c> per watched-folder user or file owner, review D1 M2; <see cref="BudgetFor"/>), never a requester's: a user's own scans can't use up real-time slots, and a
/// file a user drops needs no per-user quota check (review C1 L6). The auto-quarantine window is still a rate limit: in a
/// burst of more than its size, later Malicious files need the user's confirmation (review B3 / D1 L2, by design).</para>
/// </remarks>
internal sealed class RealTimeMonitor : IDirectoryWatchSink, IDisposable
{
    private static readonly TimeSpan TimeMargin = TimeSpan.FromSeconds(5);

    private readonly RealTimeOptions _options;
    private readonly IWatchedFolderSource _folders;
    private readonly ScanFilePipeline _pipeline;
    private readonly ExclusionSet _excluded;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly IDirectoryWatchFactory _watches;
    private readonly IRemoteFileProbe _remote;
    private readonly Func<string, int> _driveType;
    private readonly ScanTreeWalker _walker;
    private readonly RealTimeQueue _queue;
    private readonly QuickScanFileRules _rules = new(new QuickScanOptions());
    private readonly Counters _counters = new();
    private readonly int _scanThreads;

    /// <summary>Review D1 M2: owners with their own real-time budget; past <see cref="MaxOwnerBudgets"/> they share one.</summary>
    private readonly HashSet<string> _owners = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Review D1 H1: one watchdog per scan thread.</summary>
    private readonly List<ScanThreadWatch> _scanWatches = [];

    /// <summary>Review D1 M1: raised whenever a file leaves the queue (rescan back-pressure waits on it).</summary>
    private readonly AutoResetEvent _spaceFreed = new(false);

    private readonly Lock _rootsLock = new();
    private readonly Dictionary<string, WatchedRoot> _roots = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _problems = new(StringComparer.OrdinalIgnoreCase);
    private int _nextRootId;

    private readonly Lock _rescanLock = new();
    private readonly Dictionary<string, RescanRequest> _rescans = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _storming = [];

    private readonly CancellationTokenSource _stop = new();
    private readonly AutoResetEvent _wake = new(false);
    private readonly AutoResetEvent _rescanSignal = new(false);
    private readonly SemaphoreSlim _readySignal = new(0);
    private readonly List<Thread> _threads = [];
    private long _nextRevalidateTicks;
    private int _started;
    private int _disposed;

    public RealTimeMonitor(
        RealTimeOptions options, IWatchedFolderSource folders, ScanFilePipeline pipeline, ExclusionSet excluded, TimeProvider time, ILogger logger,
        IDirectoryWatchFactory? watches = null, IRemoteFileProbe? remote = null, ISyncRootProbe? syncRoots = null, Func<string, int>? driveType = null,
        int? workerCount = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _folders = folders ?? throw new ArgumentNullException(nameof(folders));
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _excluded = excluded ?? throw new ArgumentNullException(nameof(excluded));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _watches = watches ?? NativeDirectoryWatchFactory.Instance;
        _remote = remote ?? RemoteFileProbe.Instance;
        _driveType = driveType ?? Pipe.Native.PipeNative.DriveType;
        _walker = new ScanTreeWalker(excluded, remote: _remote, syncRoots: syncRoots);
        _queue = new RealTimeQueue(options);
        _scanThreads = workerCount is { } workers ? options.EffectiveScanThreads(workers) : options.ScanThreads;
    }

    /// <summary>Raised for every file handled (on a scan thread; handlers must be quick and must not throw).</summary>
    public event Action<RealTimeFileResult>? FileHandled;

    internal RealTimeQueue Queue => _queue;

    /// <summary>The roots watched right now (tests).</summary>
    internal IReadOnlyList<WatchedRoot> Roots
    {
        get
        {
            lock (_rootsLock)
            {
                return [.. _roots.Values];
            }
        }
    }

    /// <summary>Why each refused folder isn't watched (by exact path; tests and the status).</summary>
    internal IReadOnlyDictionary<string, string> Problems
    {
        get
        {
            lock (_rootsLock)
            {
                return new Dictionary<string, string>(_problems, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    public RealTimeStatus Status
    {
        get
        {
            int watched, refused;
            lock (_rootsLock)
            {
                watched = _roots.Values.Count(r => !r.Failed);
                refused = _problems.Count;
            }

            var c = _counters;
            return new RealTimeStatus(watched, refused, _queue.Count, _queue.ReadyCount, Interlocked.Read(ref c.Events), Interlocked.Read(ref c.Coalesced),
                Interlocked.Read(ref c.Dropped), Interlocked.Read(ref c.Overflows), Interlocked.Read(ref c.Rescans), Interlocked.Read(ref c.RescansIncomplete),
                Interlocked.Read(ref c.Scanned), Interlocked.Read(ref c.Flagged), Interlocked.Read(ref c.Quarantined), Interlocked.Read(ref c.LockRetries),
                Interlocked.Read(ref c.LockWaitsExpired), Interlocked.Read(ref c.Blocked), Interlocked.Read(ref c.Gone), Interlocked.Read(ref c.Links),
                Interlocked.Read(ref c.TooLarge), Interlocked.Read(ref c.Errors));
        }
    }

    /// <summary>Opens and watches the folders, then starts the scheduler, scan and rescan threads. Once.</summary>
    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            return;
        }

        Revalidate();
        ScheduleRevalidation(_options.RevalidateInterval);
        _threads.Add(BackgroundThread.Start("sap-AV real-time scheduler", () => Guarded(SchedulerLoop)));
        for (int i = 0; i < _scanThreads; i++)
        {
            _threads.Add(BackgroundThread.Start($"sap-AV real-time scan #{i}", () => Guarded(ScanLoop)));
        }

        _threads.Add(BackgroundThread.Start("sap-AV real-time rescan", () => Guarded(RescanLoop)));
        _logger.LogInformation("Real-time monitoring started: {Count} folder(s) watched, {Refused} refused.", Status.WatchedFolders, Status.RefusedFolders);
    }

    // ---- Watcher notifications (I/O completion threads: parse, enqueue, return) ----

    public void OnChanges(WatchedRoot root, IReadOnlyList<FileChange> changes)
    {
        if (root.Closed)
        {
            return;
        }

        var now = _time.GetUtcNow();
        root.MarkBatch(now);
        bool queued = false;
        foreach (var change in changes)
        {
            Interlocked.Increment(ref _counters.Events);
            if (!RelativeOpen.IsValidRelative(change.Name))
            {
                Interlocked.Increment(ref _counters.Errors);
                continue;
            }

            if (change.IsLink)
            {
                Interlocked.Increment(ref _counters.Links); // never followed; a file reached through one is refused on open anyway
                continue;
            }

            if (change.IsDirectory)
            {
                if (change.Kind is FileChangeKind.Added or FileChangeKind.RenamedTo)
                {
                    RequestRescan(root, change.Name, since: null, now); // moved in with content: its files raise no events of their own
                }

                continue;
            }

            if (change.Kind == FileChangeKind.StreamChanged && !change.IsMarkOfTheWeb)
            {
                continue; // other named streams don't change the file's content
            }

            switch (_queue.Offer(root, change.Name, change.IsMarkOfTheWeb, now))
            {
                case OfferResult.Queued:
                    queued = true;
                    break;
                case OfferResult.Coalesced:
                    Interlocked.Increment(ref _counters.Coalesced);
                    break;
                default:
                    Interlocked.Increment(ref _counters.Dropped);
                    OnStorm(root, now);
                    break;
            }
        }

        if (queued)
        {
            _wake.Set();
        }
    }

    public void OnOverflow(WatchedRoot root)
    {
        if (root.Closed)
        {
            return;
        }

        var now = _time.GetUtcNow();
        Interlocked.Increment(ref _counters.Overflows);
        // Lost events happened after the last batch that arrived; the rescan looks a little before it (time stamp granularity).
        var since = root.LastBatchAt - TimeMargin;
        root.MarkBatch(now);
        _logger.LogWarning("Real-time: the watcher buffer for {Folder} overflowed; files changed since {Since:u} are rescanned.", Shown(root.ExactPath), since);
        RequestRescan(root, string.Empty, since, now);
    }

    public void OnFailed(WatchedRoot root, int win32Error)
    {
        if (root.Closed)
        {
            return;
        }

        root.Failed = true;
        _logger.LogWarning("Real-time: the watch on {Folder} stopped (Win32 error {Error}); it is checked again shortly.", Shown(root.ExactPath), win32Error);
        ScheduleRevalidation(TimeSpan.FromSeconds(5));
    }

    private void OnStorm(WatchedRoot root, DateTimeOffset now)
    {
        bool first;
        lock (_rescanLock)
        {
            first = _storming.Add(root.Id);
        }

        if (first)
        {
            _logger.LogWarning("Real-time: the queue is full ({Max} files); new events in {Folder} are dropped for now, and the folder is rescanned for "
                + "recently changed files once the queue drains.", _options.MaxPendingFiles, Shown(root.ExactPath));
        }

        RequestRescan(root, string.Empty, now - TimeMargin, now);
    }

    // ---- Rescans (overflows, storms, folders that appear) ----

    private sealed record RescanRequest(WatchedRoot Root, string Folder, DateTimeOffset? Since);

    /// <param name="since">Only files created, written or changed since then; null = every file (a folder that just appeared).</param>
    internal void RequestRescan(WatchedRoot root, string folder, DateTimeOffset? since, DateTimeOffset now)
    {
        var floor = now - _options.RescanLookback;
        if (since is { } s && s < floor)
        {
            since = floor;
        }

        lock (_rescanLock)
        {
            string key = Key(root, folder);
            if (!_rescans.ContainsKey(key) && _rescans.Count >= _options.MaxPendingRescans)
            {
                // Too many separate requests: one bounded rescan of the whole folder for recent changes covers them.
                key = Key(root, string.Empty);
                folder = string.Empty;
                since = since is null ? floor : since;
            }

            _rescans[key] = _rescans.TryGetValue(key, out var existing)
                ? existing with { Since = existing.Since is null || since is null ? null : Min(existing.Since.Value, since.Value) }
                : new RescanRequest(root, folder, since);
        }

        _wake.Set();
    }

    private bool TryTakeRescan(out RescanRequest request)
    {
        lock (_rescanLock)
        {
            // Folder rescans (new folders) before whole-folder ones; any order within.
            var next = _rescans.OrderBy(r => r.Value.Folder.Length == 0 ? 1 : 0).Select(r => r.Key).FirstOrDefault();
            if (next is null)
            {
                request = null!;
                return false;
            }

            request = _rescans[next];
            _rescans.Remove(next);
            if (request.Folder.Length == 0)
            {
                _storming.Remove(request.Root.Id);
            }

            return true;
        }
    }

    private bool HasRescans()
    {
        lock (_rescanLock)
        {
            return _rescans.Count > 0;
        }
    }

    private void Rescan(RescanRequest request)
    {
        var root = request.Root;
        if (root.Closed)
        {
            return;
        }

        Interlocked.Increment(ref _counters.Rescans);
        var since = request.Since;
        var filter = new ScanWalkFilter
        {
            MaxDepth = _options.MaxRescanDepth,
            MaxEntries = _options.MaxRescanEntries,
            IncludeFile = e => e.Length <= _options.MaxFileSizeBytes && (since is null || (e.NewestTimeUtc is { } newest && newest >= since)),
        };

        int offered = 0;
        bool capped = false;
        _walker.Walk([root.PathOf(request.Folder)], entry =>
        {
            entry.Folder?.Release(); // the file is opened relative to the watched root's handle later, not this listing's
            if (entry.Kind != ScanTreeEntryKind.File || entry.Folder is null || root.RelativeOf(entry.Path) is not { } relative)
            {
                return;
            }

            if (offered >= _options.MaxRescanFiles)
            {
                capped = true;
                filter.LimitReached = true;
                return;
            }

            if (OfferWithBackPressure(root, relative))
            {
                offered++;
            }
            else
            {
                capped = true; // a name that can never fit in this folder's share of the queue
            }
        }, _stop.Token, filter: filter);

        if (capped || filter.LimitReached)
        {
            Interlocked.Increment(ref _counters.RescansIncomplete);
            _logger.LogWarning("Real-time: the rescan of {Folder} stopped at its limit ({Files} files queued); some changed files there were not checked "
                + "in real time. A Quick Scan covers them.", Shown(root.PathOf(request.Folder)), offered);
        }
        else
        {
            _logger.LogInformation("Real-time: rescanned {Folder}: {Files} file(s) queued.", Shown(root.PathOf(request.Folder)), offered);
        }
    }

    /// <summary>
    /// Offers one file from a rescan (long names allowed: here they cost only their folder's share), waiting while the queue
    /// or the folder's share is full (the rescan thread is the producer). Review D1 M1: the wait is on the "space freed" signal
    /// the scan threads raise, and both caps (files and path characters) count, so a full character budget can't make it spin.
    /// </summary>
    /// <returns>False when the name could never fit (it is longer than the folder's whole share).</returns>
    private bool OfferWithBackPressure(WatchedRoot root, string relative)
    {
        if (relative.Length + 16 > _queue.RootShare.Chars)
        {
            return false;
        }

        var waits = new WaitHandle[] { _spaceFreed, _stop.Token.WaitHandle };
        while (!_stop.IsCancellationRequested)
        {
            var result = _queue.Offer(root, relative, false, _time.GetUtcNow(), allowLong: true);
            if (result != OfferResult.Dropped)
            {
                if (result == OfferResult.Queued)
                {
                    _wake.Set();
                }

                return true;
            }

            // Until this folder's share (and the whole queue) can take it again, with some slack so it doesn't refill one by one.
            while (!(_queue.HasRoomFor(root, relative.Length) && _queue.CountFor(root) <= _queue.RootShare.Files / 2) && !_stop.IsCancellationRequested)
            {
                WaitHandle.WaitAny(waits, TimeSpan.FromSeconds(1));
            }
        }

        _stop.Token.ThrowIfCancellationRequested();
        return false;
    }

    // ---- Threads ----

    private void Guarded(Action loop)
    {
        try
        {
            loop();
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(ex, "A real-time monitoring thread failed; real-time protection is degraded until the engine restarts.");
        }
    }

    private void SchedulerLoop()
    {
        var waits = new WaitHandle[] { _wake, _stop.Token.WaitHandle };
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                SchedulerPass();
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
            {
                // One bad pass must never end real-time protection: log it and go on with the next one.
                _logger.LogError(ex, "Real-time: a scheduler pass failed.");
                _stop.Token.WaitHandle.WaitOne(100);
            }

            var wake = new DateTimeOffset(Interlocked.Read(ref _nextRevalidateTicks), TimeSpan.Zero);
            if (_queue.NextDue() is { } due && due < wake)
            {
                wake = due;
            }

            var wait = wake - _time.GetUtcNow();
            wait = wait < TimeSpan.FromMilliseconds(1) ? TimeSpan.FromMilliseconds(1) : wait > TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait;
            WaitHandle.WaitAny(waits, wait);
        }
    }

    /// <summary>Ranks and releases every due file, revalidates when it is time, and wakes the rescan thread when there is room.</summary>
    private void SchedulerPass()
    {
        var now = _time.GetUtcNow();
        while (_queue.TryTakeDue(now, out var file))
        {
            _queue.MakeReady(file, RankSafely(file));
            _readySignal.Release();
        }

        if (now.UtcTicks >= Interlocked.Read(ref _nextRevalidateTicks))
        {
            ScheduleRevalidation(_options.RevalidateInterval);
            RevalidateSafely();
        }

        if (_queue.HasRoom && HasRescans())
        {
            _rescanSignal.Set();
        }

        CheckScanWatches();
    }

    private void ScanLoop()
    {
        using var watch = ScanThreadWatch.ForCurrentThread();
        lock (_scanWatches)
        {
            _scanWatches.Add(watch);
        }

        try
        {
            while (!_stop.IsCancellationRequested)
            {
                _readySignal.Wait(_stop.Token);
                if (_queue.TryTakeReady(out var file))
                {
                    Handle(file, watch);
                }
            }
        }
        finally
        {
            lock (_scanWatches)
            {
                _scanWatches.Remove(watch);
            }
        }
    }

    /// <summary>
    /// Review D1 H1: a scan thread past its stage deadline (an open stuck behind an oplock break that is never acknowledged,
    /// a quarantine reopen, anything synchronous) gets <c>CancelSynchronousIo</c>, again every second until it moves on.
    /// </summary>
    private void CheckScanWatches()
    {
        ScanThreadWatch[] watches;
        lock (_scanWatches)
        {
            watches = [.. _scanWatches];
        }

        foreach (var watch in watches)
        {
            if (watch.CancelIfOverdue(Environment.TickCount64) is { } stuck)
            {
                Interlocked.Increment(ref _counters.Cancelled);
                _logger.LogWarning("Real-time: a scan thread was stuck on {Path} ({Stage}); its synchronous I/O was cancelled.", stuck.Path, stuck.Stage);
            }
        }
    }

    private void RescanLoop()
    {
        var waits = new WaitHandle[] { _rescanSignal, _stop.Token.WaitHandle };
        while (!_stop.IsCancellationRequested)
        {
            WaitHandle.WaitAny(waits, TimeSpan.FromSeconds(1));
            while (!_stop.IsCancellationRequested && _queue.HasRoom && TryTakeRescan(out var request))
            {
                try
                {
                    Rescan(request);
                }
                catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
                {
                    _logger.LogWarning(ex, "Real-time: a rescan of {Folder} failed.", Shown(request.Root.ExactPath));
                }
            }
        }
    }

    private void ScheduleRevalidation(TimeSpan after)
    {
        long at = (_time.GetUtcNow() + after).UtcTicks;
        long current;
        do
        {
            current = Interlocked.Read(ref _nextRevalidateTicks);
            if (current != 0 && current <= at && after < _options.RevalidateInterval)
            {
                return; // an earlier one is already planned
            }
        }
        while (Interlocked.CompareExchange(ref _nextRevalidateTicks, at, current) != current);

        _wake.Set();
    }

    // ---- One file ----

    private readonly record struct Step(RealTimeFileResult? Result, TimeSpan? RetryAfter)
    {
        public static Step Done(RealTimeFileResult result) => new(result, null);

        public static Step Retry(TimeSpan delay) => new(null, delay);
    }

    /// <summary>Handles one file on a scan thread (never throws except for shutdown).</summary>
    private void Handle(PendingFile file, ScanThreadWatch watch)
    {
        Step step;
        try
        {
            step = Process(file, watch);
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Real-time: handling {Path} failed.", Shown(file.Root.PathOf(file.Relative)));
            step = Step.Done(new(Shown(file.Root.PathOf(file.Relative)), RealTimeOutcome.Error, Detail: $"Real-time handling failed ({ex.GetType().Name})."));
        }

        var now = _time.GetUtcNow();
        if (step.RetryAfter is { } delay)
        {
            Interlocked.Increment(ref _counters.LockRetries);
            _queue.Retry(file, delay, now);
            _wake.Set();
            return;
        }

        if (_queue.Complete(file, now, scanned: step.Result!.Outcome == RealTimeOutcome.Scanned))
        {
            _wake.Set();
        }

        _spaceFreed.Set();
        Publish(step.Result);
    }

    private Step Process(PendingFile file, ScanThreadWatch watch)
    {
        try
        {
            return ProcessWatched(file, watch);
        }
        finally
        {
            watch.Disarm();
        }
    }

    private Step ProcessWatched(PendingFile file, ScanThreadWatch watch)
    {
        var root = file.Root;
        string shown = Shown(root.PathOf(file.Relative));
        var (folder, name) = RelativeOpen.Split(file.Relative);
        watch.Arm(shown, "open", _options.StuckOpenTimeout);
        SafeFileHandle? parent = null;
        var failure = SafeTreeFailure.NotFound; // the root stopped being watched meanwhile
        int error = 0;
        try
        {
            if (!root.Closed)
            {
                parent = RelativeOpen.OpenFolder(root.Handle, folder, out failure, out error);
            }
        }
        catch (ObjectDisposedException)
        {
            parent = null;
            failure = SafeTreeFailure.NotFound;
        }

        if (parent is null)
        {
            return Step.Done(failure switch
            {
                SafeTreeFailure.NotFound => new(shown, RealTimeOutcome.Gone),
                SafeTreeFailure.Redirected => new(shown, RealTimeOutcome.SkippedLink, Detail: "A folder on its path is a junction or symbolic link; not followed."),
                _ => new(shown, RealTimeOutcome.Error, Detail: $"Its folder could not be opened safely ({failure}, Win32 error {error})."),
            });
        }

        var shared = new SharedFolder(parent);
        try
        {
            return ProbeAndScan(file, shown, shared, name, watch);
        }
        finally
        {
            shared.Release();
        }
    }

    private Step ProbeAndScan(PendingFile file, string shown, SharedFolder parent, string name, ScanThreadWatch watch)
    {
        var probe = UnlockProbe.Probe(parent.Handle, name);
        bool expired = false;
        switch (probe.Outcome)
        {
            case ProbeOutcome.Gone:
                return Step.Done(new(shown, RealTimeOutcome.Gone));
            case ProbeOutcome.Link:
                return Step.Done(new(shown, RealTimeOutcome.SkippedLink, Detail: "It is a junction or symbolic link; not followed."));
            case ProbeOutcome.Directory:
                RequestRescan(file.Root, file.Relative, since: null, _time.GetUtcNow());
                return Step.Done(new(shown, RealTimeOutcome.FolderQueued));
            case ProbeOutcome.BlockedByAntivirus:
                return Step.Done(new(shown, RealTimeOutcome.BlockedByAntivirus, Detail: "Another antivirus blocked the file before sap-AV could scan it."));
            case ProbeOutcome.Locked:
                if (LockRetry(file) is { } delay)
                {
                    return Step.Retry(delay);
                }

                if (_options.IsInProgressName(name))
                {
                    return Step.Done(new(shown, RealTimeOutcome.StillLocked,
                        Detail: "An unfinished download still open for writing; the finished file is scanned when it is renamed.") { LockWaitExpired = true });
                }

                expired = true; // scanned anyway: the pipeline opens it shared, with the change-journal check
                break;
            case ProbeOutcome.Unlocked when probe.Length > _options.MaxFileSizeBytes:
                return Step.Done(new(shown, RealTimeOutcome.TooLarge, Detail: $"Larger than the real-time size limit ({_options.MaxFileSizeBytes} bytes); not scanned."));
            case ProbeOutcome.Unlocked:
                break;
            default:
                return Step.Done(new(shown, RealTimeOutcome.Error, Detail: $"It could not be opened safely ({probe.Outcome}, Win32 error {probe.Win32Error})."));
        }

        var budget = BudgetFor(file.Root, probe.Owner);
        watch.Arm(shown, "scan", StuckScanTimeout); // the worker has its own timeout; this catches a stuck quarantine reopen
        var outcome = _pipeline.ProcessDetailedAsync(shown, ScanTrigger.RealTime, _ => { }, _stop.Token, folder: parent, name: name,
            priority: ScanPriority.High, budget: budget, completeIfOplocked: true).GetAwaiter().GetResult();
        if (outcome.Result is not { } result)
        {
            return Step.Done(new(shown, RealTimeOutcome.Excluded));
        }

        switch (result.SkipReason)
        {
            case ScanSkipReason.Locked when !expired:
                // A writer reopened it after the probe, or a byte-range lock: wait like for a writer, then report it Locked.
                return LockRetry(file) is { } again ? Step.Retry(again) : Step.Done(new(shown, RealTimeOutcome.Scanned, result) { LockWaitExpired = true });
            case ScanSkipReason.TooLarge:
                return Step.Done(new(shown, RealTimeOutcome.TooLarge, result) { LockWaitExpired = expired });
            case ScanSkipReason.BlockedByAntivirus:
                return Step.Done(new(shown, RealTimeOutcome.BlockedByAntivirus, result, "Another antivirus blocked reading the file.") { LockWaitExpired = expired });
            case ScanSkipReason.NotFound:
                return Step.Done(new(shown, RealTimeOutcome.Gone, result));
            default:
                return Step.Done(new(shown, RealTimeOutcome.Scanned, result) { LockWaitExpired = expired });
        }
    }

    /// <summary>Distinct owners with their own real-time budget (review D1 M2); further owners share one.</summary>
    internal const int MaxOwnerBudgets = 64;

    /// <summary>Review D1 H1: the pipeline call (worker scan, alert, quarantine) is overdue after this.</summary>
    private static readonly TimeSpan StuckScanTimeout = TimeSpan.FromMinutes(3);

    /// <summary>
    /// Review D1 M2: the real-time budget for a file: the watched folder's user (<c>engine:RealTime:&lt;SID&gt;</c>), or for a
    /// machine-wide folder the file's owner. Files owned by SYSTEM, Administrators or TrustedInstaller (which no standard user
    /// can create) and files whose owner is unknown use the engine's own <c>engine:RealTime</c> budget, which therefore stays
    /// reserved for the engine: one user's synthetic detections can't use up another user's or the engine's quarantine slots.
    /// </summary>
    internal ScanBudget BudgetFor(WatchedRoot root, string? fileOwner)
    {
        string? owner = root.Folder.Sid ?? fileOwner;
        if (owner is null || owner is "S-1-5-18" or "S-1-5-32-544" || owner == AutoQuarantinePolicy.TrustedInstaller.Value)
        {
            return new ScanBudget(ScanTrigger.RealTime);
        }

        lock (_owners)
        {
            if (!_owners.Contains(owner))
            {
                if (_owners.Count >= MaxOwnerBudgets)
                {
                    owner = "*";
                }
                else
                {
                    _owners.Add(owner);
                }
            }
        }

        return new ScanBudget(ScanTrigger.RealTime) { Owner = owner };
    }

    /// <summary>The next wait while a writer has the file, or null when <see cref="RealTimeOptions.MaxLockWait"/> has run out.</summary>
    private TimeSpan? LockRetry(PendingFile file)
    {
        var now = _time.GetUtcNow();
        file.LockWaitStart ??= now;
        if (now - file.LockWaitStart.Value >= _options.MaxLockWait)
        {
            return null;
        }

        double factor = Math.Pow(2, Math.Min(file.LockAttempts++, 20));
        var delay = TimeSpan.FromTicks((long)Math.Min(_options.LockRetryInitial.Ticks * factor, _options.LockRetryMax.Ticks));
        var left = file.LockWaitStart.Value + _options.MaxLockWait - now;
        return delay < left ? delay : left;
    }

    /// <summary>Queue rank: Mark-of-the-Web first (an event for its stream, or the stream exists), then by file class.</summary>
    private int RankSafely(PendingFile file)
    {
        var (folder, name) = RelativeOpen.Split(file.Relative);
        bool motw = file.MotwHint;
        if (!motw && !file.Root.Closed)
        {
            try
            {
                using var parent = RelativeOpen.OpenFolder(file.Root.Handle, folder, out _, out _);
                motw = parent is not null && HasMarkOfTheWeb(parent, name);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // The root went away (ObjectDisposedException) or the probe failed: ranked without a mark; the scan thread reports the rest.
            }
        }

        return (motw ? 0 : 10) + _rules.ClassOf(name);
    }

    /// <summary>
    /// Whether the file has a <c>Zone.Identifier</c> stream: an attributes-only open relative to its folder's handle (no
    /// sharing check, no oplock break, no recall). Its content is parsed by the scan worker, never here.
    /// </summary>
    internal static bool HasMarkOfTheWeb(SafeFileHandle parent, string name)
    {
        using var stream = SafeTree.OpenChild(parent, name + ":Zone.Identifier", N.FileReadAttributes, SafeTree.ShareAll,
            N.FileNonDirectoryFile | SafeTree.OpenNoRecall | N.FileCompleteIfOplocked, out _, out _);
        return stream is not null;
    }

    private void Publish(RealTimeFileResult result)
    {
        Count(result);
        Log(result);
        try
        {
            FileHandled?.Invoke(result);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "A real-time result handler failed.");
        }
    }

    private void Count(RealTimeFileResult result)
    {
        if (result.LockWaitExpired)
        {
            Interlocked.Increment(ref _counters.LockWaitsExpired);
        }

        switch (result.Outcome)
        {
            case RealTimeOutcome.Scanned:
                Interlocked.Increment(ref _counters.Scanned);
                break;
            case RealTimeOutcome.Gone or RealTimeOutcome.Excluded or RealTimeOutcome.StillLocked:
                Interlocked.Increment(ref _counters.Gone);
                break;
            case RealTimeOutcome.SkippedLink:
                Interlocked.Increment(ref _counters.Links);
                break;
            case RealTimeOutcome.TooLarge:
                Interlocked.Increment(ref _counters.TooLarge);
                break;
            case RealTimeOutcome.BlockedByAntivirus:
                Interlocked.Increment(ref _counters.Blocked);
                break;
            case RealTimeOutcome.FolderQueued:
                break; // counted as a rescan
            default:
                Interlocked.Increment(ref _counters.Errors);
                break;
        }

        if (result.Scan is { Verdict: { } verdict } && verdict != Verdict.Clean)
        {
            Interlocked.Increment(ref _counters.Flagged);
        }

        if (result.Scan?.Action == ScanFileAction.Quarantined)
        {
            Interlocked.Increment(ref _counters.Quarantined);
        }
    }

    private void Log(RealTimeFileResult result)
    {
        var scan = result.Scan;
        if (scan is { Verdict: { } verdict } && verdict != Verdict.Clean)
        {
            _logger.LogWarning("Real-time: {Path} is {Verdict} ({Action}).", result.Path, verdict, scan.Action);
        }
        else if (result.Outcome == RealTimeOutcome.BlockedByAntivirus)
        {
            _logger.LogInformation("Real-time: {Path}: {Detail}", result.Path, result.Detail);
        }
        else if (result.Outcome == RealTimeOutcome.Error)
        {
            _logger.LogWarning("Real-time: {Path} was not scanned: {Detail}", result.Path, result.Detail);
        }
        else if (result.LockWaitExpired || scan is { SkipReason: not null })
        {
            _logger.LogInformation("Real-time: {Path}: {Outcome}{Expired}; {Detail}", result.Path, result.Outcome,
                result.LockWaitExpired ? $" after waiting {_options.MaxLockWait} for the writer to close it" : string.Empty, result.Detail ?? scan?.Detail);
        }
        else
        {
            _logger.LogDebug("Real-time: {Path}: {Outcome}.", result.Path, result.Outcome);
        }
    }

    // ---- Watched folders ----

    private void RevalidateSafely()
    {
        try
        {
            Revalidate();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Real-time: re-checking the watched folders failed; the current watches stay.");
        }
    }

    /// <summary>
    /// Resolves the folders again and makes the watches match: new folders are opened and watched, folders no longer wanted
    /// (or no longer safe: now a link, gone, remote) stop, and a folder whose object changed (renamed and replaced) is watched
    /// again on the new object. Runs at start, every <see cref="RealTimeOptions.RevalidateInterval"/>, and soon after a watch fails.
    /// </summary>
    internal void Revalidate()
    {
        var set = _folders.Resolve();
        var desired = new Dictionary<string, WatchedFolder>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in set.Folders)
        {
            if (ExactPath.ToExtended(folder.Path) is { } exact)
            {
                desired.TryAdd(exact, folder);
            }
        }

        lock (_rootsLock)
        {
            foreach (var (key, root) in _roots.Where(r => !desired.ContainsKey(r.Key)).ToArray())
            {
                StopRootLocked(key, root, "it is no longer a watched folder");
            }

            foreach (var key in _problems.Keys.Where(k => !desired.ContainsKey(k)).ToArray())
            {
                _problems.Remove(key);
            }

            foreach (var (key, folder) in desired)
            {
                RevalidateLocked(key, folder);
            }
        }
    }

    private void RevalidateLocked(string key, WatchedFolder folder)
    {
        _roots.TryGetValue(key, out var existing);
        var opened = OpenRoot(key, out string? problem);
        if (opened is null)
        {
            if (existing is not null)
            {
                StopRootLocked(key, existing, problem!);
            }

            NoteProblemLocked(key, problem!);
            return;
        }

        if (existing is { Closed: false, Failed: false } && existing.Volume == opened.Value.Volume
            && string.Equals(existing.FileId, opened.Value.FileId, StringComparison.Ordinal))
        {
            opened.Value.Handle.Dispose(); // the same folder object: the watch stays
            return;
        }

        if (existing is not null)
        {
            StopRootLocked(key, existing, existing.Failed ? "its watch failed" : "the folder was replaced");
        }

        var root = new WatchedRoot(++_nextRootId, folder, key, opened.Value.Handle, opened.Value.Volume, opened.Value.FileId, _time.GetUtcNow());
        try
        {
            root.Watch = _watches.Start(root, this, _options.WatcherBufferBytes);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            root.Dispose();
            NoteProblemLocked(key, $"it could not be watched ({ex.Message})");
            return;
        }

        _roots[key] = root;
        if (_problems.Remove(key))
        {
            _logger.LogInformation("Real-time: {Folder} is watched again.", Shown(key));
        }
    }

    /// <summary>Opens a watched folder (<see cref="WatchedRootOpener"/>) that isn't excluded from scanning.</summary>
    private WatchedRootOpener.Opened? OpenRoot(string exact, out string? problem)
    {
        if (WatchedRootOpener.IsOnFixedDrive(exact, _driveType) && _excluded.Contains(exact))
        {
            problem = "it is excluded from scanning";
            return null;
        }

        return WatchedRootOpener.Open(exact, _driveType, _remote, out problem);
    }

    private void StopRootLocked(string key, WatchedRoot root, string why)
    {
        _roots.Remove(key);
        int dropped = _queue.RemoveRoot(root);
        lock (_rescanLock)
        {
            foreach (var stale in _rescans.Where(r => ReferenceEquals(r.Value.Root, root)).Select(r => r.Key).ToArray())
            {
                _rescans.Remove(stale);
            }

            _storming.Remove(root.Id);
        }

        _spaceFreed.Set();
        root.Dispose();
        _logger.LogWarning("Real-time: stopped watching {Folder}: {Why} ({Dropped} waiting file(s) dropped).", Shown(key), why, dropped);
    }

    private void NoteProblemLocked(string key, string problem)
    {
        if (!_problems.TryGetValue(key, out var previous) || previous != problem)
        {
            _problems[key] = problem;
            _logger.LogWarning("Real-time: {Folder} is not watched: {Why}.", Shown(key), problem);
        }
    }

    private static string Key(WatchedRoot root, string folder) => root.Id.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + folder;

    private static string Shown(string exact) => ExactPath.ForOpening(exact);

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stop.Cancel();
        _wake.Set();
        _rescanSignal.Set();
        foreach (var thread in _threads)
        {
            if (!thread.Join(TimeSpan.FromSeconds(30)))
            {
                _logger.LogWarning("Real-time: thread {Thread} did not stop in time.", thread.Name);
            }
        }

        lock (_rootsLock)
        {
            foreach (var root in _roots.Values)
            {
                root.Dispose();
            }

            _roots.Clear();
        }

        _stop.Dispose();
        _wake.Dispose();
        _rescanSignal.Dispose();
        _readySignal.Dispose();
        _spaceFreed.Dispose();
    }

    private sealed class Counters
    {
        public long Events, Coalesced, Dropped, Overflows, Rescans, RescansIncomplete, Scanned, Flagged, Quarantined, LockRetries, LockWaitsExpired, Cancelled,
            Blocked, Gone, Links, TooLarge, Errors;
    }
}
