using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Engine.Alerts;
using SapAV.Engine.RealTime;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>A snapshot of real-time persistence monitoring (counters since start).</summary>
/// <param name="Baseline">How the stored baseline loaded at start.</param>
/// <param name="Unjudged">Known entries still waiting for their judgement (a storm, or the initial baseline in progress).</param>
/// <param name="Problems">Places that should be watched but aren't (a folder that is a link, missing or not local).</param>
internal sealed record PersistenceMonitorStatus(
    BaselineLoadStatus Baseline, int Entries, int Unjudged, int RegistryWatches, int FolderWatches, int Problems, long Passes, long Judged,
    long New, long Changed, long Removed, long Flagged, long Failures);

/// <summary>
/// Real-time persistence monitoring (ROADMAP D4): watches every autostart location the C2 collectors read, re-collects only
/// what changed, diffs it against a baseline, and judges new or changed entries with the C3 judgement through the existing
/// target-scan and alert path (alerts 2001 / 2002 with their MITRE IDs, in the Event Log). Read-only: nothing is removed or
/// blocked (Block &amp; remove is D5, always user-confirmed).
/// </summary>
/// <remarks>
/// <para><b>Signals.</b> <see cref="IPersistenceSource.WatchTargets"/> names, per scope (a source's machine part, or one
/// user's part), the registry keys (<c>RegNotifyChangeKeyValue</c>, <see cref="RegistryKeyWatch"/>) and folders (the D1
/// handle-bound <see cref="NativeDirectoryWatch"/>, no link followed) to watch, in HKLM and in every loaded user hive. A
/// notification only marks its scopes dirty (O(1) on the notifying thread). HKEY_USERS is listed every
/// <see cref="PersistenceMonitorOptions.HiveCheckInterval"/> (one key enumeration), and ProfileList and HKU are watched too, so
/// a hive loaded at logon gets its watches and its first collection, and an unloaded one loses its watches (their handles
/// are released).</para>
/// <para><b>Debounce and coalesce.</b> A dirty scope is collected after <see cref="PersistenceMonitorOptions.SettleDelay"/> of
/// quiet (at most <see cref="PersistenceMonitorOptions.MaxSettleDelay"/> after its first change), at most once per
/// <see cref="PersistenceMonitorOptions.MinInterval"/>, and only that scope (only that hive's SID). Definition files that
/// didn't change aren't parsed again (<see cref="ParsedFileCache"/>).</para>
/// <para><b>Fair and bounded.</b> One dedicated background-mode thread does all the work, one pass at a time. Each pass serves
/// one owner (the machine, or one user SID) in turn, round-robin, so a user flooding their own hive or Startup folder only
/// delays their own next pass. A pass judges at most <see cref="PersistenceMonitorOptions.MaxJudgedPerPass"/> entries (new
/// and changed ones first, machine-wide before per-user); the rest wait for that scope's next turn. Collection keeps its own
/// caps (entries per user, items per key, files) and a pass budget. Alerts count against a per-user engine budget
/// (<c>engine:Persistence:&lt;SID&gt;</c>), so one user's synthetic detections can't push another user's or a machine-wide
/// alert into the summary; target scans use that user's real-time-style scan budget.</para>
/// <para><b>Baseline.</b> See <see cref="PersistenceBaseline"/>: the first collection of each scope is judged quietly (only
/// Suspicious / Malicious entries alert, once); after that, new or changed entries are judged and alerted, removed ones are
/// logged at Information. Kept in the protected data folder with an HMAC (<see cref="FileBaselineStore"/>).</para>
/// <para><b>No scheduled cost</b> beyond the hive listing and a <see cref="PersistenceMonitorOptions.SafetyRescanInterval"/>
/// re-collection at background priority, which also catches what no notification reported (e.g. a user-made registry link).</para>
/// </remarks>
internal sealed class PersistenceMonitor : IDirectoryWatchSink, IDisposable
{
    internal const string ServicesSource = "services";

    /// <summary>Distinct users with their own alert budget; further users share one.</summary>
    internal const int MaxOwnerBudgets = 64;

    private readonly PersistenceMonitorOptions _options;
    private readonly IScopedPersistenceCollector _collector;
    private readonly IPersistenceScanner _scanner;
    private readonly IPersistenceBaselineStore _store;
    private readonly IRegistryWatchFactory _registryWatches;
    private readonly IDirectoryWatchFactory _folderWatches;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Func<string, int> _driveType;
    private readonly IRemoteFileProbe _remote;

    private readonly Lock _lock = new();
    private readonly Dictionary<PersistenceScope, ScopeState> _scopes = [];
    private readonly HashSet<PersistenceScope> _known = [];
    private readonly Dictionary<string, ActiveWatch> _watches = new(StringComparer.Ordinal);
    private readonly Dictionary<int, string> _rootTargets = [];
    private readonly Dictionary<string, string> _problems = new(StringComparer.Ordinal);
    private readonly HashSet<string> _owners = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _loadedSids = new(StringComparer.OrdinalIgnoreCase);
    private string? _lastOwner;
    private int _nextRootId;
    private bool _planWanted;
    private DateTimeOffset _nextHiveCheck, _nextRevalidate, _nextSafety;

    private readonly CancellationTokenSource _stop = new();
    private readonly AutoResetEvent _wake = new(false);
    private Thread? _thread;
    private int _started, _disposed;

    // The monitor thread's own state (Initialize, passes, plans), read by Status through the counters below.
    private PersistenceBaseline _baseline = new();
    private BaselineLoadStatus _baselineStatus = BaselineLoadStatus.Missing;
    private bool _baselineDirty, _saveFailing, _initialized, _firstCollectionMarked;
    private int _entries, _unjudged;
    private long _passes, _judged, _new, _changed, _removed, _flagged, _failures;

    public PersistenceMonitor(
        PersistenceMonitorOptions options, IScopedPersistenceCollector collector, IPersistenceScanner scanner, IPersistenceBaselineStore store,
        IRegistryWatchFactory registryWatches, IDirectoryWatchFactory folderWatches, TimeProvider time, ILogger logger,
        Func<string, int>? driveType = null, IRemoteFileProbe? remote = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _collector = collector ?? throw new ArgumentNullException(nameof(collector));
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _registryWatches = registryWatches ?? throw new ArgumentNullException(nameof(registryWatches));
        _folderWatches = folderWatches ?? throw new ArgumentNullException(nameof(folderWatches));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _driveType = driveType ?? Pipe.Native.PipeNative.DriveType;
        _remote = remote ?? RemoteFileProbe.Instance;
    }

    /// <summary>Raised after each pass that judged entries (on the monitor thread; handlers must be quick and must not throw).</summary>
    public event Action<IReadOnlyList<PersistenceFinding>>? Judged;

    public PersistenceMonitorStatus Status
    {
        get
        {
            int registry, folders, problems;
            lock (_lock)
            {
                registry = _watches.Values.Count(w => w.Target.Kind == PersistenceWatchKind.RegistryKey && w.Watch is not null);
                folders = _watches.Values.Count(w => w.Target.Kind == PersistenceWatchKind.Folder && w.Watch is not null);
                problems = _problems.Count;
            }

            return new PersistenceMonitorStatus(_baselineStatus, Volatile.Read(ref _entries), Volatile.Read(ref _unjudged), registry, folders, problems,
                Interlocked.Read(ref _passes), Interlocked.Read(ref _judged), Interlocked.Read(ref _new), Interlocked.Read(ref _changed),
                Interlocked.Read(ref _removed), Interlocked.Read(ref _flagged), Interlocked.Read(ref _failures));
        }
    }

    /// <summary>The places watched right now, by what is watched (tests).</summary>
    internal IReadOnlyList<PersistenceWatchTarget> Watched
    {
        get
        {
            lock (_lock)
            {
                return [.. _watches.Values.Where(w => w.Watch is not null).Select(w => w.Target)];
            }
        }
    }

    /// <summary>Why each place that should be watched isn't (tests and the status).</summary>
    internal IReadOnlyDictionary<string, string> Problems
    {
        get
        {
            lock (_lock)
            {
                return new Dictionary<string, string>(_problems, StringComparer.Ordinal);
            }
        }
    }

    internal PersistenceBaseline Baseline => _baseline;

    /// <summary>Starts the monitor thread (after <see cref="PersistenceMonitorOptions.StartDelay"/>). Once.</summary>
    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            return;
        }

        _thread = BackgroundThread.Start("sap-AV persistence monitor", () => Guarded(Loop));
    }

    // ---- Notifications (registry wait / I/O completion threads: mark, signal, return) ----

    public void OnChanges(WatchedRoot root, IReadOnlyList<FileChange> changes) => FolderChanged(root);

    public void OnOverflow(WatchedRoot root) => FolderChanged(root);

    public void OnFailed(WatchedRoot root, int win32Error)
    {
        if (root.Closed)
        {
            return;
        }

        root.Failed = true;
        _logger.LogWarning("Persistence monitor: the watch on {Folder} stopped (Win32 error {Error}); it is checked again shortly.", ExactPath.ForOpening(root.ExactPath), win32Error);
        lock (_lock)
        {
            var soon = _time.GetUtcNow() + TimeSpan.FromSeconds(5);
            _nextRevalidate = soon < _nextRevalidate ? soon : _nextRevalidate;
        }

        _wake.Set();
    }

    private void FolderChanged(WatchedRoot root)
    {
        if (root.Closed)
        {
            return;
        }

        string? id;
        lock (_lock)
        {
            _rootTargets.TryGetValue(root.Id, out id);
        }

        if (id is not null)
        {
            Changed(id);
        }
    }

    /// <summary>A watched place changed: its scopes are dirty.</summary>
    internal void Changed(string watchId)
    {
        PersistenceScope[] scopes;
        lock (_lock)
        {
            scopes = _watches.TryGetValue(watchId, out var watch) ? [.. watch.Scopes] : [];
        }

        foreach (var scope in scopes)
        {
            MarkDirty(scope);
        }
    }

    /// <summary>Marks a scope for collection (after the settle delay, or right away with <paramref name="immediate"/>).</summary>
    internal void MarkDirty(PersistenceScope scope, bool immediate = false)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return; // a late notification after shutdown
        }

        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (scope == PersistenceScope.Profiles)
            {
                _planWanted = true;
            }
            else if (scope == PersistenceScope.All)
            {
                foreach (var known in _known)
                {
                    MarkDirtyLocked(known, now, immediate);
                }
            }
            else
            {
                MarkDirtyLocked(scope, now, immediate);
            }
        }

        _wake.Set();
    }

    private void MarkDirtyLocked(PersistenceScope scope, DateTimeOffset now, bool immediate)
    {
        if (!_scopes.TryGetValue(scope, out var state))
        {
            _scopes[scope] = state = new ScopeState();
        }

        state.First ??= immediate ? now - _options.MaxSettleDelay : now;
        state.Last = immediate ? now - _options.SettleDelay : now;
        if (immediate)
        {
            state.LastRun = null; // a start, a safety rescan or a newly loaded hive isn't held back by the storm interval
        }
    }

    // ---- The monitor thread ----

    private void Guarded(Action body)
    {
        try
        {
            body();
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(ex, "The persistence monitor stopped; autostart changes are found only by scans until the engine restarts.");
        }
    }

    private void Loop()
    {
        if (_options.StartDelay > TimeSpan.Zero && _stop.Token.WaitHandle.WaitOne(_options.StartDelay))
        {
            return;
        }

        Initialize();
        var waits = new WaitHandle[] { _wake, _stop.Token.WaitHandle };
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                Tick();
            }
            catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
            {
                Interlocked.Increment(ref _failures);
                _logger.LogError(ex, "Persistence monitor: a pass failed.");
                _stop.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(1));
            }

            var wait = NextWake() - _time.GetUtcNow();
            wait = wait < TimeSpan.FromMilliseconds(1) ? TimeSpan.FromMilliseconds(1) : wait > TimeSpan.FromMinutes(1) ? TimeSpan.FromMinutes(1) : wait;
            WaitHandle.WaitAny(waits, wait);
        }
    }

    /// <summary>Loads the baseline, starts the watches, and marks every scope for its first collection.</summary>
    internal void Initialize()
    {
        var load = _store.Load();
        _baselineStatus = load.Status;
        _baseline = new PersistenceBaseline(load.Status == BaselineLoadStatus.Loaded ? load.Snapshot : null);
        switch (load.Status)
        {
            case BaselineLoadStatus.Tampered:
                _logger.LogWarning("Persistence monitor: the stored baseline was refused ({Why}); it is taken again, and existing autostart entries are judged once more.", load.Problem);
                break;
            case BaselineLoadStatus.Missing:
                _logger.LogInformation("Persistence monitor: no baseline yet; existing autostart entries are judged once (only Suspicious or Malicious ones alert).");
                break;
            default:
                _logger.LogInformation("Persistence monitor: baseline of {Count} autostart entries loaded.", _baseline.Count);
                break;
        }

        UpdateCounts();
        RefreshWatches();
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            _nextHiveCheck = now + _options.HiveCheckInterval;
            _nextRevalidate = now + _options.RevalidateInterval;
            _nextSafety = now + _options.SafetyRescanInterval;
        }

        _initialized = true;
        MarkFirstCollection();
    }

    /// <summary>Every known scope's first collection, once there is a plan (if the first one failed, after the next that works).</summary>
    private void MarkFirstCollection()
    {
        bool known;
        lock (_lock)
        {
            known = _known.Count > 0;
        }

        if (_initialized && !_firstCollectionMarked && known)
        {
            _firstCollectionMarked = true;
            MarkDirty(PersistenceScope.All, immediate: true);
        }
    }

    /// <summary>One round of the thread: hive check, plan refresh, safety rescan when due, then at most one pass.</summary>
    internal void Tick()
    {
        var now = _time.GetUtcNow();
        bool hives, plan, safety;
        lock (_lock)
        {
            hives = now >= _nextHiveCheck;
            if (hives)
            {
                _nextHiveCheck = now + _options.HiveCheckInterval;
            }

            plan = _planWanted || now >= _nextRevalidate;
            if (plan)
            {
                _nextRevalidate = now + _options.RevalidateInterval;
            }

            safety = now >= _nextSafety;
            if (safety)
            {
                _nextSafety = now + _options.SafetyRescanInterval;
            }
        }

        if (hives && CheckHives())
        {
            plan = true;
        }

        if (plan)
        {
            RefreshWatches();
        }

        if (safety)
        {
            _logger.LogInformation("Persistence monitor: safety rescan of every autostart location.");
            MarkDirty(PersistenceScope.All, immediate: true);
        }

        RunDue(maxPasses: 1);
    }

    private DateTimeOffset NextWake()
    {
        lock (_lock)
        {
            var next = _nextHiveCheck < _nextRevalidate ? _nextHiveCheck : _nextRevalidate;
            next = _nextSafety < next ? _nextSafety : next;
            if (_planWanted)
            {
                return _time.GetUtcNow();
            }

            foreach (var (scope, state) in _scopes)
            {
                if (Due(scope, state) is { } due && due < next)
                {
                    next = due;
                }
            }

            return next;
        }
    }

    /// <summary>Runs passes while scopes are due (at most <paramref name="maxPasses"/>); returns how many ran.</summary>
    internal int RunDue(int maxPasses = 1000)
    {
        int ran = 0;
        while (ran < maxPasses && !_stop.IsCancellationRequested && TryTakeDue(_time.GetUtcNow(), out var owner, out var scopes))
        {
            RunPass(owner, scopes);
            ran++;
        }

        return ran;
    }

    // ---- Scheduling ----

    private sealed class ScopeState
    {
        public DateTimeOffset? First { get; set; }

        public DateTimeOffset Last { get; set; }

        public DateTimeOffset? LastRun { get; set; }

        public DateTimeOffset? ContinueAt { get; set; }
    }

    private TimeSpan MinIntervalFor(PersistenceScope scope) => scope.Source == ServicesSource ? _options.ServicesMinInterval : _options.MinInterval;

    private DateTimeOffset? Due(PersistenceScope scope, ScopeState state)
    {
        DateTimeOffset? due = null;
        if (state.First is { } first)
        {
            var settled = Min(state.Last + _options.SettleDelay, first + _options.MaxSettleDelay);
            due = state.LastRun is { } last && last + MinIntervalFor(scope) > settled ? last + MinIntervalFor(scope) : settled;
        }

        if (state.ContinueAt is { } next)
        {
            due = due is { } d ? Min(d, next) : next;
        }

        return due;
    }

    /// <summary>The next owner in turn with a due scope, and all of that owner's due scopes (taken: events from now on mark them again).</summary>
    private bool TryTakeDue(DateTimeOffset now, out string owner, out PersistenceScope[] scopes)
    {
        lock (_lock)
        {
            var due = _scopes.Where(s => Due(s.Key, s.Value) is { } at && at <= now).Select(s => s.Key).ToArray();
            if (due.Length == 0)
            {
                owner = string.Empty;
                scopes = [];
                return false;
            }

            var owners = due.Select(s => s.Owner).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            owner = _lastOwner is null ? owners[0] : owners.FirstOrDefault(o => string.CompareOrdinal(o, _lastOwner) > 0) ?? owners[0];
            _lastOwner = owner;
            string chosen = owner;
            scopes = due.Where(s => s.Owner == chosen).ToArray();
            foreach (var scope in scopes)
            {
                var state = _scopes[scope];
                state.First = null;
                state.ContinueAt = null;
                state.LastRun = now;
            }

            return true;
        }
    }

    private void ContinueLater(IEnumerable<PersistenceScope> scopes, TimeSpan after)
    {
        var at = _time.GetUtcNow() + after;
        lock (_lock)
        {
            foreach (var scope in scopes)
            {
                if (_scopes.TryGetValue(scope, out var state))
                {
                    state.ContinueAt = state.ContinueAt is { } existing ? Min(existing, at) : at;
                }
            }
        }
    }

    // ---- One pass ----

    /// <summary>Collects the owner's due scopes, diffs them against the baseline, and judges what is new or changed (capped).</summary>
    private void RunPass(string owner, PersistenceScope[] scopes)
    {
        Interlocked.Increment(ref _passes);
        try
        {
            var collected = _collector.CollectScoped(scopes, _stop.Token, new PersistenceCollectOptions { TimeBudget = _options.CollectionTimeBudget });
            var diff = _baseline.Apply(collected);
            _baselineDirty |= diff.Any;
            LogDiff(diff);

            var pending = _baseline.Pending(collected, int.MaxValue);
            var batch = Cap(pending, _options.MaxJudgedPerPass);
            if (batch.Count > 0)
            {
                Judge(owner, batch);
            }

            if (pending.Count > batch.Count)
            {
                _logger.LogInformation("Persistence monitor: {Waiting} autostart entries of {Owner} wait for their judgement (at most {Max} per pass).",
                    pending.Count - batch.Count, OwnerName(owner), _options.MaxJudgedPerPass);
                ContinueLater(pending.Skip(batch.Count).Select(p => p.Record.Scope).Distinct(), _options.ContinuationDelay); // only scopes with entries left
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Interlocked.Increment(ref _failures);
            _logger.LogWarning(ex, "Persistence monitor: the pass for {Owner} failed; it is tried again later.", OwnerName(owner));
            ContinueLater(scopes, _options.MinInterval);
        }
        finally
        {
            UpdateCounts();
            SaveIfDirty();
        }
    }

    private static List<PendingJudgement> Cap(IReadOnlyList<PendingJudgement> pending, int maxEntries)
    {
        var batch = new List<PendingJudgement>();
        int entries = 0;
        foreach (var item in pending)
        {
            if (batch.Count > 0 && entries + item.Entries.Count > maxEntries)
            {
                break;
            }

            batch.Add(item);
            entries += item.Entries.Count;
        }

        return batch;
    }

    private void Judge(string owner, IReadOnlyList<PendingJudgement> batch)
    {
        var entries = batch.SelectMany(p => p.Entries).ToArray();
        var budget = OwnerBudget(owner);
        var options = new PersistenceScanOptions
        {
            Trigger = ScanTrigger.Persistence,
            Priority = owner.Length == 0 ? ScanPriority.High : ScanPriority.Normal,
            Parallelism = 1, // on this background-mode thread, one worker at a time
            TimeBudget = _options.ScanTimeBudget,
            MaxTargets = _options.MaxJudgedPerPass * 2,
            RaiseAlerts = true,
            AlertBudget = budget.Alerts,
            TargetBudget = budget,
        };

        var result = _scanner.ScanAsync(new PersistenceCollection(entries, [], TimeSpan.Zero), options, _stop.Token).GetAwaiter().GetResult();
        var findings = result.Findings;
        int at = 0, logged = 0, initial = 0, initialFlagged = 0;
        foreach (var item in batch)
        {
            var mine = findings.Skip(at).Take(item.Entries.Count).ToArray();
            at += item.Entries.Count;
            _baseline.MarkJudged(item.Record.Key, item.Record.Fingerprint);
            _baselineDirty = true;
            Interlocked.Increment(ref _judged);
            var worst = mine.Length == 0 ? Verdict.Clean : mine.Max(f => f.Verdict);
            bool flagged = worst != Verdict.Clean;
            if (flagged)
            {
                Interlocked.Increment(ref _flagged);
            }

            if (item.Record.Change == BaselineChange.Initial)
            {
                initial++;
                initialFlagged += flagged ? 1 : 0;
                continue;
            }

            Interlocked.Increment(ref item.Record.Change == BaselineChange.New ? ref _new : ref _changed);
            if (logged++ < _options.MaxLoggedChangesPerPass)
            {
                var entry = item.Entries[0];
                _logger.Log(flagged ? LogLevel.Warning : LogLevel.Information, "Persistence monitor: {Change} autostart entry {Location} ({Kind}, {Scope}): {Verdict}{Outcome}. Runs: {Command}",
                    item.Record.Change == BaselineChange.New ? "new" : "changed", item.Record.Display, entry.Kind, item.Record.Scope, worst,
                    mine.Any(f => f.Outcome == PersistenceOutcome.Unverified) ? " (unverified)" : string.Empty, entry.CommandLine);
            }
        }

        if (logged > _options.MaxLoggedChangesPerPass)
        {
            _logger.LogInformation("Persistence monitor: {More} more new or changed autostart entries of {Owner} were judged.", logged - _options.MaxLoggedChangesPerPass, OwnerName(owner));
        }

        if (initial > 0)
        {
            _logger.LogInformation("Persistence monitor: baseline: {Count} existing autostart entries of {Owner} judged, {Flagged} flagged.", initial, OwnerName(owner), initialFlagged);
        }

        try
        {
            Judged?.Invoke(findings);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "A persistence monitor result handler failed.");
        }
    }

    /// <summary>The scan budget (and with it the alert budget) of an owner: the engine's for the machine, the user's own otherwise (at most <see cref="MaxOwnerBudgets"/>).</summary>
    internal ScanBudget OwnerBudget(string owner)
    {
        if (owner.Length == 0)
        {
            return new ScanBudget(ScanTrigger.Persistence);
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

        return new ScanBudget(ScanTrigger.Persistence) { Owner = owner };
    }

    private void LogDiff(BaselineDiff diff)
    {
        Interlocked.Add(ref _removed, diff.Removed.Count);
        foreach (var gone in diff.Removed.Take(_options.MaxLoggedChangesPerPass))
        {
            _logger.LogInformation("Persistence monitor: autostart entry removed: {Location} ({Scope}).", gone.Display, gone.Scope);
        }

        if (diff.Removed.Count > _options.MaxLoggedChangesPerPass)
        {
            _logger.LogInformation("Persistence monitor: {More} more autostart entries were removed.", diff.Removed.Count - _options.MaxLoggedChangesPerPass);
        }

        foreach (var scope in diff.NewlyBaselined)
        {
            _logger.LogDebug("Persistence monitor: {Scope} is baselined.", scope);
        }
    }

    private void SaveIfDirty()
    {
        if (!_baselineDirty)
        {
            return;
        }

        try
        {
            _store.Save(_baseline.Snapshot());
            _baselineDirty = false;
            if (_saveFailing)
            {
                _saveFailing = false;
                _logger.LogInformation("Persistence monitor: the baseline is saved again.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (!_saveFailing)
            {
                _saveFailing = true;
                _logger.LogWarning("Persistence monitor: the baseline can't be saved ({Why}); it is kept in memory.", ex.Message);
            }
        }
    }

    private void UpdateCounts()
    {
        Volatile.Write(ref _entries, _baseline.Count);
        Volatile.Write(ref _unjudged, _baseline.Unjudged);
    }

    // ---- Watches ----

    private sealed class ActiveWatch(PersistenceWatchTarget target)
    {
        public PersistenceWatchTarget Target { get; } = target;

        public HashSet<PersistenceScope> Scopes { get; } = [];

        public IDisposable? Watch { get; set; }

        public WatchedRoot? Root { get; set; }
    }

    /// <summary>The loaded user hives changed since the last plan (a logon or logoff).</summary>
    internal bool CheckHives()
    {
        HashSet<string> loaded;
        try
        {
            using var users = _collector.Registry.Open(RegistryRoot.Users, string.Empty);
            loaded = (users?.SubKeyNames() ?? []).Where(RegistryEnvironment.IsUserSid).Take(PersistenceCollector.MaxProfiles).ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return false;
        }

        lock (_lock)
        {
            return !loaded.SetEquals(_loadedSids);
        }
    }

    /// <summary>
    /// Makes the watches match the sources' current plan: new places are watched, places no longer wanted (an unloaded hive's
    /// keys) are released, a folder whose object changed (replaced, now a link) is watched again or refused. Newly loaded
    /// hives get their first collection; users whose profile is gone are forgotten.
    /// </summary>
    internal void RefreshWatches()
    {
        PersistenceWatchPlan plan;
        try
        {
            plan = _collector.Plan(_stop.Token);
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            _logger.LogWarning(ex, "Persistence monitor: the watch plan failed; the current watches stay.");
            return;
        }

        var desired = new Dictionary<string, (PersistenceWatchTarget Target, HashSet<PersistenceScope> Scopes)>(StringComparer.Ordinal);
        foreach (var (scope, target) in plan.Watches)
        {
            if (!desired.TryGetValue(target.Id, out var entry))
            {
                desired[target.Id] = entry = (target, []);
            }

            entry.Scopes.Add(scope);
        }

        var stop = new List<ActiveWatch>();
        var start = new List<ActiveWatch>();
        string[] newlyLoaded;
        lock (_lock)
        {
            _planWanted = false;
            newlyLoaded = [.. plan.LoadedSids.Where(s => !_loadedSids.Contains(s))];
            foreach (var gone in _loadedSids.Where(s => !plan.LoadedSids.Contains(s)))
            {
                _logger.LogInformation("Persistence monitor: the hive of {Sid} was unloaded; its registry watches are released.", gone);
            }

            _loadedSids = new HashSet<string>(plan.LoadedSids, StringComparer.OrdinalIgnoreCase);
            _known.Clear();
            _known.UnionWith(plan.SourceNames.Select(s => new PersistenceScope(s, null)));
            _known.UnionWith(plan.Watches.Select(w => w.Scope).Where(s => !s.IsSpecial));

            foreach (var (id, watch) in _watches.Where(w => !desired.ContainsKey(w.Key)).ToArray())
            {
                _watches.Remove(id);
                _problems.Remove(id);
                stop.Add(watch);
            }

            foreach (var (id, (target, scopes)) in desired)
            {
                if (!_watches.TryGetValue(id, out var watch))
                {
                    _watches[id] = watch = new ActiveWatch(target);
                    start.Add(watch);
                }
                else if (watch.Watch is null || (watch.Root is { } root && (root.Failed || root.Closed)) || target.Kind == PersistenceWatchKind.Folder)
                {
                    start.Add(watch); // a failed watch is retried; a folder is re-checked (it may have been replaced)
                }

                watch.Scopes.Clear();
                watch.Scopes.UnionWith(scopes);
            }
        }

        foreach (var watch in stop)
        {
            StopWatch(watch);
        }

        foreach (var watch in start)
        {
            StartOrRecheck(watch);
        }

        if (_initialized && _firstCollectionMarked)
        {
            foreach (var sid in newlyLoaded)
            {
                _logger.LogInformation("Persistence monitor: the hive of {Sid} was loaded; its autostart locations are watched and collected.", sid);
                foreach (var scope in plan.Watches.Select(w => w.Scope).Where(s => string.Equals(s.UserSid, sid, StringComparison.OrdinalIgnoreCase)).Distinct())
                {
                    MarkDirty(scope, immediate: true);
                }
            }
        }

        MarkFirstCollection();

        if (plan.ProfilesComplete && _baseline.ForgetUsers(plan.UserSids.Concat(plan.LoadedSids).ToHashSet(StringComparer.OrdinalIgnoreCase)) is > 0 and var forgotten)
        {
            _logger.LogInformation("Persistence monitor: {Count} baseline entries of profiles that no longer exist were dropped.", forgotten);
            _baselineDirty = true;
            UpdateCounts();
            SaveIfDirty();
        }
    }

    private void StartOrRecheck(ActiveWatch watch)
    {
        var target = watch.Target;
        if (target.Kind == PersistenceWatchKind.RegistryKey)
        {
            if (watch.Watch is not null)
            {
                return;
            }

            string id = target.Id;
            try
            {
                watch.Watch = _registryWatches.Watch(target.Root, target.Path, target.Subtree, () => Changed(id));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                NoteProblem(id, $"it could not be watched ({ex.GetType().Name})");
            }

            return;
        }

        StartFolder(watch);
    }

    private void StartFolder(ActiveWatch watch)
    {
        string id = watch.Target.Id;
        if (ExactPath.ToExtended(watch.Target.Path) is not { } exact)
        {
            NoteProblem(id, "it isn't a local folder path");
            return;
        }

        var opened = WatchedRootOpener.Open(exact, _driveType, _remote, out string? problem);
        if (opened is null)
        {
            ReplaceRoot(watch, null);
            NoteProblem(id, problem!);
            return;
        }

        if (watch.Root is { Closed: false, Failed: false } current && current.Volume == opened.Value.Volume
            && string.Equals(current.FileId, opened.Value.FileId, StringComparison.Ordinal))
        {
            opened.Value.Handle.Dispose(); // the same folder object: the watch stays
            return;
        }

        int rootId = Interlocked.Increment(ref _nextRootId);
        var root = new WatchedRoot(rootId, new WatchedFolder(watch.Target.Path, WatchedFolderKind.Configured), exact, opened.Value.Handle,
            opened.Value.Volume, opened.Value.FileId, _time.GetUtcNow());
        lock (_lock)
        {
            _rootTargets[rootId] = id;
        }

        try
        {
            root.Watch = _folderWatches.Start(root, this, _options.WatcherBufferBytes, watch.Target.Subtree);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            root.Dispose();
            ReplaceRoot(watch, null);
            NoteProblem(id, $"it could not be watched ({ex.Message})");
            return;
        }

        bool replaced = watch.Root is not null;
        ReplaceRoot(watch, root);
        lock (_lock)
        {
            if (_problems.Remove(id) || replaced)
            {
                _logger.LogInformation("Persistence monitor: {Folder} is watched{Again}.", watch.Target.Path, replaced ? " again (the folder object changed)" : string.Empty);
            }
        }

        if (replaced)
        {
            Changed(id); // whatever happened while it was replaced
        }
    }

    private void ReplaceRoot(ActiveWatch watch, WatchedRoot? root)
    {
        var old = watch.Root;
        watch.Root = root;
        watch.Watch = root;
        if (old is not null)
        {
            lock (_lock)
            {
                _rootTargets.Remove(old.Id);
            }

            old.Dispose();
        }
    }

    private void StopWatch(ActiveWatch watch)
    {
        if (watch.Root is not null)
        {
            ReplaceRoot(watch, null);
        }
        else
        {
            watch.Watch?.Dispose();
            watch.Watch = null;
        }
    }

    private void NoteProblem(string id, string problem)
    {
        lock (_lock)
        {
            if (_problems.TryGetValue(id, out var previous) && previous == problem)
            {
                return;
            }

            _problems[id] = problem;
        }

        _logger.LogWarning("Persistence monitor: {Target} is not watched: {Why}. A safety rescan still covers it.", id[(id.LastIndexOf('|') + 1)..], problem);
    }

    private static string OwnerName(string owner) => owner.Length == 0 ? "the machine" : owner;

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stop.Cancel();
        _wake.Set();
        if (_thread is not null && !_thread.Join(TimeSpan.FromSeconds(30)))
        {
            _logger.LogWarning("Persistence monitor: its thread did not stop in time.");
        }

        ActiveWatch[] watches;
        lock (_lock)
        {
            watches = [.. _watches.Values];
            _watches.Clear();
            _rootTargets.Clear();
        }

        foreach (var watch in watches)
        {
            try
            {
                StopWatch(watch);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                _logger.LogDebug(ex, "Persistence monitor: a watch didn't close cleanly.");
            }
        }

        if (_thread is null || !_thread.IsAlive)
        {
            SaveIfDirty();
        }

        _stop.Dispose();
        _wake.Dispose();
    }
}
