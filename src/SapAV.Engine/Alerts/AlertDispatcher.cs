using System.Security.Principal;
using System.Threading.Channels;
using SapAV.Core.Alerts;
using SapAV.Core.Models;

namespace SapAV.Engine.Alerts;

/// <summary>
/// Whose budget an alert counts against (section B M2). The engine's own alerts (real-time, its own scans, health) use one
/// budget per trigger; alerts from a job a user asked for over the pipe use that user's budget, so a user's own scans can
/// never use up the engine's budget, its alert keys or its share of the queue.
/// </summary>
/// <param name="Key">Identifies the budget (<c>engine:RealTime</c>, <c>user:S-1-5-21-…</c>).</param>
/// <param name="Requested">A user-requested budget: capped per user, and limited to half the alert queue together.</param>
public sealed record AlertBudget(string Key, bool Requested)
{
    public static AlertBudget ForEngine(ScanTrigger trigger) => new("engine:" + trigger, false);

    public static AlertBudget ForRequester(SecurityIdentifier user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return new("user:" + user.Value, true);
    }
}

/// <summary>Hands alerts to the alert sink without ever blocking the caller. Fake it in tests.</summary>
public interface IAlertDispatcher
{
    /// <summary>
    /// Queues <paramref name="alert"/> unless it is aggregated (same type + hash + path already alerted in this window),
    /// over the per-window limit, or the queue is full; those are counted for the next summary. Never blocks. Counts
    /// against the engine's budget for the alert's trigger.
    /// </summary>
    /// <param name="health">Engine-health alerts skip the per-window limit, as Malicious alerts do (still one per type + path per window).</param>
    /// <returns>True if queued.</returns>
    bool Post(Alert alert, bool health = false);

    /// <summary>Like <see cref="Post(Alert, bool)"/>, counted against <paramref name="budget"/> (section B M2).</summary>
    bool Post(Alert alert, AlertBudget budget, bool health = false) => Post(alert, health);

    /// <summary>Queues one <see cref="AlertType.AlertsSuppressed"/> summary if anything was suppressed since the last one.</summary>
    void FlushSummary();
}

/// <summary>
/// Review B1 M4: alert flooding and blocking writes. Alerts go through a <b>bounded channel with one writer thread</b>, so a
/// hung Event Log RPC (or any slow sink) blocks only that thread, never a scan thread; when the queue is full new alerts
/// are dropped and counted. Within each window (<c>ScanJobs:AlertWindow</c>) only the first alert per type + SHA-256 + path
/// is written, and at most a fixed number in total; everything held back is reported in one summary event
/// (<see cref="AlertType.AlertsSuppressed"/>, event 9001) when the window rolls over or a job ends. Scan results are
/// never affected: only the Event Log copy is aggregated.
/// </summary>
/// <remarks>
/// <para><b>Budgets</b> (section B M2, <see cref="AlertBudget"/>). Every budget has its own per-window total (for
/// non-Malicious alerts) and its own set of alert keys. The engine's budgets keep <see cref="MaxKeysPerWindow"/> keys each;
/// a user's budget keeps <see cref="MaxKeysPerRequesterWindow"/>, and at most <see cref="MaxRequesterBudgets"/> users get
/// their own budget per window (the rest share one). User-requested alerts together may fill at most half of the queue, so
/// the other half is always free for the engine's own (real-time) alerts: a user flood can push only that user's alerts
/// into the summary, never an engine or real-time Malicious alert.</para>
/// <para>The summary lists up to <see cref="MaxSummaryHashes"/> distinct SHA-256 values of what was held back.</para>
/// </remarks>
public sealed class AlertDispatcher : IAlertDispatcher, IDisposable
{
    /// <summary>Distinct alert keys remembered per window in one engine budget; beyond this, new keys count as rate-limited.</summary>
    public const int MaxKeysPerWindow = 10_000;

    /// <summary>Distinct alert keys per window in one user's budget.</summary>
    public const int MaxKeysPerRequesterWindow = 1_000;

    /// <summary>Users with their own budget per window; any further user shares one overflow budget.</summary>
    public const int MaxRequesterBudgets = 64;

    /// <summary>Distinct suppressed SHA-256 values named in a summary.</summary>
    public const int MaxSummaryHashes = 12;

    private const string RequesterOverflowKey = "user:*";

    private readonly IAlertSink _sink;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly TimeSpan _window;
    private readonly int _maxPerWindow;
    private readonly int _requestedQueueShare;
    private readonly Channel<Queued> _queue;
    private readonly Thread _writer;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, BudgetState> _budgets = new(StringComparer.Ordinal);
    private readonly HashSet<string> _suppressedHashes = new(StringComparer.Ordinal);

    private DateTimeOffset _windowStart;
    private int _requestedInQueue;
    private long _duplicates, _rateLimited, _dropped, _malicious, _requested;
    private bool _moreHashes;
    private Alert? _worst;

    public AlertDispatcher(IAlertSink sink, TimeProvider time, ILogger<AlertDispatcher> logger, TimeSpan window, int maxPerWindow, int capacity)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        ArgumentOutOfRangeException.ThrowIfLessThan(window, TimeSpan.FromMilliseconds(1));
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPerWindow, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _window = window;
        _maxPerWindow = maxPerWindow;
        _requestedQueueShare = capacity / 2;
        _queue = Channel.CreateBounded<Queued>(new BoundedChannelOptions(capacity) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
        _windowStart = time.GetUtcNow();

        // Normal priority on purpose (not background mode): alerts must not starve behind scanning.
        _writer = new Thread(WriterLoop) { IsBackground = true, Name = "sap-AV alert writer" };
        _writer.Start();
    }

    /// <summary>Alerts written to the sink so far (tests, status).</summary>
    public long Written => Interlocked.Read(ref _written);

    private long _written;

    public bool Post(Alert alert, bool health = false)
    {
        ArgumentNullException.ThrowIfNull(alert);
        return Post(alert, AlertBudget.ForEngine(alert.Trigger), health);
    }

    public bool Post(Alert alert, AlertBudget budget, bool health = false)
    {
        ArgumentNullException.ThrowIfNull(alert);
        ArgumentNullException.ThrowIfNull(budget);

        // Review M3: a flood of Suspicious alerts must not crowd out a Malicious one, so Malicious and health alerts skip the
        // total cap (they still get per-key aggregation and the key limit).
        bool uncapped = health || alert.Verdict == Verdict.Malicious;
        Pending? summary;
        bool accepted;
        lock (_lock)
        {
            summary = RollWindowLocked();
            var state = BudgetLocked(budget);
            string key = Key(alert);
            if (state.Seen.Contains(key))
            {
                _duplicates++;
                accepted = false;
            }
            else if ((!uncapped && state.Passed >= _maxPerWindow) || state.Seen.Count >= state.MaxKeys)
            {
                _rateLimited++;
                accepted = false;
            }
            else
            {
                state.Seen.Add(key);
                state.Passed += uncapped ? 0 : 1;
                accepted = true;
            }

            if (!accepted)
            {
                SuppressedLocked(alert, budget);
            }
        }

        if (summary is { } s)
        {
            EnqueueSummary(s);
        }

        return accepted && Enqueue(alert, budget);
    }

    public void FlushSummary()
    {
        Pending? summary;
        lock (_lock)
        {
            summary = TakeSummaryLocked();
        }

        if (summary is { } s)
        {
            EnqueueSummary(s);
        }
    }

    /// <summary>
    /// Shutdown: queues the last summary (waiting up to <paramref name="timeout"/> for room), stops accepting alerts and lets
    /// the writer drain. A hung sink is abandoned after the timeout. True if the writer finished.
    /// </summary>
    public bool Drain(TimeSpan timeout)
    {
        Pending? summary;
        lock (_lock)
        {
            summary = TakeSummaryLocked();
        }

        if (summary is { } s)
        {
            try
            {
                _queue.Writer.WriteAsync(new Queued(s.Alert, false)).AsTask().Wait(timeout);
            }
            catch (AggregateException)
            {
                // already completed
            }
        }

        _queue.Writer.TryComplete();
        return _writer.Join(timeout);
    }

    public void Dispose() => Drain(TimeSpan.FromSeconds(5));

    /// <summary>
    /// Queues an accepted alert. User-requested alerts may hold at most half of the queue together (the rest is the
    /// engine's reserve); a full queue or share drops the alert into the summary.
    /// </summary>
    private bool Enqueue(Alert alert, AlertBudget budget)
    {
        if (budget.Requested && Interlocked.Increment(ref _requestedInQueue) > _requestedQueueShare)
        {
            Interlocked.Decrement(ref _requestedInQueue);
            DroppedLocked(alert, budget);
            return false;
        }

        if (_queue.Writer.TryWrite(new Queued(alert, budget.Requested)))
        {
            return true;
        }

        if (budget.Requested)
        {
            Interlocked.Decrement(ref _requestedInQueue);
        }

        DroppedLocked(alert, budget);
        return false;
    }

    private void DroppedLocked(Alert alert, AlertBudget budget)
    {
        lock (_lock)
        {
            _dropped++;
            SuppressedLocked(alert, budget);
        }
    }

    /// <summary>A summary that couldn't be queued keeps its counts for the next one.</summary>
    private void EnqueueSummary(Pending summary)
    {
        if (_queue.Writer.TryWrite(new Queued(summary.Alert, false)))
        {
            return;
        }

        lock (_lock)
        {
            _duplicates += summary.Duplicates;
            _rateLimited += summary.RateLimited;
            _dropped += summary.Dropped;
            _malicious += summary.Malicious;
            _requested += summary.Requested;
            TrackLocked(summary.Worst);
        }
    }

    private void WriterLoop()
    {
        try
        {
            while (_queue.Reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
            {
                while (_queue.Reader.TryRead(out var queued))
                {
                    if (queued.Requested)
                    {
                        Interlocked.Decrement(ref _requestedInQueue);
                    }

                    try
                    {
                        _sink.WriteAsync(queued.Alert).AsTask().GetAwaiter().GetResult();
                        Interlocked.Increment(ref _written);
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        _logger.LogWarning(ex, "Delivering alert {AlertId} failed.", queued.Alert.AlertId); // sinks shouldn't throw; never fatal
                    }
                }
            }
        }
        catch (ChannelClosedException)
        {
            // drained
        }
    }

    /// <summary>The window state of <paramref name="budget"/>; users beyond <see cref="MaxRequesterBudgets"/> share one.</summary>
    private BudgetState BudgetLocked(AlertBudget budget)
    {
        if (_budgets.TryGetValue(budget.Key, out var state))
        {
            return state;
        }

        string key = budget.Key;
        if (budget.Requested && _budgets.Keys.Count(k => k.StartsWith("user:", StringComparison.Ordinal)) >= MaxRequesterBudgets)
        {
            key = RequesterOverflowKey;
            if (_budgets.TryGetValue(key, out state))
            {
                return state;
            }
        }

        state = new BudgetState(budget.Requested ? MaxKeysPerRequesterWindow : MaxKeysPerWindow);
        _budgets[key] = state;
        return state;
    }

    private Pending? RollWindowLocked()
    {
        var now = _time.GetUtcNow();
        if (now - _windowStart < _window)
        {
            return null;
        }

        var summary = TakeSummaryLocked();
        _windowStart = now;
        _budgets.Clear();
        return summary;
    }

    private Pending? TakeSummaryLocked()
    {
        long total = _duplicates + _rateLimited + _dropped;
        if (total == 0 || _worst is null)
        {
            return null;
        }

        var worst = _worst;
        string reason = $"{total} alert(s) were not written to the Event Log: {_duplicates} repeat(s) of an alert already raised for the " +
            $"same file and SHA-256, {_rateLimited} over the limit of {_maxPerWindow} alerts per {_window}, {_dropped} because the alert " +
            $"queue was full; {_malicious} of them Malicious, {_requested} from scans a user requested. Scan results keep every file.";
        var reasons = new List<string> { reason };
        if (_suppressedHashes.Count > 0)
        {
            reasons.Add($"SHA-256 of held-back alerts ({_suppressedHashes.Count} distinct" +
                (_moreHashes ? ", more not listed" : string.Empty) + "): " + string.Join(", ", _suppressedHashes.Order(StringComparer.Ordinal)));
        }

        var pending = new Pending(null!, _duplicates, _rateLimited, _dropped, _malicious, _requested, worst);
        _duplicates = _rateLimited = _dropped = _malicious = _requested = 0;
        _moreHashes = false;
        _suppressedHashes.Clear();
        _worst = null;
        var now = _time.GetUtcNow();
        var verdict = worst.Verdict == Verdict.Malicious ? Verdict.Malicious : Verdict.Suspicious;
        return pending with
        {
            Alert = new Alert(Alert.ComputeAlertId(AlertType.AlertsSuppressed, now, worst.FilePath, null, worst.Trigger), now,
                AlertType.AlertsSuppressed, verdict, worst.FilePath, null, null, null, worst.TechniqueId, [], reasons, null,
                AlertAction.None, worst.Trigger, EngineInfo.Version),
        };
    }

    private void SuppressedLocked(Alert alert, AlertBudget budget)
    {
        if (alert.Verdict == Verdict.Malicious && alert.Type != AlertType.AlertsSuppressed)
        {
            _malicious++;
        }

        if (budget.Requested)
        {
            _requested++;
        }

        if (alert.Sha256 is { } sha && !_suppressedHashes.Contains(sha))
        {
            if (_suppressedHashes.Count < MaxSummaryHashes)
            {
                _suppressedHashes.Add(sha);
            }
            else
            {
                _moreHashes = true;
            }
        }

        TrackLocked(alert);
    }

    private void TrackLocked(Alert alert)
    {
        if (_worst is null || alert.Verdict > _worst.Verdict)
        {
            _worst = alert;
        }
    }

    /// <remarks>C3: two autostart entries running the same file are two incidents, so the entry is part of the key.</remarks>
    private static string Key(Alert alert) =>
        string.Join('|', alert.Type.ToString(), alert.Sha256 ?? string.Empty, alert.FilePath.ToUpperInvariant(), alert.Autostart?.Key ?? string.Empty);

    private sealed class BudgetState(int maxKeys)
    {
        public int MaxKeys { get; } = maxKeys;

        public int Passed { get; set; }

        public HashSet<string> Seen { get; } = new(StringComparer.Ordinal);
    }

    private readonly record struct Queued(Alert Alert, bool Requested);

    /// <summary>A built summary and the counts it took (restored if it can't be queued).</summary>
    private readonly record struct Pending(Alert Alert, long Duplicates, long RateLimited, long Dropped, long Malicious, long Requested, Alert Worst);
}
