using System.Threading.Channels;
using SapAV.Core.Alerts;
using SapAV.Core.Models;

namespace SapAV.Engine.Alerts;

/// <summary>Hands alerts to the alert sink without ever blocking the caller. Fake it in tests.</summary>
public interface IAlertDispatcher
{
    /// <summary>
    /// Queues <paramref name="alert"/> unless it is aggregated (same type + hash + path already alerted in this window),
    /// over the per-window limit, or the queue is full; those are counted for the next summary. Never blocks.
    /// </summary>
    /// <param name="health">Engine-health alerts skip the per-window limit (still one per type + path per window).</param>
    /// <returns>True if queued.</returns>
    bool Post(Alert alert, bool health = false);

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
public sealed class AlertDispatcher : IAlertDispatcher, IDisposable
{
    /// <summary>Distinct alert keys remembered per window; beyond this, new keys count as rate-limited.</summary>
    public const int MaxKeysPerWindow = 10_000;

    private readonly IAlertSink _sink;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly TimeSpan _window;
    private readonly int _maxPerWindow;
    private readonly Channel<Alert> _queue;
    private readonly Thread _writer;
    private readonly Lock _lock = new();
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    private DateTimeOffset _windowStart;
    private int _passed;
    private long _duplicates, _rateLimited, _dropped;
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
        _queue = Channel.CreateBounded<Alert>(new BoundedChannelOptions(capacity) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
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
        Pending? summary;
        bool accepted;
        lock (_lock)
        {
            summary = RollWindowLocked();
            string key = Key(alert);
            if (_seen.Contains(key))
            {
                _duplicates++;
                accepted = false;
            }
            else if ((!health && _passed >= _maxPerWindow) || _seen.Count >= MaxKeysPerWindow)
            {
                _rateLimited++;
                accepted = false;
            }
            else
            {
                _seen.Add(key);
                _passed += health ? 0 : 1;
                accepted = true;
            }

            if (!accepted)
            {
                TrackLocked(alert);
            }
        }

        if (summary is { } s)
        {
            EnqueueSummary(s);
        }

        if (!accepted)
        {
            return false;
        }

        if (_queue.Writer.TryWrite(alert))
        {
            return true;
        }

        lock (_lock)
        {
            _dropped++;
            TrackLocked(alert);
        }

        return false;
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
                _queue.Writer.WriteAsync(s.Alert).AsTask().Wait(timeout);
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

    /// <summary>A summary that couldn't be queued keeps its counts for the next one.</summary>
    private void EnqueueSummary(Pending summary)
    {
        if (_queue.Writer.TryWrite(summary.Alert))
        {
            return;
        }

        lock (_lock)
        {
            _duplicates += summary.Duplicates;
            _rateLimited += summary.RateLimited;
            _dropped += summary.Dropped;
            TrackLocked(summary.Worst);
        }
    }

    private void WriterLoop()
    {
        try
        {
            while (_queue.Reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
            {
                while (_queue.Reader.TryRead(out var alert))
                {
                    try
                    {
                        _sink.WriteAsync(alert).AsTask().GetAwaiter().GetResult();
                        Interlocked.Increment(ref _written);
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    {
                        _logger.LogWarning(ex, "Delivering alert {AlertId} failed.", alert.AlertId); // sinks shouldn't throw; never fatal
                    }
                }
            }
        }
        catch (ChannelClosedException)
        {
            // drained
        }
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
        _passed = 0;
        _seen.Clear();
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
            "queue was full. Scan results keep every file.";
        var pending = new Pending(null!, _duplicates, _rateLimited, _dropped, worst);
        _duplicates = _rateLimited = _dropped = 0;
        _worst = null;
        var now = _time.GetUtcNow();
        var verdict = worst.Verdict == Verdict.Malicious ? Verdict.Malicious : Verdict.Suspicious;
        return pending with
        {
            Alert = new Alert(Alert.ComputeAlertId(AlertType.AlertsSuppressed, now, worst.FilePath, null, worst.Trigger), now,
                AlertType.AlertsSuppressed, verdict, worst.FilePath, null, null, null, worst.TechniqueId, [], [reason], null,
                AlertAction.None, worst.Trigger, EngineInfo.Version),
        };
    }

    private void TrackLocked(Alert alert)
    {
        if (_worst is null || alert.Verdict > _worst.Verdict)
        {
            _worst = alert;
        }
    }

    private static string Key(Alert alert) =>
        string.Join('|', alert.Type.ToString(), alert.Sha256 ?? string.Empty, alert.FilePath.ToUpperInvariant());

    /// <summary>A built summary and the counts it took (restored if it can't be queued).</summary>
    private readonly record struct Pending(Alert Alert, long Duplicates, long RateLimited, long Dropped, Alert Worst);
}
