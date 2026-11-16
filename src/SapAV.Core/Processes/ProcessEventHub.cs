namespace SapAV.Core.Processes;

/// <summary>
/// The shared core of every <see cref="IProcessEventSource"/>: the process table, fan-out to bounded subscriptions, counters
/// and health. <see cref="Publish"/> is safe to call from an ETW callback: it never blocks on a consumer (full buffers drop
/// their oldest event) and takes only a short internal lock.
/// </summary>
public sealed class ProcessEventHub
{
    private readonly object _gate = new();
    private readonly ProcessTable _table;
    private ProcessEventSubscription[] _subscriptions = [];
    private long _received;
    private long _lost;              // over all sessions (reported in the status)
    private long _lostBeforeSession; // part of _lost from earlier sessions
    private long _droppedByClosedSubscriptions;
    private ProcessEventSourceHealth _health = ProcessEventSourceHealth.Stopped;
    private string? _detail = "not started";
    private string? _sessionName;
    private bool _completed;

    public ProcessEventHub(int tableCapacity = ProcessTable.DefaultCapacity)
    {
        _table = new ProcessTable(tableCapacity);
    }

    public ProcessEventSourceStatus Status
    {
        get
        {
            lock (_gate)
            {
                long dropped = _droppedByClosedSubscriptions;
                foreach (var subscription in _subscriptions)
                {
                    dropped += subscription.Dropped;
                }

                return new ProcessEventSourceStatus(_health, _detail, _received, _lost, dropped, _sessionName);
            }
        }
    }

    /// <summary>Sets the health and detail (and optionally the session name). <see cref="ProcessEventSourceHealth.Running"/>
    /// becomes <see cref="ProcessEventSourceHealth.LostEvents"/> while lost events are on record.</summary>
    public void SetHealth(ProcessEventSourceHealth health, string? detail, string? sessionName = null)
    {
        lock (_gate)
        {
            _health = health == ProcessEventSourceHealth.Running && _lost > _lostBeforeSession ? ProcessEventSourceHealth.LostEvents : health;
            _detail = detail;
            if (sessionName is not null)
            {
                _sessionName = sessionName;
            }
        }
    }

    /// <summary>Records the OS-reported lost-event total of the current session (monotonic; a smaller value is ignored).</summary>
    public void ReportLost(long totalLost)
    {
        lock (_gate)
        {
            if (totalLost < 0 || _lostBeforeSession + totalLost <= _lost)
            {
                return;
            }

            _lost = _lostBeforeSession + totalLost;
            if (_health == ProcessEventSourceHealth.Running)
            {
                _health = ProcessEventSourceHealth.LostEvents;
                _detail = "the operating system reported lost process events";
            }
        }
    }

    /// <summary>
    /// Starts a new OS session: forgets every known process (the old table may be stale) and restarts the per-session lost-event
    /// count (the status keeps the total).
    /// </summary>
    public void BeginSession()
    {
        lock (_gate)
        {
            _lostBeforeSession = _lost;
            foreach (var process in _table.Snapshot())
            {
                _table.Remove(process.Key);
            }
        }
    }

    public ProcessEventSubscription Subscribe(int capacity)
    {
        var subscription = new ProcessEventSubscription(capacity, Unsubscribe);
        lock (_gate)
        {
            if (_completed)
            {
                subscription.Complete();
                return subscription;
            }

            _subscriptions = [.. _subscriptions, subscription];
        }

        return subscription;
    }

    /// <summary>
    /// Updates the table and delivers the event to every subscriber. Returns the delivered event (a stop is completed from the
    /// matching start: image path, command line, parent, user), or null when it was not delivered (a pre-existing entry for a
    /// process that is already known, or the hub is completed).
    /// </summary>
    public ProcessEvent? Publish(ProcessEvent processEvent)
    {
        ArgumentNullException.ThrowIfNull(processEvent);
        lock (_gate)
        {
            if (_completed)
            {
                return null;
            }

            ProcessEvent delivered;
            switch (processEvent.Kind)
            {
                case ProcessEventKind.Existing:
                    if (!_table.TryAdd(processEvent))
                    {
                        return null; // already reported by a start event (the snapshot runs after the session starts)
                    }

                    delivered = processEvent;
                    break;
                case ProcessEventKind.Started:
                    // A start for a known key replaces the old entry: the start event is the authoritative record.
                    _table.Remove(processEvent.Key);
                    _table.TryAdd(processEvent);
                    delivered = processEvent;
                    break;
                default:
                    var started = _table.Remove(processEvent.Key);
                    delivered = started is null ? processEvent : CompleteStop(processEvent, started);
                    break;
            }

            _received++;
            foreach (var subscription in _subscriptions)
            {
                subscription.TryWrite(delivered);
            }

            return delivered;
        }
    }

    public IReadOnlyList<ProcessEvent> GetKnownProcesses()
    {
        lock (_gate)
        {
            return _table.Snapshot();
        }
    }

    public ProcessEvent? FindProcess(ProcessKey key)
    {
        lock (_gate)
        {
            return _table.Find(key);
        }
    }

    public ProcessEvent? FindParent(ProcessEvent child)
    {
        lock (_gate)
        {
            return _table.FindParent(child);
        }
    }

    /// <summary>Completes every subscription's reader; later publishes and subscriptions get nothing. Idempotent.</summary>
    public void Complete()
    {
        ProcessEventSubscription[] subscriptions;
        lock (_gate)
        {
            _completed = true;
            subscriptions = _subscriptions;
        }

        foreach (var subscription in subscriptions)
        {
            subscription.Complete();
        }
    }

    private void Unsubscribe(ProcessEventSubscription subscription)
    {
        lock (_gate)
        {
            if (Array.IndexOf(_subscriptions, subscription) < 0)
            {
                return;
            }

            _droppedByClosedSubscriptions += subscription.Dropped;
            _subscriptions = [.. _subscriptions.Where(s => !ReferenceEquals(s, subscription))];
        }
    }

    /// <summary>A stop event only carries what the OS logs at exit; the rest comes from the matching start (same key).</summary>
    private static ProcessEvent CompleteStop(ProcessEvent stop, ProcessEvent started) => stop with
    {
        ParentProcessId = stop.ParentProcessId ?? started.ParentProcessId,
        ImagePath = IsFullPath(stop.ImagePath) ? stop.ImagePath : started.ImagePath ?? stop.ImagePath,
        CommandLine = stop.CommandLine ?? started.CommandLine,
        CommandLineTruncated = stop.CommandLine is null ? started.CommandLineTruncated : stop.CommandLineTruncated,
        SessionId = stop.SessionId ?? started.SessionId,
        UserSid = stop.UserSid ?? started.UserSid,
        IntegrityLevel = stop.IntegrityLevel == ProcessIntegrityLevel.Unknown ? started.IntegrityLevel : stop.IntegrityLevel,
    };

    private static bool IsFullPath(string? path) => path is not null && Path.IsPathFullyQualified(path);
}
