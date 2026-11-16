namespace SapAV.Core.Processes;

/// <summary>
/// The processes believed to be running, keyed by <see cref="ProcessKey"/> (PID + start time) so a reused PID never matches the
/// old process. Bounded: when full, the oldest entry is evicted (stop events can be lost, so entries can go stale). Not
/// thread-safe; <see cref="ProcessEventHub"/> serializes access.
/// </summary>
public sealed class ProcessTable
{
    /// <summary>Default capacity: far above the few hundred processes a PC runs, small enough to bound memory.</summary>
    public const int DefaultCapacity = 32768;

    private readonly Dictionary<ProcessKey, ProcessEvent> _byKey = [];
    private readonly Dictionary<int, List<ProcessKey>> _byPid = []; // usually one entry per PID
    private readonly Queue<ProcessKey> _order = new();

    public ProcessTable(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        Capacity = capacity;
    }

    public int Capacity { get; }

    public int Count => _byKey.Count;

    /// <summary>Entries removed because the table was full.</summary>
    public long Evicted { get; private set; }

    /// <summary>Adds a running process. False (nothing changes) if this exact process instance is already known.</summary>
    public bool TryAdd(ProcessEvent process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var key = process.Key;
        if (_byKey.ContainsKey(key))
        {
            return false;
        }

        while (_byKey.Count >= Capacity && _order.TryDequeue(out var oldest))
        {
            if (Remove(oldest) is not null)
            {
                Evicted++;
            }
        }

        _byKey[key] = process;
        _order.Enqueue(key);
        if (!_byPid.TryGetValue(key.ProcessId, out var keys))
        {
            _byPid[key.ProcessId] = keys = new List<ProcessKey>(1);
        }

        keys.Add(key);

        if (_order.Count > Capacity * 2)
        {
            Compact();
        }

        return true;
    }

    /// <summary>Removes and returns the process with this identity, or null if it isn't known.</summary>
    public ProcessEvent? Remove(ProcessKey key)
    {
        if (!_byKey.Remove(key, out var removed))
        {
            return null;
        }

        if (_byPid.TryGetValue(key.ProcessId, out var keys))
        {
            keys.Remove(key);
            if (keys.Count == 0)
            {
                _byPid.Remove(key.ProcessId);
            }
        }

        return removed;
    }

    public ProcessEvent? Find(ProcessKey key) => _byKey.GetValueOrDefault(key);

    /// <summary>The most recently started known process with this PID, or null.</summary>
    public ProcessEvent? FindLatestByPid(int processId)
    {
        if (!_byPid.TryGetValue(processId, out var keys) || keys.Count == 0)
        {
            return null;
        }

        var latest = keys[0];
        foreach (var key in keys)
        {
            if (key.StartTime > latest.StartTime)
            {
                latest = key;
            }
        }

        return _byKey[latest];
    }

    /// <summary>
    /// The known running parent of <paramref name="child"/>: the latest process with the child's parent PID that started no
    /// later than the child. Null when unknown, when the parent exited, or when the PID now belongs to a younger process
    /// (PID reuse: a process can't be the parent of one that started before it).
    /// </summary>
    public ProcessEvent? FindParent(ProcessEvent child)
    {
        ArgumentNullException.ThrowIfNull(child);
        if (child.ParentProcessId is not { } parentPid || parentPid == child.ProcessId)
        {
            return null;
        }

        var parent = FindLatestByPid(parentPid);
        if (parent is null)
        {
            return null;
        }

        if (parent.StartTime is { } parentStart && child.StartTime is { } childStart && parentStart > childStart)
        {
            return null;
        }

        return parent;
    }

    public IReadOnlyList<ProcessEvent> Snapshot() => [.. _byKey.Values];

    private void Compact()
    {
        // Drop keys of processes that already stopped; keep the insertion order of the rest.
        var live = _order.Where(_byKey.ContainsKey).Distinct().ToArray();
        _order.Clear();
        foreach (var key in live)
        {
            _order.Enqueue(key);
        }
    }
}
