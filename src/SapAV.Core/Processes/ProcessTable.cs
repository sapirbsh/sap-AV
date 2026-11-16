namespace SapAV.Core.Processes;

/// <summary>
/// The processes believed to be running, keyed by <see cref="ProcessKey"/> (PID + start time) so a reused PID never matches the
/// old process. Bounded: when full, entries whose process is gone are pruned first (stop events can be lost or forged-away,
/// so entries can go stale), then the oldest entry is evicted. Entries without a start time are never stored (they can't be
/// told apart from a reused PID). Not thread-safe; <see cref="ProcessEventHub"/> serializes access.
/// </summary>
public sealed class ProcessTable
{
    /// <summary>Default capacity: far above the few hundred processes a PC runs, small enough to bound memory.</summary>
    public const int DefaultCapacity = 8192;

    private readonly Dictionary<ProcessKey, ProcessEvent> _byKey = [];
    private readonly Dictionary<int, List<ProcessKey>> _byPid = []; // usually one entry per PID
    private readonly Queue<ProcessKey> _order = new();
    private readonly Func<ProcessEvent, bool>? _isGone;
    private int _addsSincePrune = int.MaxValue;

    /// <param name="capacity">Most entries kept.</param>
    /// <param name="isGone">Optional: true when the process of an entry no longer runs (checked by PID and start time). Used to
    /// prune a full table before anything live is evicted, at most once per quarter-capacity of additions.</param>
    public ProcessTable(int capacity = DefaultCapacity, Func<ProcessEvent, bool>? isGone = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        Capacity = capacity;
        _isGone = isGone;
    }

    public int Capacity { get; }

    public int Count => _byKey.Count;

    /// <summary>Live-looking entries removed because the table was full and nothing could be pruned.</summary>
    public long Evicted { get; private set; }

    /// <summary>Entries removed because their process was found gone (pruning and reconciliation).</summary>
    public long Pruned { get; private set; }

    /// <summary>
    /// Adds a running process. False (nothing changes) if this exact process instance is already known, or if it has no start
    /// time (it is still delivered to subscribers by the hub, just not remembered).
    /// </summary>
    public bool TryAdd(ProcessEvent process)
    {
        ArgumentNullException.ThrowIfNull(process);
        if (process.StartTime is null)
        {
            return false;
        }

        var key = process.Key;
        if (_byKey.ContainsKey(key))
        {
            return false;
        }

        if (_byKey.Count >= Capacity && _isGone is not null && _addsSincePrune >= Math.Max(1, Capacity / 4))
        {
            _addsSincePrune = 0;
            RemoveWhere(_isGone);
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
        if (_addsSincePrune != int.MaxValue)
        {
            _addsSincePrune++;
        }

        if (_order.Count > Capacity * 2)
        {
            Compact();
        }

        return true;
    }

    public bool Contains(ProcessKey key) => _byKey.ContainsKey(key);

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

    /// <summary>Removes every entry <paramref name="isGone"/> says no longer runs; returns how many. A throwing check keeps the entry.</summary>
    public int RemoveWhere(Func<ProcessEvent, bool> isGone)
    {
        ArgumentNullException.ThrowIfNull(isGone);
        var gone = new List<ProcessKey>();
        foreach (var (key, process) in _byKey)
        {
            bool remove;
            try
            {
                remove = isGone(process);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                remove = false;
            }

            if (remove)
            {
                gone.Add(key);
            }
        }

        foreach (var key in gone)
        {
            Remove(key);
        }

        Pruned += gone.Count;
        return gone.Count;
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
