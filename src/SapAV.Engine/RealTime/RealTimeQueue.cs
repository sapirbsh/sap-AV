namespace SapAV.Engine.RealTime;

/// <summary>Where a waiting file is.</summary>
internal enum PendingState
{
    /// <summary>Waiting for quiet (debounce) or for a writer to close it (retry).</summary>
    Settling,

    /// <summary>Due; being ranked or waiting for a scan thread.</summary>
    Ready,

    /// <summary>A scan thread has it.</summary>
    InProgress,
}

/// <summary>One file waiting in <see cref="RealTimeQueue"/> (one per watched root + relative name).</summary>
internal sealed class PendingFile(WatchedRoot root, string relative, string key, DateTimeOffset firstSeen)
{
    public WatchedRoot Root { get; } = root;

    /// <summary>Relative to <see cref="Root"/>, exact.</summary>
    public string Relative { get; } = relative;

    internal string Key { get; } = key;

    public DateTimeOffset FirstSeen { get; internal set; } = firstSeen;

    public DateTimeOffset Due { get; internal set; }

    public PendingState State { get; internal set; }

    /// <summary>A Mark-of-the-Web stream event was seen for it.</summary>
    public bool MotwHint { get; internal set; }

    /// <summary>Lower runs first (Mark-of-the-Web, then executables, archives, Office files, the rest).</summary>
    public int Rank { get; internal set; }

    /// <summary>When the first "a writer has it open" was seen; null while none was.</summary>
    public DateTimeOffset? LockWaitStart { get; set; }

    public int LockAttempts { get; set; }

    /// <summary>An event arrived while it was being scanned: it is looked at again afterwards.</summary>
    internal bool Again { get; set; }

    internal long Sequence { get; set; }

    internal bool Removed { get; set; }
}

/// <summary>Result of <see cref="RealTimeQueue.Offer"/>.</summary>
internal enum OfferResult
{
    /// <summary>A new waiting file.</summary>
    Queued,

    /// <summary>Merged into the entry already waiting (or being scanned) for that file.</summary>
    Coalesced,

    /// <summary>The queue is at its cap (files or path characters): the caller switches the folder to "rescan later".</summary>
    Dropped,
}

/// <summary>
/// The real-time queue (D1): <b>bounded</b> (at most <see cref="RealTimeOptions.MaxPendingFiles"/> files and
/// <see cref="RealTimeOptions.MaxPendingPathChars"/> path characters, so an event storm can't grow memory), <b>coalescing</b>
/// (one entry per file however many events arrive; an event during the scan marks it to be looked at once more afterwards),
/// <b>debounced</b> (a file is due <see cref="RealTimeOptions.SettleDelay"/> after its last event, at most
/// <see cref="RealTimeOptions.MaxSettleDelay"/> after its first) and <b>prioritised</b> (due files are ranked by the caller:
/// Mark-of-the-Web first; FIFO within a rank). Pure state, thread-safe, driven by the caller's clock: no threads or I/O here.
/// Every waiting file has at most one entry in the due-time heap, so repeated events can't grow it either.
/// </summary>
internal sealed class RealTimeQueue(RealTimeOptions options)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, PendingFile> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly PriorityQueue<(PendingFile File, long Sequence), (long Due, long Sequence)> _settling = new();
    private readonly PriorityQueue<PendingFile, (int Rank, long Sequence)> _ready = new();
    private long _sequence;
    private long _chars;

    /// <summary>Files waiting in any state (scanned ones included until they complete).</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _items.Count;
            }
        }
    }

    public int ReadyCount
    {
        get
        {
            lock (_gate)
            {
                return _ready.Count;
            }
        }
    }

    /// <summary>Path characters held (for tests and the status).</summary>
    public long PathChars
    {
        get
        {
            lock (_gate)
            {
                return _chars;
            }
        }
    }

    /// <summary>At or below a quarter of the file cap: rescans may add files again.</summary>
    public bool HasRoom
    {
        get
        {
            lock (_gate)
            {
                return _items.Count <= options.MaxPendingFiles / 4;
            }
        }
    }

    public OfferResult Offer(WatchedRoot root, string relative, bool motwHint, DateTimeOffset now)
    {
        string key = root.Id.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + relative;
        lock (_gate)
        {
            if (_items.TryGetValue(key, out var file))
            {
                file.MotwHint |= motwHint;
                switch (file.State)
                {
                    case PendingState.Settling when file.LockWaitStart is null:
                        // Debounce: later, never past the cap; the heap entry moves when it surfaces (TakeDue).
                        var due = Min(now + options.SettleDelay, file.FirstSeen + options.MaxSettleDelay);
                        file.Due = due > file.Due ? due : file.Due;
                        break;
                    case PendingState.InProgress:
                        file.Again = true;
                        break;
                }

                return OfferResult.Coalesced;
            }

            if (_items.Count >= options.MaxPendingFiles || _chars + key.Length > options.MaxPendingPathChars)
            {
                return OfferResult.Dropped;
            }

            file = new PendingFile(root, relative, key, now) { MotwHint = motwHint, Due = now + options.SettleDelay };
            _items.Add(key, file);
            _chars += key.Length;
            PushSettlingLocked(file);
            return OfferResult.Queued;
        }
    }

    /// <summary>
    /// Takes the next file that is due by <paramref name="now"/> out of the settling set (state Ready, not yet ranked). The
    /// caller ranks it and calls <see cref="MakeReady"/>.
    /// </summary>
    public bool TryTakeDue(DateTimeOffset now, out PendingFile file)
    {
        lock (_gate)
        {
            while (_settling.TryPeek(out var entry, out var priority))
            {
                if (priority.Due > now.UtcTicks)
                {
                    break;
                }

                _settling.Dequeue();
                var candidate = entry.File;
                if (candidate.Removed || candidate.State != PendingState.Settling || candidate.Sequence != entry.Sequence)
                {
                    continue; // stale
                }

                if (candidate.Due > now)
                {
                    _settling.Enqueue(entry, (candidate.Due.UtcTicks, entry.Sequence)); // debounced since: its one entry moves
                    continue;
                }

                candidate.State = PendingState.Ready;
                file = candidate;
                return true;
            }
        }

        file = null!;
        return false;
    }

    /// <summary>Ranks a due file and makes it available to the scan threads.</summary>
    public void MakeReady(PendingFile file, int rank)
    {
        lock (_gate)
        {
            if (file.Removed)
            {
                return;
            }

            file.Rank = rank;
            file.Sequence = ++_sequence;
            _ready.Enqueue(file, (rank, file.Sequence));
        }
    }

    /// <summary>The best ready file (lowest rank, then first ranked), now InProgress.</summary>
    public bool TryTakeReady(out PendingFile file)
    {
        lock (_gate)
        {
            while (_ready.TryDequeue(out var candidate, out _))
            {
                if (candidate.Removed)
                {
                    continue;
                }

                candidate.State = PendingState.InProgress;
                file = candidate;
                return true;
            }
        }

        file = null!;
        return false;
    }

    /// <summary>A scan thread hands the file back to wait <paramref name="delay"/> (a writer still has it).</summary>
    public void Retry(PendingFile file, TimeSpan delay, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (file.Removed)
            {
                return;
            }

            file.State = PendingState.Settling;
            file.Again = false;
            file.Due = now + delay;
            PushSettlingLocked(file);
        }
    }

    /// <summary>Done with the file. If an event arrived meanwhile, it waits again (from now); otherwise it leaves the queue.</summary>
    /// <returns>True if it is waiting again.</returns>
    public bool Complete(PendingFile file, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (file.Removed)
            {
                return false;
            }

            if (file.Again)
            {
                file.Again = false;
                file.State = PendingState.Settling;
                file.FirstSeen = now;
                file.LockWaitStart = null;
                file.LockAttempts = 0;
                file.Due = now + options.SettleDelay;
                PushSettlingLocked(file);
                return true;
            }

            RemoveLocked(file);
            return false;
        }
    }

    /// <summary>Forgets every file of a root that stopped being watched (files in progress finish and are then dropped).</summary>
    public int RemoveRoot(WatchedRoot root)
    {
        lock (_gate)
        {
            var gone = _items.Values.Where(f => ReferenceEquals(f.Root, root)).ToArray();
            foreach (var file in gone)
            {
                RemoveLocked(file);
            }

            return gone.Length;
        }
    }

    /// <summary>When the earliest settling file may be due (a wake-up hint; null when none waits).</summary>
    public DateTimeOffset? NextDue()
    {
        lock (_gate)
        {
            return _settling.TryPeek(out _, out var priority) ? new DateTimeOffset(priority.Due, TimeSpan.Zero) : null;
        }
    }

    private void PushSettlingLocked(PendingFile file)
    {
        file.Sequence = ++_sequence;
        _settling.Enqueue((file, file.Sequence), (file.Due.UtcTicks, file.Sequence));
    }

    private void RemoveLocked(PendingFile file)
    {
        file.Removed = true;
        if (_items.Remove(file.Key))
        {
            _chars -= file.Key.Length;
        }
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;
}
