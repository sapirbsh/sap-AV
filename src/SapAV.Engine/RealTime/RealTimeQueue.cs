namespace SapAV.Engine.RealTime;

/// <summary>Where a waiting file is.</summary>
internal enum PendingState
{
    /// <summary>Waiting for quiet (debounce), its minimum re-scan interval, or a writer to close it (retry).</summary>
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

    /// <summary>Review D1 H2: not looked at before this (the file's minimum re-scan interval).</summary>
    internal DateTimeOffset NotBefore { get; set; }

    public PendingState State { get; internal set; }

    /// <summary>A Mark-of-the-Web stream event was seen for it.</summary>
    public bool MotwHint { get; internal set; }

    /// <summary>Lower runs first within its root (Mark-of-the-Web, then executables, archives, Office files, the rest).</summary>
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

    /// <summary>The queue, or this folder's share of it, is at its cap: the caller switches that folder to "rescan later".</summary>
    Dropped,

    /// <summary>The name is longer than <see cref="RealTimeOptions.MaxQueuedNameLength"/>: the caller rescans the folder later instead.</summary>
    TooLong,
}

/// <summary>
/// The real-time queue (D1): <b>bounded</b> globally (<see cref="RealTimeOptions.MaxPendingFiles"/> files,
/// <see cref="RealTimeOptions.MaxPendingPathChars"/> path characters) and <b>per watched folder</b> (review D1 H2: an eighth of
/// each by default, so one folder's storm, e.g. a user's churning TEMP, puts only that folder into "rescan later") and <b>per
/// owner</b> (section D review H5: all of one user's folders together, or all machine-wide folders together, at most a quarter,
/// and the last quarter of the queue only for owners below half their share, so many flooded folders of one user can't
/// crowd out another user's file);
/// <b>coalescing</b> (one entry per file however many events arrive; an event during the scan marks it to be looked at once
/// more afterwards); <b>debounced</b> (due <see cref="RealTimeOptions.SettleDelay"/> after its last event, at most
/// <see cref="RealTimeOptions.MaxSettleDelay"/> after its first) with a <b>minimum re-scan interval</b> per file (a file
/// rewritten every half second is scanned at most every <see cref="RealTimeOptions.MinRescanInterval"/>); and <b>fair</b>:
/// due files are ranked within their folder (Mark-of-the-Web first, FIFO within a rank) and the folders take turns, so no
/// folder's files, however highly ranked, can starve another's. Pure state, thread-safe, driven by the caller's clock: no
/// threads or I/O here. Every waiting file has at most one entry in the due-time heap, so repeated events can't grow it.
/// </summary>
internal sealed class RealTimeQueue(RealTimeOptions options)
{
    /// <summary>Most recently scanned files remembered for the minimum re-scan interval.</summary>
    internal const int MaxRecentScans = 8192;

    private readonly object _gate = new();
    private readonly Dictionary<string, PendingFile> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly PriorityQueue<(PendingFile File, long Sequence), (long Due, long Sequence)> _settling = new();
    private readonly Dictionary<int, PriorityQueue<PendingFile, (int Rank, long Sequence)>> _ready = [];
    private readonly Queue<int> _turns = new();
    private readonly Dictionary<int, (int Files, long Chars)> _perRoot = [];
    private readonly Dictionary<string, (int Files, long Chars)> _perOwner = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> _recentOrder = new();
    private long _sequence;
    private long _chars;
    private int _readyCount;

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
                return _readyCount;
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

    /// <summary>Files waiting for one root.</summary>
    public int CountFor(WatchedRoot root)
    {
        lock (_gate)
        {
            return _perRoot.TryGetValue(root.Id, out var used) ? used.Files : 0;
        }
    }

    /// <summary>Review D1 M1: both caps at or below a quarter: rescans may add files again.</summary>
    public bool HasRoom
    {
        get
        {
            lock (_gate)
            {
                return _items.Count <= options.MaxPendingFiles / 4 && _chars <= options.MaxPendingPathChars / 4;
            }
        }
    }

    /// <summary>Room for one more file of <paramref name="root"/> with a name of <paramref name="length"/> characters (global and the root's share).</summary>
    public bool HasRoomFor(WatchedRoot root, int length)
    {
        lock (_gate)
        {
            return FitsLocked(root, length + KeyOverhead);
        }
    }

    private const int KeyOverhead = 12; // the root id and the separator in the key

    public OfferResult Offer(WatchedRoot root, string relative, bool motwHint, DateTimeOffset now, bool allowLong = false)
    {
        if (!allowLong && relative.Length > options.MaxQueuedNameLength)
        {
            return OfferResult.TooLong;
        }

        string key = root.Id.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + relative;
        lock (_gate)
        {
            if (_items.TryGetValue(key, out var file))
            {
                file.MotwHint |= motwHint;
                switch (file.State)
                {
                    case PendingState.Settling when file.LockWaitStart is null:
                        // Debounce: later, never past the cap (but never before the minimum re-scan interval); the heap entry
                        // moves when it surfaces (TakeDue).
                        var due = Max(Min(now + options.SettleDelay, file.FirstSeen + options.MaxSettleDelay), file.NotBefore);
                        file.Due = due > file.Due ? due : file.Due;
                        break;
                    case PendingState.InProgress:
                        file.Again = true;
                        break;
                }

                return OfferResult.Coalesced;
            }

            if (!FitsLocked(root, key.Length))
            {
                return OfferResult.Dropped;
            }

            var notBefore = _recent.TryGetValue(key, out var scanned) ? scanned + options.MinRescanInterval : DateTimeOffset.MinValue;
            file = new PendingFile(root, relative, key, now) { MotwHint = motwHint, NotBefore = notBefore, Due = Max(now + options.SettleDelay, notBefore) };
            _items.Add(key, file);
            Charge(root, 1, key.Length);
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

    /// <summary>Ranks a due file and makes it available to the scan threads (in its root's turn).</summary>
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
            if (!_ready.TryGetValue(file.Root.Id, out var heap))
            {
                _ready[file.Root.Id] = heap = new();
                _turns.Enqueue(file.Root.Id);
            }

            heap.Enqueue(file, (rank, file.Sequence));
            _readyCount++;
        }
    }

    /// <summary>The next root's best ready file (lowest rank, then first ranked), now InProgress. Roots take turns.</summary>
    public bool TryTakeReady(out PendingFile file)
    {
        lock (_gate)
        {
            while (_turns.TryDequeue(out int rootId))
            {
                var heap = _ready[rootId];
                PendingFile? taken = null;
                while (taken is null && heap.TryDequeue(out var candidate, out _))
                {
                    _readyCount--;
                    if (!candidate.Removed)
                    {
                        taken = candidate;
                    }
                }

                if (heap.Count > 0)
                {
                    _turns.Enqueue(rootId); // back of the line
                }
                else
                {
                    _ready.Remove(rootId);
                }

                if (taken is not null)
                {
                    taken.State = PendingState.InProgress;
                    file = taken;
                    return true;
                }
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

    /// <summary>
    /// Done with the file (scanned at <paramref name="now"/>, which starts its minimum re-scan interval). If an event arrived
    /// meanwhile, it waits again; otherwise it leaves the queue.
    /// </summary>
    /// <returns>True if it is waiting again.</returns>
    public bool Complete(PendingFile file, DateTimeOffset now, bool scanned = true)
    {
        lock (_gate)
        {
            if (file.Removed)
            {
                return false;
            }

            if (scanned)
            {
                RememberLocked(file.Key, now);
            }

            if (file.Again)
            {
                file.Again = false;
                file.State = PendingState.Settling;
                file.FirstSeen = now;
                file.LockWaitStart = null;
                file.LockAttempts = 0;
                file.NotBefore = scanned ? now + options.MinRescanInterval : file.NotBefore;
                file.Due = Max(now + options.SettleDelay, file.NotBefore);
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

            _perRoot.Remove(root.Id);
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

    /// <summary>The root's share: an eighth of each cap (at least 4 files and 4,096 characters).</summary>
    internal (int Files, long Chars) RootShare =>
        (Math.Max(4, options.MaxPendingFiles / options.FolderShareDivisor), Math.Max(4096, options.MaxPendingPathChars / options.FolderShareDivisor));

    /// <summary>Section D review H5: an owner's share (all its folders together): a quarter of each cap by default.</summary>
    internal (int Files, long Chars) OwnerShare =>
        (Math.Max(4, options.MaxPendingFiles / options.OwnerShareDivisor), Math.Max(4096, options.MaxPendingPathChars / options.OwnerShareDivisor));

    /// <summary>
    /// Section D review H5: whose fair share a root's files count against: the user of a per-user folder (their SID), or one
    /// shared "machine" owner for the machine-wide folders (reading each file's owner when it is queued would cost an open per event).
    /// </summary>
    internal static string OwnerOf(WatchedRoot root) => root.Folder.Sid ?? "machine";

    /// <summary>
    /// Section D review H5: the owner uses less than half its share and the queue isn't full, so its folders' rescans run even
    /// while the queue is busy with other owners' files.
    /// </summary>
    public bool OwnerUnderQuota(WatchedRoot root)
    {
        lock (_gate)
        {
            var used = _perOwner.GetValueOrDefault(OwnerOf(root));
            var share = OwnerShare;
            return used.Files < share.Files / 2 && used.Chars < share.Chars / 2 && _items.Count < options.MaxPendingFiles;
        }
    }

    private bool FitsLocked(WatchedRoot root, long chars)
    {
        var share = RootShare;
        var used = _perRoot.GetValueOrDefault(root.Id);
        if (!(_items.Count < options.MaxPendingFiles && _chars + chars <= options.MaxPendingPathChars && used.Files < share.Files && used.Chars + chars <= share.Chars))
        {
            return false;
        }

        // Section D review H5: the owner's share too, and the last quarter of the queue only for owners below half their share.
        var ownerShare = OwnerShare;
        var owner = _perOwner.GetValueOrDefault(OwnerOf(root));
        if (owner.Files >= ownerShare.Files || owner.Chars + chars > ownerShare.Chars)
        {
            return false;
        }

        bool heavy = owner.Files >= ownerShare.Files / 2 || owner.Chars >= ownerShare.Chars / 2;
        return !heavy || (_items.Count < options.MaxPendingFiles / 4 * 3 && _chars + chars <= options.MaxPendingPathChars / 4 * 3);
    }

    private void Charge(WatchedRoot root, int files, long chars)
    {
        var used = _perRoot.GetValueOrDefault(root.Id);
        used = (used.Files + files, used.Chars + chars);
        if (used.Files <= 0)
        {
            _perRoot.Remove(root.Id);
        }
        else
        {
            _perRoot[root.Id] = used;
        }

        string ownerKey = OwnerOf(root);
        var owner = _perOwner.GetValueOrDefault(ownerKey);
        owner = (owner.Files + files, owner.Chars + chars);
        if (owner.Files <= 0)
        {
            _perOwner.Remove(ownerKey);
        }
        else
        {
            _perOwner[ownerKey] = owner;
        }

        _chars += chars;
    }

    private void RememberLocked(string key, DateTimeOffset at)
    {
        if (!_recent.ContainsKey(key))
        {
            _recentOrder.Enqueue(key);
            while (_recentOrder.Count > MaxRecentScans)
            {
                _recent.Remove(_recentOrder.Dequeue());
            }
        }

        _recent[key] = at;
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
            Charge(file.Root, -1, -file.Key.Length);
        }
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;
}
