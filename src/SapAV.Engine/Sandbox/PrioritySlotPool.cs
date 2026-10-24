namespace SapAV.Engine.Sandbox;

/// <summary>Who a scan is for, highest last (review B H3): it decides who gets the next free scan worker.</summary>
public enum ScanPriority
{
    /// <summary>A job a standard user asked for over the pipe.</summary>
    Low,

    /// <summary>A job an administrator asked for.</summary>
    Normal,

    /// <summary>The engine's own work (scheduled / startup scans, and D1's real-time scans).</summary>
    High,
}

/// <summary>
/// The broker's pool of idle scan workers (review B H3). A returned worker goes to the waiting request with the highest
/// <see cref="ScanPriority"/> (first come, first served within a priority), so the engine's own work never queues behind a
/// user's job. <see cref="ScanPriority.Low"/> requests may hold at most all but one worker at a time (when there is more
/// than one), so one worker is always kept for administrator and engine scans.
/// </summary>
internal sealed class PrioritySlotPool<T>
    where T : class
{
    private readonly Lock _lock = new();
    private readonly Queue<T> _idle = new();
    private readonly LinkedList<Waiter>[] _waiters = [new(), new(), new()];
    private int _lowInUse;

    public PrioritySlotPool(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        foreach (var item in items)
        {
            _idle.Enqueue(item);
        }

        Count = _idle.Count;
        MaxLow = Math.Max(1, Count - 1);
    }

    public int Count { get; }

    /// <summary>Most workers <see cref="ScanPriority.Low"/> requests hold at once.</summary>
    public int MaxLow { get; }

    /// <summary>Waits for a worker (or <paramref name="cancellationToken"/>). Give it back with <see cref="Return"/> and the same priority.</summary>
    public Task<T> RentAsync(ScanPriority priority, CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(priority))
        {
            throw new ArgumentOutOfRangeException(nameof(priority), priority, "Undefined scan priority.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        Waiter waiter;
        lock (_lock)
        {
            if (Allowed(priority) && _idle.TryDequeue(out var item))
            {
                Take(priority);
                return Task.FromResult(item);
            }

            waiter = new Waiter(priority);
            waiter.Node = _waiters[(int)priority].AddLast(waiter);
        }

        waiter.Registration = cancellationToken.Register(() =>
        {
            bool removed;
            lock (_lock)
            {
                removed = waiter.Node?.List is not null;
                if (removed)
                {
                    waiter.Node!.List!.Remove(waiter.Node);
                }
            }

            if (removed)
            {
                waiter.Completion.TrySetCanceled(cancellationToken);
            }
        });
        return waiter.Completion.Task;
    }

    /// <summary>Gives a worker back: to the highest-priority waiter allowed to take it, else to the idle queue.</summary>
    public void Return(T item, ScanPriority rentedWith)
    {
        ArgumentNullException.ThrowIfNull(item);
        Waiter? next = null;
        lock (_lock)
        {
            if (rentedWith == ScanPriority.Low)
            {
                _lowInUse--;
            }

            for (int p = (int)ScanPriority.High; p >= (int)ScanPriority.Low && next is null; p--)
            {
                if (Allowed((ScanPriority)p) && _waiters[p].First is { } first)
                {
                    _waiters[p].Remove(first);
                    Take((ScanPriority)p);
                    next = first.Value;
                }
            }

            if (next is null)
            {
                _idle.Enqueue(item);
                return;
            }
        }

        next.Registration.Dispose();
        next.Completion.TrySetResult(item); // removed from the list under the lock, so it can't be cancelled any more
    }

    private bool Allowed(ScanPriority priority) => priority != ScanPriority.Low || _lowInUse < MaxLow;

    private void Take(ScanPriority priority)
    {
        if (priority == ScanPriority.Low)
        {
            _lowInUse++;
        }
    }

    private sealed class Waiter(ScanPriority priority)
    {
        public ScanPriority Priority { get; } = priority;

        public TaskCompletionSource<T> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public LinkedListNode<Waiter>? Node { get; set; }

        public CancellationTokenRegistration Registration { get; set; }
    }
}
