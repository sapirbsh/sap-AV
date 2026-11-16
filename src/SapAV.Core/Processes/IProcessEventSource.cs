using System.Threading.Channels;

namespace SapAV.Core.Processes;

/// <summary>
/// A stream of process start / stop events plus the processes that were already running when it started (ROADMAP E8). The
/// consumers are the miner monitor (E9: "stops when Task Manager opens"), the infostealer monitor (E10: which process read a
/// store) and the parent-child chains / network telemetry of G2a.
/// </summary>
/// <remarks>
/// <para>
/// Every consumer gets its own bounded buffer through <see cref="Subscribe"/>. The producer never blocks: when a buffer is full
/// the oldest event is dropped and counted (<see cref="ProcessEventSubscription.Dropped"/>), so a slow consumer can't stall the
/// ETW callback or the other consumers.
/// </para>
/// <para>
/// Process identity is <see cref="ProcessKey"/> (PID + start time), never the PID alone. The engine's implementation is an ETW
/// real-time session (Microsoft-Windows-Kernel-Process) that needs administrator or SYSTEM; tests use
/// <see cref="FakeProcessEventSource"/>.
/// </para>
/// </remarks>
public interface IProcessEventSource : IDisposable
{
    /// <summary>The current health and counters.</summary>
    ProcessEventSourceStatus Status { get; }

    /// <summary>
    /// Starts receiving events and publishes the pre-existing processes (<see cref="ProcessEventKind.Existing"/>). Idempotent.
    /// Never throws for missing rights or an unavailable OS facility: that is reported in the returned status
    /// (<see cref="ProcessEventSourceHealth.AccessDenied"/> / <see cref="ProcessEventSourceHealth.Unavailable"/>). Only
    /// cancellation throws <see cref="OperationCanceledException"/>.
    /// </summary>
    Task<ProcessEventSourceStatus> StartAsync(CancellationToken cancellationToken = default);

    /// <summary>Stops receiving events and releases the OS session. Idempotent; never throws. The source can be started again.</summary>
    Task StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// A new subscription with its own bounded buffer of <paramref name="capacity"/> events. It sees events published from now
    /// on; use <see cref="GetKnownProcesses"/> for what is already known. Dispose it to unsubscribe. After the source is
    /// disposed, the subscription's reader is completed.
    /// </summary>
    ProcessEventSubscription Subscribe(int capacity = ProcessEventSubscription.DefaultCapacity);

    /// <summary>The processes currently believed to be running (pre-existing and started, not yet stopped).</summary>
    IReadOnlyList<ProcessEvent> GetKnownProcesses();

    /// <summary>The known running process with this identity, or null.</summary>
    ProcessEvent? FindProcess(ProcessKey key);

    /// <summary>The known running parent of <paramref name="child"/>, or null (unknown, exited, or its PID was reused).</summary>
    ProcessEvent? FindParent(ProcessEvent child);

    /// <summary>
    /// The known running process that really created <paramref name="child"/> (the ETW creator), or null. Differs from
    /// <see cref="FindParent"/> only when <see cref="ProcessEvent.ParentMismatch"/> is set (PPID spoofing): then the parent is
    /// attacker-controlled and the creator is the real one.
    /// </summary>
    ProcessEvent? FindCreator(ProcessEvent child);
}

/// <summary>
/// One consumer's view of an <see cref="IProcessEventSource"/>: a bounded, drop-oldest buffer. Read from <see cref="Reader"/>
/// on one consumer task. Dispose to unsubscribe (the reader then completes).
/// </summary>
public sealed class ProcessEventSubscription : IDisposable
{
    /// <summary>Default buffer size: enough for a burst of process starts (a build, a login) without holding much memory.</summary>
    public const int DefaultCapacity = 2048;

    /// <summary>Largest allowed buffer. An event can hold about 20 KB (capped command line and path), so this bounds a buffer at ~160 MB worst case.</summary>
    public const int MaxCapacity = 8192;

    private readonly Channel<ProcessEvent> _channel;
    private readonly Action<ProcessEventSubscription>? _onDispose;
    private long _dropped;
    private int _disposed;

    internal ProcessEventSubscription(int capacity, Action<ProcessEventSubscription>? onDispose)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(capacity, MaxCapacity);
        Capacity = capacity;
        _onDispose = onDispose;
        _channel = Channel.CreateBounded<ProcessEvent>(
            new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false, // the producer (an ETW callback) never runs consumer code
            },
            _ => Interlocked.Increment(ref _dropped));
    }

    /// <summary>The buffer size.</summary>
    public int Capacity { get; }

    /// <summary>The events; completes when the subscription or the source is disposed.</summary>
    public ChannelReader<ProcessEvent> Reader => _channel.Reader;

    /// <summary>Events dropped from this buffer because it was full (the oldest ones).</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>Never blocks: a full buffer drops its oldest event. False only after completion.</summary>
    internal bool TryWrite(ProcessEvent processEvent) => _channel.Writer.TryWrite(processEvent);

    internal void Complete() => _channel.Writer.TryComplete();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Complete();
        _onDispose?.Invoke(this);
    }
}
