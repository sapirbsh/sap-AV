namespace SapAV.Core.Processes;

/// <summary>
/// A scripted <see cref="IProcessEventSource"/> for tests (the "fake feed"): events are pushed with <see cref="Publish"/>, the
/// start result and pre-existing processes are set up front. Uses the same <see cref="ProcessEventHub"/> as the real source,
/// so buffering, drop counting, PID-reuse handling and stop completion behave the same.
/// </summary>
public sealed class FakeProcessEventSource : IProcessEventSource
{
    private readonly ProcessEventHub _hub;
    private int _startCalls;
    private int _stopCalls;
    private bool _disposed;

    public FakeProcessEventSource(IEnumerable<ProcessEvent>? preExisting = null, int tableCapacity = ProcessTable.DefaultCapacity)
    {
        _hub = new ProcessEventHub(tableCapacity);
        PreExisting = preExisting?.ToArray() ?? [];
    }

    /// <summary>Published as <see cref="ProcessEventKind.Existing"/> entries on a successful start.</summary>
    public IReadOnlyList<ProcessEvent> PreExisting { get; set; }

    /// <summary>The health <see cref="StartAsync"/> ends in (e.g. <see cref="ProcessEventSourceHealth.AccessDenied"/>).</summary>
    public ProcessEventSourceHealth StartResult { get; set; } = ProcessEventSourceHealth.Running;

    public int StartCalls => Volatile.Read(ref _startCalls);

    public int StopCalls => Volatile.Read(ref _stopCalls);

    public bool IsDisposed => _disposed;

    public ProcessEventSourceStatus Status => _hub.Status;

    public Task<ProcessEventSourceStatus> StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);
        Interlocked.Increment(ref _startCalls);
        if (Status.IsReceiving)
        {
            return Task.FromResult(Status);
        }

        _hub.SetHealth(StartResult, StartResult.ToString(), "fake");
        if (StartResult == ProcessEventSourceHealth.Running)
        {
            foreach (var process in PreExisting)
            {
                _hub.Publish(process with { Kind = ProcessEventKind.Existing });
            }
        }

        return Task.FromResult(Status);
    }

    public Task StopAsync(CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _stopCalls);
        _hub.SetHealth(ProcessEventSourceHealth.Stopped, "stopped");
        return Task.CompletedTask;
    }

    /// <summary>Feeds one event, as the OS would. Returns what subscribers received (null if nothing was delivered).</summary>
    public ProcessEvent? Publish(ProcessEvent processEvent) => _hub.Publish(processEvent);

    /// <summary>Simulates OS-level event loss (total so far).</summary>
    public void ReportLost(long totalLost) => _hub.ReportLost(totalLost);

    /// <summary>Simulates a health change (e.g. the session died).</summary>
    public void SetHealth(ProcessEventSourceHealth health, string? detail) => _hub.SetHealth(health, detail);

    public ProcessEventSubscription Subscribe(int capacity = ProcessEventSubscription.DefaultCapacity) => _hub.Subscribe(capacity);

    public IReadOnlyList<ProcessEvent> GetKnownProcesses() => _hub.GetKnownProcesses();

    public ProcessEvent? FindProcess(ProcessKey key) => _hub.FindProcess(key);

    public ProcessEvent? FindParent(ProcessEvent child) => _hub.FindParent(child);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _hub.SetHealth(ProcessEventSourceHealth.Stopped, "disposed");
        _hub.Complete();
    }
}
