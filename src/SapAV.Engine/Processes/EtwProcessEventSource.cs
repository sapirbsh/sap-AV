using Microsoft.Extensions.Options;
using SapAV.Core.Processes;

namespace SapAV.Engine.Processes;

/// <summary>
/// The engine's <see cref="IProcessEventSource"/> (ROADMAP E8): an ETW real-time session on Microsoft-Windows-Kernel-Process,
/// read on a dedicated background thread, plus a Toolhelp snapshot of the processes already running (pre-existing).
/// </summary>
/// <remarks>
/// <para>
/// Needs administrator or SYSTEM. Without them, or when no session can be created, <see cref="StartAsync"/> reports
/// <see cref="ProcessEventSourceHealth.AccessDenied"/> / <see cref="ProcessEventSourceHealth.Unavailable"/> and never throws.
/// </para>
/// <para>
/// Session lifetime: a fixed, sap-AV-prefixed name; a same-name leftover is stopped before the start; the session is stopped
/// on <see cref="StopAsync"/>, <see cref="Dispose"/>, process exit and unhandled exceptions (<see cref="EtwSessionRegistry"/>).
/// </para>
/// <para>
/// The ETW callback never blocks: it maps the event (one query-only open of the new process), publishes it to bounded
/// drop-oldest buffers and returns. Only event metadata and query-only process information are read; no file is opened.
/// </para>
/// </remarks>
public sealed class EtwProcessEventSource : IProcessEventSource
{
    private static readonly TimeSpan LostPollInterval = TimeSpan.FromSeconds(2);

    private readonly ProcessEventSourceOptions _options;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly IKernelProcessSessionFactory _factory;
    private readonly IRunningProcessSnapshot _snapshot;
    private readonly KernelProcessEventMapper _mapper;
    private readonly ProcessEventHub _hub = new();
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private IKernelProcessSession? _session;
    private Thread? _thread;
    private volatile bool _stopping;
    private long _lastLostPoll;
    private long _mappingErrors;
    private bool _disposed;

    public EtwProcessEventSource(IOptions<ProcessEventSourceOptions> options, ILogger<EtwProcessEventSource> logger, TimeProvider time)
        : this(options.Value, logger, time, TraceEventKernelProcessSessionFactory.Instance, ToolhelpProcessSnapshot.Instance,
            NativeProcessInfoReader.Instance, new DevicePathMapper().ToWin32)
    {
    }

    internal EtwProcessEventSource(ProcessEventSourceOptions options, ILogger logger, TimeProvider time, IKernelProcessSessionFactory factory,
        IRunningProcessSnapshot snapshot, IProcessInfoReader info, Func<string?, string?> toWin32)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        _mapper = new KernelProcessEventMapper(info, toWin32);
    }

    /// <summary>The session name in use (validated; see <see cref="ProcessEventSourceOptions.EffectiveSessionName"/>).</summary>
    public string SessionName => _options.EffectiveSessionName;

    /// <summary>Events that couldn't be mapped (logged at most once per 1000).</summary>
    public long MappingErrors => Interlocked.Read(ref _mappingErrors);

    public ProcessEventSourceStatus Status
    {
        get
        {
            PollLost();
            return _hub.Status;
        }
    }

    public async Task<ProcessEventSourceStatus> StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_session is not null)
            {
                if (_hub.Status.IsReceiving)
                {
                    return Status;
                }

                StopCore("restarting after the session ended"); // the session died on its own: clean up, then start again
            }

            if (!TryCreateSession(out var session))
            {
                return _hub.Status;
            }

            var startedAt = _time.GetUtcNow();
            _stopping = false;
            _session = session;
            _hub.BeginSession();
            _hub.SetHealth(ProcessEventSourceHealth.Running, "receiving Kernel-Process events", session.Name);
            _thread = new Thread(() => RunSession(session)) { IsBackground = true, Name = "sap-AV process events" };
            _thread.Start();
            _logger.LogInformation("Process event source started (ETW session {Session})", session.Name);

            // The snapshot runs after the session started, so no process falls between the two; a process that started in
            // between is left to its start event (MapExisting skips it).
            await Task.Run(() => PublishPreExisting(startedAt, cancellationToken), cancellationToken).ConfigureAwait(false);
            return Status;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycle.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            StopCore("stopped");
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public ProcessEventSubscription Subscribe(int capacity = ProcessEventSubscription.DefaultCapacity) => _hub.Subscribe(capacity);

    public IReadOnlyList<ProcessEvent> GetKnownProcesses() => _hub.GetKnownProcesses();

    public ProcessEvent? FindProcess(ProcessKey key) => _hub.FindProcess(key);

    public ProcessEvent? FindParent(ProcessEvent child) => _hub.FindParent(child);

    public void Dispose()
    {
        _lifecycle.Wait();
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            StopCore("disposed");
            _hub.Complete();
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    private bool TryCreateSession(out IKernelProcessSession session)
    {
        session = null!;
        if (_factory.IsElevated() == false)
        {
            _hub.SetHealth(ProcessEventSourceHealth.AccessDenied, "process events need administrator or SYSTEM rights");
            _logger.LogWarning("Process event source not started: the engine is not elevated");
            return false;
        }

        string name = SessionName;
        if (_factory.StopSession(name))
        {
            _logger.LogWarning("Stopped a leftover ETW session {Session} (from a previous run that didn't shut down)", name);
        }

        try
        {
            session = _factory.Create(name, _options.BufferSizeMB);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            _hub.SetHealth(ProcessEventSourceHealth.AccessDenied, "access denied creating the ETW session");
            _logger.LogWarning("Process event source not started: access denied creating ETW session {Session}", name);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            string detail = $"the ETW session couldn't be created ({ex.GetType().Name}, 0x{ex.HResult:X8})";
            _hub.SetHealth(ProcessEventSourceHealth.Unavailable, detail);
            _logger.LogWarning(ex, "Process event source unavailable: {Detail}", detail);
        }

        return false;
    }

    private void RunSession(IKernelProcessSession session)
    {
        try
        {
            session.Run(OnRecord);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (!_stopping)
            {
                _logger.LogError(ex, "ETW session {Session} failed", session.Name);
            }
        }

        if (!_stopping)
        {
            // The session ended on its own (stopped from outside, e.g. logman stop): report it, and make sure it's gone.
            session.Stop();
            _hub.SetHealth(ProcessEventSourceHealth.Unavailable, "the ETW session ended unexpectedly");
            _logger.LogWarning("ETW session {Session} ended unexpectedly; process events are unavailable", session.Name);
        }
    }

    private void OnRecord(KernelProcessRecord record)
    {
        try
        {
            _hub.Publish(_mapper.Map(record));
            if (Environment.TickCount64 - Interlocked.Read(ref _lastLostPoll) >= LostPollInterval.TotalMilliseconds)
            {
                PollLost();
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Never throw into TraceEvent's dispatch loop.
            if (Interlocked.Increment(ref _mappingErrors) % 1000 == 1)
            {
                _logger.LogWarning(ex, "A process event couldn't be mapped ({Count} so far)", MappingErrors);
            }
        }
    }

    private void PublishPreExisting(DateTimeOffset startedAt, CancellationToken cancellationToken)
    {
        int published = 0;
        foreach (var entry in _snapshot.Take())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_stopping)
            {
                return;
            }

            try
            {
                if (_mapper.MapExisting(entry, startedAt, _time.GetUtcNow()) is { } existing && _hub.Publish(existing) is not null)
                {
                    published++;
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Interlocked.Increment(ref _mappingErrors);
                _logger.LogDebug(ex, "Pre-existing process {Pid} couldn't be mapped", entry.ProcessId);
            }
        }

        _logger.LogInformation("Process event source: {Count} pre-existing processes", published);
    }

    private void PollLost()
    {
        Interlocked.Exchange(ref _lastLostPoll, Environment.TickCount64);
        if (Volatile.Read(ref _session)?.EventsLost is { } lost)
        {
            _hub.ReportLost(lost);
        }
    }

    /// <summary>Stops the OS session first (so it can't leak even if the thread hangs), then joins the event thread.</summary>
    private void StopCore(string reason)
    {
        var session = _session;
        if (session is null)
        {
            if (_hub.Status.Health is ProcessEventSourceHealth.Running or ProcessEventSourceHealth.LostEvents)
            {
                _hub.SetHealth(ProcessEventSourceHealth.Stopped, reason);
            }

            return;
        }

        _stopping = true;
        session.Stop();
        var thread = _thread;
        if (thread is not null && thread != Thread.CurrentThread && !thread.Join(_options.StopTimeout))
        {
            _logger.LogWarning("The process event thread didn't finish within {Timeout} after the session stopped", _options.StopTimeout);
        }

        session.Dispose();
        _session = null;
        _thread = null;
        _hub.SetHealth(ProcessEventSourceHealth.Stopped, reason);
        _logger.LogInformation("Process event source {Reason} (ETW session {Session})", reason, session.Name);
    }
}
