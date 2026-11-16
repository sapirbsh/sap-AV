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
/// A session that ends without the engine asking (e.g. <c>logman stop</c>) raises <see cref="Unavailable"/> (health alert
/// 9012) and is restarted with backoff (1 s, 5 s, then every 30 s) by a watchdog (E8 review M2).
/// </para>
/// <para>
/// The ETW callback never waits for a consumer: it validates and maps the event (one or two query-only opens of the
/// process), publishes it to bounded drop-oldest buffers under a short lock and returns. Malformed or forged events are
/// dropped and counted (<see cref="ProcessEventSourceStatus.RejectedEvents"/>, see <see cref="KernelProcessEventMapper"/>).
/// Only event metadata and query-only process information are read; no file is opened.
/// </para>
/// </remarks>
public sealed class EtwProcessEventSource : IProcessEventSource
{
    private static readonly TimeSpan LostPollInterval = TimeSpan.FromSeconds(2);

    /// <summary>A session that ran at least this long before dying restarts the backoff from its first step.</summary>
    private static readonly TimeSpan HealthyRun = TimeSpan.FromSeconds(60);

    private readonly ProcessEventSourceOptions _options;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly IKernelProcessSessionFactory _factory;
    private readonly IRunningProcessSnapshot _snapshot;
    private readonly IProcessInfoReader _info;
    private readonly KernelProcessEventMapper _mapper;
    private readonly ProcessEventHub _hub;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private IKernelProcessSession? _session;
    private Thread? _thread;
    private CancellationTokenSource? _sessionCts;  // the current session's maintenance (reconciliation); ends with the session
    private CancellationTokenSource? _watchdogCts; // pending restarts; ends only when the engine asks to stop
    private DateTimeOffset _sessionStartedAt;
    private int _restartAttempt;
    private volatile bool _stopping;
    private long _lastLostPoll;
    private long _errors;
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
        _info = info ?? throw new ArgumentNullException(nameof(info));
        _mapper = new KernelProcessEventMapper(info, toWin32);
        _hub = new ProcessEventHub(ProcessTable.DefaultCapacity, IsGone);
    }

    /// <summary>Called (with engine text) when the session ended without the engine asking; the host posts health alert 9012.</summary>
    public Action<string>? Unavailable { get; set; }

    /// <summary>Watchdog restart delays; the last one repeats.</summary>
    internal TimeSpan[] RestartBackoff { get; set; } = [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30)];

    /// <summary>How often the table is reconciled against a Toolhelp snapshot (stale entries from lost stop events).</summary>
    internal TimeSpan ReconcileInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The session name in use (validated; see <see cref="ProcessEventSourceOptions.EffectiveSessionName"/>).</summary>
    public string SessionName => _options.EffectiveSessionName;

    /// <summary>Events that failed while being decoded or handled (logged at most once per 1000).</summary>
    public long Errors => Interlocked.Read(ref _errors);

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
            if (_session is not null && _hub.Status.IsReceiving)
            {
                return Status;
            }

            _watchdogCts?.Cancel();
            _watchdogCts?.Dispose();
            _watchdogCts = new CancellationTokenSource();
            _restartAttempt = 0;
            return await StartCoreAsync(cancellationToken).ConfigureAwait(false);
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
            CancelWatchdog();
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

    public ProcessEvent? FindCreator(ProcessEvent child) => _hub.FindCreator(child);

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
            CancelWatchdog();
            StopCore("disposed");
            _hub.Complete();
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    /// <summary>Creates the session, starts the event thread and publishes the pre-existing processes. Caller holds the lifecycle lock.</summary>
    private async Task<ProcessEventSourceStatus> StartCoreAsync(CancellationToken cancellationToken)
    {
        if (_session is not null)
        {
            StopCore("restarting after the session ended"); // the session died on its own: clean up first
        }

        if (!TryCreateSession(out var session))
        {
            return _hub.Status;
        }

        var startedAt = _time.GetUtcNow();
        _sessionStartedAt = startedAt;
        _stopping = false;
        _session = session;
        _sessionCts = new CancellationTokenSource();
        _hub.BeginSession();
        _hub.SetHealth(ProcessEventSourceHealth.Running, "receiving Kernel-Process events", session.Name);
        _thread = new Thread(() => RunSession(session)) { IsBackground = true, Name = "sap-AV process events" };
        _thread.Start();
        _ = ReconcileLoopAsync(_sessionCts.Token);
        _logger.LogInformation("Process event source started (ETW session {Session})", session.Name);

        // The snapshot runs after the session started, so no process falls between the two; a process that started in
        // between is left to its start event (MapExisting skips it).
        await Task.Run(() => PublishPreExisting(startedAt, cancellationToken), cancellationToken).ConfigureAwait(false);
        return Status;
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
            session.Run(OnRecord, OnError);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (!_stopping)
            {
                _logger.LogError(ex, "ETW session {Session} failed", session.Name);
            }
        }

        if (_stopping)
        {
            return;
        }

        // The session ended on its own (stopped from outside, e.g. logman stop, or it failed): make sure it's gone, report it
        // (health alert 9012, T1562.006) and let the watchdog restart it.
        session.Stop();
        _hub.SetHealth(ProcessEventSourceHealth.Unavailable, "the ETW session ended unexpectedly; restarting");
        _logger.LogWarning("ETW session {Session} ended unexpectedly; process events are unavailable until it restarts", session.Name);
        ReportUnavailable("the ETW session ended without the engine asking (stopped from outside, or it failed); it is restarted automatically.");
        ScheduleRestart(_time.GetUtcNow() - _sessionStartedAt >= HealthyRun);
    }

    private void ScheduleRestart(bool resetBackoff)
    {
        var watchdog = _watchdogCts;
        if (watchdog is null || watchdog.IsCancellationRequested)
        {
            return;
        }

        if (resetBackoff)
        {
            Interlocked.Exchange(ref _restartAttempt, 0);
        }

        int attempt = Interlocked.Increment(ref _restartAttempt) - 1;

        var delay = RestartBackoff[Math.Clamp(attempt, 0, RestartBackoff.Length - 1)];
        var token = watchdog.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay, _time, token).ConfigureAwait(false);
                await RestartAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // the engine stopped the source meanwhile
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                _logger.LogError(ex, "Restarting the process event source failed");
            }
        }, CancellationToken.None);
    }

    private async Task RestartAsync(CancellationToken token)
    {
        await _lifecycle.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (_disposed || token.IsCancellationRequested || _hub.Status.IsReceiving)
            {
                return;
            }

            var status = await StartCoreAsync(token).ConfigureAwait(false);
            if (status.IsReceiving)
            {
                _logger.LogInformation("Process event source restarted after the session ended");
                return;
            }
        }
        finally
        {
            _lifecycle.Release();
        }

        ScheduleRestart(resetBackoff: false); // still down: try again later
    }

    private void OnRecord(KernelProcessRecord record)
    {
        var processEvent = _mapper.Map(record, out var rejection);
        if (processEvent is null)
        {
            _hub.CountRejected();
            if (_hub.Status.RejectedEvents % 1000 == 1)
            {
                _logger.LogWarning("Dropped a {Kind} event for PID {Pid} logged by PID {Header}: {Reason} (possible forged event)",
                    record.Kind, record.ProcessId, record.HeaderProcessId, rejection);
            }
        }
        else
        {
            _hub.Publish(processEvent);
        }

        if (Environment.TickCount64 - Interlocked.Read(ref _lastLostPoll) >= LostPollInterval.TotalMilliseconds)
        {
            PollLost();
        }
    }

    private void OnError(Exception ex)
    {
        if (Interlocked.Increment(ref _errors) % 1000 == 1)
        {
            _logger.LogWarning(ex, "A process event couldn't be decoded or handled ({Count} so far)", Errors);
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
                Interlocked.Increment(ref _errors);
                _logger.LogDebug(ex, "Pre-existing process {Pid} couldn't be mapped", entry.ProcessId);
            }
        }

        _logger.LogInformation("Process event source: {Count} pre-existing processes", published);
    }

    /// <summary>Every <see cref="ReconcileInterval"/>: forget known processes that no longer run (their stop event was lost).</summary>
    private async Task ReconcileLoopAsync(CancellationToken token)
    {
        try
        {
            while (true)
            {
                await Task.Delay(ReconcileInterval, _time, token).ConfigureAwait(false);
                var running = _snapshot.Take().Select(e => e.ProcessId).ToHashSet();
                if (running.Count == 0)
                {
                    continue; // the snapshot failed: no evidence either way
                }

                int removed = _hub.Reconcile(p => !running.Contains(p.ProcessId) || IsGone(p));
                if (removed > 0)
                {
                    _logger.LogDebug("Process table reconciled: {Count} stale entries removed", removed);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // the session ended
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Process table reconciliation stopped");
        }
    }

    private bool IsGone(ProcessEvent process) => _info.CheckLiveness(process.ProcessId, process.StartTime) == ProcessLiveness.Gone;

    private void ReportUnavailable(string problem)
    {
        try
        {
            Unavailable?.Invoke(problem);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "The process-events health alert couldn't be raised");
        }
    }

    private void PollLost()
    {
        Interlocked.Exchange(ref _lastLostPoll, Environment.TickCount64);
        if (Volatile.Read(ref _session)?.EventsLost is { } lost)
        {
            _hub.ReportLost(lost);
        }
    }

    private void CancelWatchdog()
    {
        _watchdogCts?.Cancel();
        _watchdogCts?.Dispose();
        _watchdogCts = null;
    }

    /// <summary>Stops the OS session first (so it can't leak even if the thread hangs), then joins the event thread.</summary>
    private void StopCore(string reason)
    {
        var session = _session;
        if (session is null)
        {
            if (_hub.Status.Health is ProcessEventSourceHealth.Running or ProcessEventSourceHealth.LostEvents
                or ProcessEventSourceHealth.Unavailable)
            {
                _hub.SetHealth(ProcessEventSourceHealth.Stopped, reason);
            }

            return;
        }

        _stopping = true;
        _sessionCts?.Cancel();
        _sessionCts?.Dispose();
        _sessionCts = null;
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
