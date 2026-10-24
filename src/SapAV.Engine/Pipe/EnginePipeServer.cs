using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Alerts;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Pipe;

/// <summary>The pipe name is already taken: something else created it first (squatting), or a second engine is running.</summary>
public sealed class PipeNameTakenException(string message) : Exception(message);

/// <summary>
/// The engine's named-pipe server (B4): <c>\\.\pipe\ProtectedPrefix\Administrators\sap-AV.engine</c> (review B M5), protocol v1
/// (<see cref="Core.Pipe.PipeProtocol"/>).
/// </summary>
/// <remarks>
/// <para><b>Pipe security.</b> Every instance is created with the explicit descriptor of <see cref="EnginePipeSecurity"/>
/// (owner and group = the engine's account; SYSTEM full; Authenticated Users connect but can't create instances), with
/// PIPE_REJECT_REMOTE_CLIENTS. Whenever the engine holds no instance, the next one is created with
/// FILE_FLAG_FIRST_PIPE_INSTANCE, so a name someone else created is refused (<see cref="PipeNameTakenException"/>, logged
/// as critical) instead of joined. Every new instance is read back: its owner and DACL must be the engine's own, otherwise
/// it belongs to a squatter's pipe object and is closed (review B4 H2).</para>
/// <para><b>Always listening</b> (review B4 H2). A replacement instance is created before a connected one is handed off,
/// and the instance limit is <see cref="PipeServerOptions.MaxClients"/> + 1, so the engine keeps the name even when every
/// connection slot is in use. A client that connects while all slots are taken is disconnected at once.</para>
/// <para><b>Resilience</b> (review B4 H1). A client that connects and leaves before the connect completes, or any other
/// failure of one instance, only costs that instance; creating an instance is retried with backoff. Only stopping the
/// service ends the loop.</para>
/// <para><b>Concurrency.</b> At most <see cref="PipeServerOptions.MaxClients"/> connections, at most
/// <see cref="PipeServerOptions.MaxUnidentifiedConnections"/> of them not yet identified (review B4 M1), at most
/// <see cref="PipeServerOptions.MaxConnectionsPerUser"/> per user SID. Each connection runs on its own task
/// (<see cref="PipeConnection"/>).</para>
/// </remarks>
public sealed class EnginePipeServer : BackgroundService
{
    private static readonly TimeSpan MinBackoff = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(5);

    private readonly PipeServerOptions _options;
    private readonly IAlertDispatcher? _alerts;
    private readonly TimeProvider _time;
    private readonly PipeRequestHandler _handler;
    private readonly IClientIdentityResolver _resolver;
    private readonly ILogger _logger;
    private readonly SecurityIdentifier _owner;
    private readonly RawSecurityDescriptor _descriptor;
    private readonly byte[] _securityDescriptor;
    private readonly SemaphoreSlim _slots;
    private readonly Lock _lock = new();
    private readonly Dictionary<SecurityIdentifier, int> _perUser = [];
    private readonly HashSet<Task> _connections = [];
    private readonly TaskCompletionSource _listening = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _liveInstances;
    private int _unidentified;
    private long _listeningGeneration;
    private CancellationToken _stoppingToken;

    public EnginePipeServer(IOptions<PipeServerOptions> options, IScanJobService jobs, IQuarantineService quarantine, TimeProvider time,
        ILogger<EnginePipeServer> logger, IAlertDispatcher alerts)
        : this(ForThisProcess(options.Value, RunningAsSystemOrElevated()), jobs, quarantine, time, logger, new PipeClientIdentityResolver(),
            EnginePipeSecurity.CurrentAccount(), alerts: alerts)
    {
    }

    /// <param name="resolver">Test seam: the identity of each connection. Production always uses <see cref="PipeClientIdentityResolver"/>.</param>
    /// <param name="serverAccount">The account that gets full control besides SYSTEM (the engine's own account).</param>
    /// <param name="alerts">Where the pipe-unavailable health alert goes (review B M4); null in most tests.</param>
    internal EnginePipeServer(PipeServerOptions options, IScanJobService jobs, IQuarantineService? quarantine, TimeProvider time, ILogger logger,
        IClientIdentityResolver resolver, SecurityIdentifier? serverAccount, Func<string, int>? driveType = null, IAlertDispatcher? alerts = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _alerts = alerts;
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _handler = new PipeRequestHandler(jobs, quarantine, options, time, logger, driveType);
        _owner = EnginePipeSecurity.CurrentAccount();
        _descriptor = EnginePipeSecurity.Create(_owner, serverAccount);
        _securityDescriptor = EnginePipeSecurity.ToBytes(_descriptor);
        _slots = new SemaphoreSlim(options.MaxClients, options.MaxClients);
    }

    /// <summary>Completes when the first instance exists (faults if the first attempt failed; the server keeps retrying).</summary>
    public Task Listening => _listening.Task;

    internal PipeRequestHandler Handler => _handler;

    public string FullPipeName => @"\\.\pipe\" + _options.PipeName;

    internal int ActiveConnections
    {
        get
        {
            lock (_lock)
            {
                return _connections.Count;
            }
        }
    }

    /// <summary>Pipe instances the engine holds right now (listening + connected).</summary>
    internal int LiveInstances => Volatile.Read(ref _liveInstances);

    /// <summary>Increments every time a new listening instance is ready (tests wait on it).</summary>
    internal long ListeningGeneration => Interlocked.Read(ref _listeningGeneration);

    /// <summary>Test seam: runs before each WaitForConnection (e.g. to let a client connect and leave first).</summary>
    internal Func<Task>? BeforeWaitForConnection { get; set; }

    /// <summary>Test seam: the event-frame factory of new connections (to inject a writer fault).</summary>
    internal Func<Core.Pipe.PipeEventKind, object, Core.Pipe.PipeFrame>? EventFactory { get; set; }

    public override void Dispose()
    {
        _handler.Dispose();
        base.Dispose();
    }

    /// <summary>
    /// Review B M5: only an elevated or SYSTEM engine can create <see cref="Core.Pipe.PipeProtocol.PipeName"/> (under
    /// <c>ProtectedPrefix\Administrators\</c>); a non-elevated console run uses <see cref="Core.Pipe.PipeProtocol.DebugPipeName"/>.
    /// </summary>
    internal static PipeServerOptions ForThisProcess(PipeServerOptions options, bool privileged)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!privileged && options.PipeName == Core.Pipe.PipeProtocol.PipeName)
        {
            options.PipeName = Core.Pipe.PipeProtocol.DebugPipeName;
        }

        return options;
    }

    private static bool RunningAsSystemOrElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Review B M4: the accept loop is supervised. It already survives failures of single instances; anything unexpected
    /// that still escapes it is logged as critical, raises the pipe-unavailable alert, and the loop starts again after a
    /// backoff, so the engine never loses its pipe for good (and never stops because of it).
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.PipeName == Core.Pipe.PipeProtocol.DebugPipeName)
        {
            _logger.LogWarning("The engine is not elevated: it listens on the debug pipe {Pipe}, not the protected engine pipe.", FullPipeName);
        }

        var delay = MinBackoff;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await AcceptLoopAsync(stoppingToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException && !stoppingToken.IsCancellationRequested)
            {
                _logger.LogCritical(ex, "The engine pipe loop failed; restarting it in {Delay}.", delay);
                ReportUnavailable($"the pipe loop failed ({ex.GetType().Name}).");
            }

            try
            {
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            delay = TimeSpan.FromTicks(Math.Min(MaxBackoff.Ticks, delay.Ticks * 2));
        }
    }

    private void ReportUnavailable(string why) =>
        _alerts?.Post(Alerts.ScanAlerts.PipeUnavailable(FullPipeName, why, _time.GetUtcNow()), health: true);

    private async Task AcceptLoopAsync(CancellationToken stoppingToken)
    {
        _stoppingToken = stoppingToken;
        NamedPipeServerStream? listening = null;
        try
        {
            while (true)
            {
                listening ??= await CreateWithRetryAsync(stoppingToken).ConfigureAwait(false);
                if (BeforeWaitForConnection is { } hook)
                {
                    await hook().ConfigureAwait(false);
                }

                try
                {
                    await listening.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    // e.g. ERROR_NO_DATA: the client connected and left before the connect completed. Only this instance is lost.
                    _logger.LogDebug("A pipe instance failed while waiting for a client: {Why}", ex.Message);
                    await CloseInstanceAsync(listening).ConfigureAwait(false);
                    listening = null;
                    continue;
                }

                var connected = listening;
                listening = null;
                bool slot = _slots.Wait(0);
                if (!slot)
                {
                    _logger.LogWarning("Pipe client refused: all {Max} connection slots are in use.", _options.MaxClients);
                    await CloseInstanceAsync(connected).ConfigureAwait(false);
                }

                // The replacement exists before the connected instance is handed off, so the name is never released.
                listening = TryCreateInstance(out _);
                if (slot)
                {
                    Track(connected);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // stopping
        }
        finally
        {
            if (listening is not null)
            {
                await CloseInstanceAsync(listening).ConfigureAwait(false);
            }

            Task[] running;
            lock (_lock)
            {
                running = [.. _connections];
            }

            await Task.WhenAll(running).ConfigureAwait(false);
        }
    }

    /// <summary>Creates an instance, retrying with backoff until it works or the service stops.</summary>
    private async Task<NamedPipeServerStream> CreateWithRetryAsync(CancellationToken stoppingToken)
    {
        var delay = MinBackoff;
        bool reported = false;
        while (true)
        {
            stoppingToken.ThrowIfCancellationRequested();
            var instance = TryCreateInstance(out Exception? failure);
            if (instance is not null)
            {
                if (_listening.TrySetResult())
                {
                    _logger.LogInformation("Engine pipe listening on {Pipe}.", FullPipeName);
                }
                else if (reported)
                {
                    _logger.LogWarning("Engine pipe {Pipe} is available again.", FullPipeName);
                }

                return instance;
            }

            if (!reported)
            {
                _logger.LogCritical("The engine pipe {Pipe} could not be created: {Why} The GUI can't connect; retrying.", FullPipeName, failure!.Message);
                ReportUnavailable(failure.Message);
                _listening.TrySetException(failure);
                reported = true;
            }

            await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
            delay = TimeSpan.FromTicks(Math.Min(MaxBackoff.Ticks, delay.Ticks * 2));
        }
    }

    private void Track(NamedPipeServerStream instance)
    {
        if (Interlocked.Increment(ref _unidentified) > _options.EffectiveMaxUnidentified)
        {
            Interlocked.Decrement(ref _unidentified);
            _logger.LogWarning("Pipe client refused: {Max} connections are still waiting to be identified.", _options.EffectiveMaxUnidentified);
            _ = CloseAndReleaseAsync(instance);
            return;
        }

        var identified = new Release(() => Interlocked.Decrement(ref _unidentified));
        var connection = new PipeConnection(instance, _handler, _resolver, AcquireUserSlot, identified.Dispose, _options, _logger);
        if (EventFactory is { } factory)
        {
            connection.EventFactory = factory;
        }

        lock (_lock)
        {
            var task = Task.Run(async () =>
            {
                try
                {
                    await connection.RunAsync(_stoppingToken).ConfigureAwait(false);
                }
                finally
                {
                    identified.Dispose();
                    Interlocked.Decrement(ref _liveInstances); // the connection disposed its instance
                    _slots.Release();
                }
            }, CancellationToken.None);
            _connections.Add(task);
            _ = task.ContinueWith(t =>
            {
                lock (_lock)
                {
                    _connections.Remove(t);
                }
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private async Task CloseAndReleaseAsync(NamedPipeServerStream instance)
    {
        await CloseInstanceAsync(instance).ConfigureAwait(false);
        _slots.Release();
    }

    private async Task CloseInstanceAsync(NamedPipeServerStream instance)
    {
        await instance.DisposeAsync().ConfigureAwait(false);
        Interlocked.Decrement(ref _liveInstances);
    }

    /// <summary>One of the user's <see cref="PipeServerOptions.MaxConnectionsPerUser"/> slots, or null.</summary>
    private IDisposable? AcquireUserSlot(IClientIdentity identity)
    {
        var user = identity.User;
        lock (_lock)
        {
            int count = _perUser.GetValueOrDefault(user);
            if (count >= _options.MaxConnectionsPerUser)
            {
                return null;
            }

            _perUser[user] = count + 1;
        }

        return new Release(() =>
        {
            lock (_lock)
            {
                if (--_perUser[user] == 0)
                {
                    _perUser.Remove(user);
                }
            }
        });
    }

    /// <summary>
    /// A new verified instance, or null with the failure. FILE_FLAG_FIRST_PIPE_INSTANCE whenever the engine holds none;
    /// the instance's owner and DACL must read back as the engine's own.
    /// </summary>
    internal NamedPipeServerStream? TryCreateInstance(out Exception? failure, bool? forceFirst = null)
    {
        bool first = forceFirst ?? Volatile.Read(ref _liveInstances) == 0;
        uint openMode = PipeNative.PipeAccessDuplex | PipeNative.FileFlagOverlapped | (first ? PipeNative.FileFlagFirstPipeInstance : 0);
        uint pipeMode = PipeNative.PipeTypeByte | PipeNative.PipeReadModeByte | PipeNative.PipeWait | PipeNative.PipeRejectRemoteClients;
        SafePipeHandle handle = PipeNative.CreatePipe(FullPipeName, openMode, pipeMode, _options.MaxClients + 1, 64 * 1024, _securityDescriptor,
            out int error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            failure = error == PipeNative.ErrorAccessDenied || (first && error == PipeNative.ErrorPipeBusy)
                ? new PipeNameTakenException($"{FullPipeName} already exists and belongs to someone else (Win32 error {error}).")
                : new IOException($"CreateNamedPipe failed for {FullPipeName} (Win32 error {error}).");
            return null;
        }

        if (!IsOwnInstance(handle))
        {
            handle.Dispose();
            _logger.LogCritical("A new instance of {Pipe} joined a pipe the engine doesn't own (owner or DACL differ); closed it.", FullPipeName);
            failure = new PipeNameTakenException($"{FullPipeName} belongs to someone else (owner or DACL differ).");
            return null;
        }

        Interlocked.Increment(ref _liveInstances);
        Interlocked.Increment(ref _listeningGeneration);
        failure = null;
        return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
    }

    /// <summary>The instance's pipe object has the engine's owner and exactly the engine's DACL.</summary>
    private bool IsOwnInstance(SafePipeHandle handle)
    {
        var actual = PipeNative.TryReadKernelObjectSecurity(handle);
        if (actual?.Owner is null || actual.Owner != _owner || actual.DiscretionaryAcl is null)
        {
            return false;
        }

        var expected = new byte[_descriptor.DiscretionaryAcl!.BinaryLength];
        _descriptor.DiscretionaryAcl.GetBinaryForm(expected, 0);
        var read = new byte[actual.DiscretionaryAcl.BinaryLength];
        actual.DiscretionaryAcl.GetBinaryForm(read, 0);
        return expected.AsSpan().SequenceEqual(read);
    }

    private sealed class Release(Action release) : IDisposable
    {
        private int _done;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0)
            {
                release();
            }
        }
    }
}
