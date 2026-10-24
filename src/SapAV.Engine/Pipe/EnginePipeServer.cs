using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Pipe;

/// <summary>The pipe name is already taken: something else created it first (squatting), or a second engine is running.</summary>
public sealed class PipeNameTakenException(string message) : Exception(message);

/// <summary>
/// The engine's named-pipe server (B4): <c>\\.\pipe\sap-AV.engine</c>, protocol v1 (<see cref="Core.Pipe.PipeProtocol"/>).
/// </summary>
/// <remarks>
/// <para><b>Pipe security.</b> Every instance is created with the explicit descriptor of <see cref="EnginePipeSecurity"/>
/// (SYSTEM full; Authenticated Users connect but can't create instances). The first instance uses
/// FILE_FLAG_FIRST_PIPE_INSTANCE, so if anyone created the name before the engine, the engine refuses to serve
/// (<see cref="PipeNameTakenException"/>, logged as critical) instead of joining a pipe it doesn't own. All instances use
/// PIPE_REJECT_REMOTE_CLIENTS; the instance limit is <see cref="PipeServerOptions.MaxClients"/>.</para>
/// <para><b>Concurrency.</b> At most <see cref="PipeServerOptions.MaxClients"/> connections (the listening instance counts),
/// at most <see cref="PipeServerOptions.MaxConnectionsPerUser"/> per user SID. Each connection runs on its own task
/// (<see cref="PipeConnection"/>).</para>
/// </remarks>
public sealed class EnginePipeServer : BackgroundService
{
    private readonly PipeServerOptions _options;
    private readonly PipeRequestHandler _handler;
    private readonly IClientIdentityResolver _resolver;
    private readonly ILogger _logger;
    private readonly byte[] _securityDescriptor;
    private readonly SemaphoreSlim _slots;
    private readonly Lock _lock = new();
    private readonly Dictionary<SecurityIdentifier, int> _perUser = [];
    private readonly HashSet<Task> _connections = [];
    private readonly TaskCompletionSource _listening = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public EnginePipeServer(IOptions<PipeServerOptions> options, IScanJobService jobs, IQuarantineService quarantine, TimeProvider time,
        ILogger<EnginePipeServer> logger)
        : this(options.Value, jobs, quarantine, time, logger, new PipeClientIdentityResolver(), EnginePipeSecurity.CurrentAccount())
    {
    }

    /// <param name="resolver">Test seam: the identity of each connection. Production always uses <see cref="PipeClientIdentityResolver"/>.</param>
    /// <param name="serverAccount">The account that gets full control besides SYSTEM (the engine's own account).</param>
    internal EnginePipeServer(PipeServerOptions options, IScanJobService jobs, IQuarantineService? quarantine, TimeProvider time, ILogger logger,
        IClientIdentityResolver resolver, SecurityIdentifier? serverAccount, Func<string, int>? driveType = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _handler = new PipeRequestHandler(jobs, quarantine, options, time, logger, driveType);
        _securityDescriptor = EnginePipeSecurity.ToBytes(EnginePipeSecurity.Create(serverAccount));
        _slots = new SemaphoreSlim(options.MaxClients, options.MaxClients);
    }

    /// <summary>Completes when the first instance exists (faults if the pipe couldn't be created).</summary>
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

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        NamedPipeServerStream? listening;
        try
        {
            listening = CreateInstance(first: true);
        }
        catch (Exception ex) when (ex is PipeNameTakenException or IOException)
        {
            _logger.LogCritical("The engine pipe {Pipe} could not be created: {Why} The GUI can't connect.", FullPipeName, ex.Message);
            _listening.TrySetException(ex);
            return;
        }

        _listening.TrySetResult();
        _logger.LogInformation("Engine pipe listening on {Pipe}.", FullPipeName);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await _slots.WaitAsync(stoppingToken).ConfigureAwait(false);
                var instance = listening ?? CreateInstance(first: false);
                listening = null;
                try
                {
                    await instance.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                }
                catch
                {
                    await instance.DisposeAsync().ConfigureAwait(false);
                    _slots.Release();
                    throw;
                }

                Track(instance, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // stopping
        }
        catch (Exception ex) when (ex is IOException or PipeNameTakenException)
        {
            _logger.LogCritical(ex, "The engine pipe stopped accepting clients.");
        }
        finally
        {
            if (listening is not null)
            {
                await listening.DisposeAsync().ConfigureAwait(false);
            }

            Task[] running;
            lock (_lock)
            {
                running = [.. _connections];
            }

            await Task.WhenAll(running).ConfigureAwait(false);
        }
    }

    private void Track(NamedPipeServerStream instance, CancellationToken stoppingToken)
    {
        var connection = new PipeConnection(instance, _handler, _resolver, AcquireUserSlot, _options, _logger, stoppingToken);
        lock (_lock)
        {
            var task = Task.Run(async () =>
            {
                try
                {
                    await connection.RunAsync().ConfigureAwait(false);
                }
                finally
                {
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

    private NamedPipeServerStream CreateInstance(bool first)
    {
        uint openMode = PipeNative.PipeAccessDuplex | PipeNative.FileFlagOverlapped | (first ? PipeNative.FileFlagFirstPipeInstance : 0);
        uint pipeMode = PipeNative.PipeTypeByte | PipeNative.PipeReadModeByte | PipeNative.PipeWait | PipeNative.PipeRejectRemoteClients;
        SafePipeHandle handle = PipeNative.CreatePipe(FullPipeName, openMode, pipeMode, _options.MaxClients, 64 * 1024, _securityDescriptor, out int error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw error is PipeNative.ErrorAccessDenied or PipeNative.ErrorPipeBusy
                ? new PipeNameTakenException($"{FullPipeName} already exists and belongs to someone else (Win32 error {error}).")
                : new IOException($"CreateNamedPipe failed for {FullPipeName} (Win32 error {error}).");
        }

        return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
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
