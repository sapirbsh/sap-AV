using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Pipe;

/// <summary>A non-Ok reply from the engine.</summary>
public sealed class PipeRequestException(PipeStatus status, string? error)
    : Exception($"The engine answered {status}: {error}")
{
    public PipeStatus Status { get; } = status;

    public string? Error { get; } = error;
}

/// <summary>An engine event (for subscribed jobs).</summary>
public sealed record PipeEvent(PipeEventKind Kind, JsonElement Body)
{
    public T Read<T>() => PipeJson.Body<T>(Body);
}

/// <summary>
/// The GUI side of the engine pipe (B4; used by F1). Connect → Hello → typed requests; events arrive on <see cref="Events"/>.
/// </summary>
/// <remarks>
/// <para>The pipe is opened with only the rights it needs (no FILE_CREATE_PIPE_INSTANCE, which the engine's DACL doesn't grant)
/// and at <b>identification</b> impersonation level, so even a fake server can't act as the user. With
/// <c>requireSystemServer</c> (the default), the pipe's owner must be LocalSystem, so a pipe a user created while the
/// service was stopped is refused.</para>
/// <para>Engine frames are capped at <see cref="PipeProtocol.MaxServerFrameBytes"/> and parsed with the same strict options.</para>
/// </remarks>
public sealed class EnginePipeClient : IAsyncDisposable
{
    private const uint ClientAccess = 0x0001 | 0x0002 | 0x0080 | 0x0100 | 0x00020000 | 0x00100000;
    private const uint OpenExisting = 3;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint SecuritySqosPresent = 0x00100000;
    private const uint SecurityIdentification = 0x00010000;
    private const int ErrorPipeBusy = 231;
    private const int ErrorFileNotFound = 2;

    private readonly NamedPipeClientStream _pipe;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<PipeFrame>> _pending = new();
    private readonly Channel<PipeEvent> _events = Channel.CreateBounded<PipeEvent>(new BoundedChannelOptions(1024)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleWriter = true,
    });
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _reader;
    private long _nextId;
    private int _disposed;

    private EnginePipeClient(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
        _reader = Task.Run(ReadLoopAsync);
    }

    /// <summary>Events for subscribed jobs (bounded; the oldest are dropped if nobody reads).</summary>
    public ChannelReader<PipeEvent> Events => _events.Reader;

    /// <summary>The engine's Hello reply.</summary>
    public HelloReply? Hello { get; private set; }

    /// <summary>Test seam: the pipe handle (e.g. to read the pipe's security back).</summary>
    internal SafePipeHandle PipeHandle => _pipe.SafePipeHandle;

    /// <summary>Completes when the connection ended.</summary>
    public Task Completion => _reader;

    /// <summary>Connects and says Hello.</summary>
    /// <param name="requireSystemServer">Refuse a pipe not owned by LocalSystem (turn off only for console runs and tests).</param>
    public static async Task<EnginePipeClient> ConnectAsync(
        string pipeName = PipeProtocol.PipeName, bool requireSystemServer = true, TimeSpan? timeout = null, string clientName = "sap-AV",
        CancellationToken cancellationToken = default)
    {
        var pipe = await OpenAsync(pipeName, timeout ?? TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        if (requireSystemServer && !IsOwnedBySystem(pipe.SafePipeHandle))
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new UnauthorizedAccessException("The engine pipe is not owned by LocalSystem; refusing to talk to it.");
        }

        var client = new EnginePipeClient(pipe);
        try
        {
            client.Hello = await client.SendAsync<HelloReply>(PipeRequestKind.Hello,
                new HelloRequest(PipeProtocol.Version, PipeProtocol.Version, clientName), cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Sends a request and waits for its reply; throws <see cref="PipeRequestException"/> for a non-Ok status.</summary>
    public async Task<T> SendAsync<T>(PipeRequestKind kind, object? body = null, CancellationToken cancellationToken = default)
    {
        var frame = await SendRawAsync(kind, body, cancellationToken).ConfigureAwait(false);
        if (frame.Status != PipeStatus.Ok)
        {
            throw new PipeRequestException(frame.Status ?? PipeStatus.Failed, frame.Error);
        }

        return PipeJson.Body<T>(frame.Body);
    }

    /// <summary>Sends a request with no reply body.</summary>
    public async Task SendAsync(PipeRequestKind kind, object? body = null, CancellationToken cancellationToken = default)
    {
        var frame = await SendRawAsync(kind, body, cancellationToken).ConfigureAwait(false);
        if (frame.Status != PipeStatus.Ok)
        {
            throw new PipeRequestException(frame.Status ?? PipeStatus.Failed, frame.Error);
        }
    }

    /// <summary>Sends a request and returns the reply frame as is (any status).</summary>
    public Task<PipeFrame> SendRawAsync(PipeRequestKind kind, object? body = null, CancellationToken cancellationToken = default)
    {
        long id = Interlocked.Increment(ref _nextId);
        var request = new PipeRequest(id, kind, body is null ? null : JsonSerializer.SerializeToElement(body, body.GetType(), PipeJson.Options));
        return SendBytesAsync(id, PipeJson.Serialize(request, PipeProtocol.MaxRequestBytes), cancellationToken);
    }

    /// <summary>Test seam: sends raw bytes as one frame and waits for the reply to <paramref name="id"/> (null: the next ID-less reply).</summary>
    internal async Task<PipeFrame> SendBytesAsync(long? id, byte[] payload, CancellationToken cancellationToken)
    {
        long key = id ?? 0;
        var waiter = new TaskCompletionSource<PipeFrame>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(key, waiter))
        {
            throw new InvalidOperationException("A request with this ID is already pending.");
        }

        try
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await PipeFraming.WriteAsync(_pipe, payload, int.MaxValue, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }

            return await waiter.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(key, out _);
        }
    }

    // ---- Typed helpers ----

    public Task<ScanCreateReply> CreateScanAsync(IReadOnlyList<string> paths, CancellationToken cancellationToken = default, bool allowRemote = false) =>
        SendAsync<ScanCreateReply>(PipeRequestKind.ScanCreate, new ScanCreateRequest(paths, allowRemote), cancellationToken);

    public Task<JobActionReply> StartScanAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync<JobActionReply>(PipeRequestKind.ScanStart, new JobRequest(jobId), cancellationToken);

    public Task<JobActionReply> PauseScanAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync<JobActionReply>(PipeRequestKind.ScanPause, new JobRequest(jobId), cancellationToken);

    public Task<JobActionReply> ResumeScanAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync<JobActionReply>(PipeRequestKind.ScanResume, new JobRequest(jobId), cancellationToken);

    public Task<JobActionReply> CancelScanAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync<JobActionReply>(PipeRequestKind.ScanCancel, new JobRequest(jobId), cancellationToken);

    public Task<JobDetails> GetScanAsync(Guid jobId, int offset = 0, int limit = 100, CancellationToken cancellationToken = default) =>
        SendAsync<JobDetails>(PipeRequestKind.ScanGet, new ScanGetRequest(jobId, offset, limit), cancellationToken);

    /// <summary>C4: creates a Quick Scan job (administrators only; then <see cref="StartScanAsync"/>).</summary>
    public Task<ScanCreateReply> CreateQuickScanAsync(CancellationToken cancellationToken = default) =>
        SendAsync<ScanCreateReply>(PipeRequestKind.QuickScanCreate, null, cancellationToken);

    /// <summary>C4: a job's phases and one page of its findings.</summary>
    public Task<JobFindingsReply> GetFindingsAsync(Guid jobId, int offset = 0, int limit = 100, CancellationToken cancellationToken = default) =>
        SendAsync<JobFindingsReply>(PipeRequestKind.ScanGetFindings, new ScanFindingsRequest(jobId, offset, limit), cancellationToken);

    public Task<ScanListReply> ListScansAsync(CancellationToken cancellationToken = default) =>
        SendAsync<ScanListReply>(PipeRequestKind.ScanList, null, cancellationToken);

    public Task SubscribeAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync(PipeRequestKind.Subscribe, new JobRequest(jobId), cancellationToken);

    public Task UnsubscribeAsync(Guid jobId, CancellationToken cancellationToken = default) =>
        SendAsync(PipeRequestKind.Unsubscribe, new JobRequest(jobId), cancellationToken);

    public Task<QuarantineListReply> ListQuarantineAsync(CancellationToken cancellationToken = default) =>
        SendAsync<QuarantineListReply>(PipeRequestKind.QuarantineList, null, cancellationToken);

    public Task<RestoreReply> RestoreAsync(string itemId, CancellationToken cancellationToken = default) =>
        SendAsync<RestoreReply>(PipeRequestKind.QuarantineRestore, new QuarantineItemRequest(itemId), cancellationToken);

    public Task<QuarantineFromResultReply> QuarantineResultAsync(Guid jobId, int resultId, CancellationToken cancellationToken = default) =>
        SendAsync<QuarantineFromResultReply>(PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(jobId, resultId), cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _cts.CancelAsync().ConfigureAwait(false);
        await _pipe.DisposeAsync().ConfigureAwait(false);
        try
        {
            await _reader.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // closing
        }

        _cts.Dispose();
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (true)
            {
                var (status, payload) = await PipeFraming.ReadAsync(_pipe, PipeProtocol.MaxServerFrameBytes, _cts.Token).ConfigureAwait(false);
                if (status == PipeFraming.FrameStatus.EndOfStream || payload is null)
                {
                    break;
                }

                var frame = JsonSerializer.Deserialize<PipeFrame>(payload, PipeJson.Options) ?? throw new JsonException("Empty frame.");
                if (frame.Kind == PipeFrameKind.Event && frame.Event is { } kind && frame.Body is { } body)
                {
                    _events.Writer.TryWrite(new PipeEvent(kind, body));
                }
                else if (frame.Kind == PipeFrameKind.Reply && FindWaiter(frame.ReplyTo) is { } waiter)
                {
                    waiter.TrySetResult(frame);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or JsonException
            or PipeProtocolException or ArgumentException)
        {
            // the connection is over (or the engine broke the protocol): fail every waiter below
        }
        finally
        {
            _events.Writer.TryComplete();
            foreach (var waiter in _pending.Values)
            {
                waiter.TrySetException(new IOException("The engine pipe closed."));
            }
        }
    }

    /// <summary>
    /// The waiter for a reply. A reply without an ID (the engine couldn't read the request's ID, or refused the connection
    /// before reading it) goes to an explicit ID-less waiter, else to the only pending request, if there is just one.
    /// </summary>
    private TaskCompletionSource<PipeFrame>? FindWaiter(long? replyTo)
    {
        if (_pending.TryGetValue(replyTo ?? 0, out var waiter))
        {
            return waiter;
        }

        if (replyTo is null)
        {
            var all = _pending.Values.Take(2).ToArray();
            return all.Length == 1 ? all[0] : null;
        }

        return null;
    }

    private static async Task<NamedPipeClientStream> OpenAsync(string pipeName, TimeSpan timeout, CancellationToken cancellationToken)
    {
        string fullName = @"\\.\pipe\" + pipeName;
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var handle = CreateFileW(fullName, ClientAccess, 0, IntPtr.Zero, OpenExisting,
                FileFlagOverlapped | SecuritySqosPresent | SecurityIdentification, IntPtr.Zero);
            if (!handle.IsInvalid)
            {
                return new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, handle);
            }

            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            if (error is not (ErrorPipeBusy or ErrorFileNotFound) || DateTime.UtcNow >= deadline)
            {
                throw new IOException($"Could not connect to {fullName}.", new Win32Exception(error));
            }

            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsOwnedBySystem(SafePipeHandle handle)
    {
        const int SeKernelObject = 6;
        const uint OwnerSecurityInformation = 1;
        if (GetSecurityInfo(handle, SeKernelObject, OwnerSecurityInformation, out IntPtr owner, out _, out _, out _, out IntPtr sd) != 0)
        {
            return false;
        }

        try
        {
            return owner != IntPtr.Zero && new SecurityIdentifier(owner).IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
        finally
        {
            LocalFree(sd);
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafePipeHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr template);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int GetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
