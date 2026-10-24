using System.IO.Pipes;
using System.Text.Json;
using System.Threading.Channels;
using SapAV.Core.Pipe;

namespace SapAV.Engine.Pipe;

/// <summary>
/// One client connection (B4): framing, timeouts, identity, request loop and the event writer.
/// </summary>
/// <remarks>
/// <para><b>Order.</b> The first frame is read within <see cref="PipeServerOptions.HelloTimeout"/>; only then is the client
/// identified (Windows can't impersonate a pipe client before data was read). A client that can't be identified, or whose
/// user already holds <see cref="PipeServerOptions.MaxConnectionsPerUser"/> connections, gets one error frame and is
/// disconnected. Until Hello succeeds every other request is answered HelloRequired; Hello must succeed in time.</para>
/// <para><b>Hostile input.</b> Requests are handled one at a time. An oversized frame (up to
/// <see cref="PipeProtocol.MaxDrainBytes"/>) is drained and answered TooLarge; unparseable JSON, duplicate keys, unknown
/// members, wrong enum spellings and model validation errors are answered BadRequest. The connection survives all of these.
/// A frame length beyond the drain limit, a truncated frame, or a body that doesn't arrive within
/// <see cref="PipeServerOptions.ReadTimeout"/> end it (the stream can't be trusted to be in sync).</para>
/// <para><b>Output.</b> Replies and events share one write lock; a write that the client doesn't take within
/// <see cref="PipeServerOptions.WriteTimeout"/> ends the connection. Events wait in a bounded queue; when it is full new
/// events are dropped and an EventsDropped event tells the client to resync. Event handlers on the job side only enqueue.</para>
/// </remarks>
internal sealed class PipeConnection : IPipeEventSink
{
    private readonly NamedPipeServerStream _pipe;
    private readonly PipeRequestHandler _handler;
    private readonly IClientIdentityResolver _resolver;
    private readonly Func<IClientIdentity, IDisposable?> _acquireUserSlot;
    private readonly PipeServerOptions _options;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Channel<(PipeEventKind Kind, object Body)> _events;
    private readonly CancellationTokenSource _cts;
    private long _dropped;

    public PipeConnection(
        NamedPipeServerStream pipe, PipeRequestHandler handler, IClientIdentityResolver resolver, Func<IClientIdentity, IDisposable?> acquireUserSlot,
        PipeServerOptions options, ILogger logger, CancellationToken stopping)
    {
        _pipe = pipe;
        _handler = handler;
        _resolver = resolver;
        _acquireUserSlot = acquireUserSlot;
        _options = options;
        _logger = logger;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        _events = Channel.CreateBounded<(PipeEventKind, object)>(
            new BoundedChannelOptions(options.EventQueueCapacity) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true },
            _ => Interlocked.Increment(ref _dropped));
    }

    public bool TryPost(PipeEventKind kind, object body)
    {
        if (_cts.IsCancellationRequested)
        {
            return false;
        }

        long before = Interlocked.Read(ref _dropped);
        return _events.Writer.TryWrite((kind, body)) && Interlocked.Read(ref _dropped) == before;
    }

    public async Task RunAsync()
    {
        var token = _cts.Token;
        PipeSession? session = null;
        IDisposable? userSlot = null;
        Task? writer = null;
        try
        {
            var helloDeadline = DateTime.UtcNow + _options.HelloTimeout;
            var first = await ReadFrameAsync(_options.HelloTimeout, token).ConfigureAwait(false);
            if (first is null)
            {
                return;
            }

            var identity = _resolver.Resolve(_pipe, out string failure);
            if (identity is null)
            {
                _logger.LogWarning("Pipe client refused: {Why}.", failure);
                await WriteReplyAsync(null, PipeReply.Fail(PipeStatus.AccessDenied, "The client could not be identified."), token).ConfigureAwait(false);
                return;
            }

            userSlot = _acquireUserSlot(identity);
            if (userSlot is null)
            {
                identity.Dispose();
                await WriteReplyAsync(null, PipeReply.Fail(PipeStatus.LimitReached, "Too many connections for this user."), token).ConfigureAwait(false);
                return;
            }

            session = new PipeSession(identity, this);
            writer = Task.Run(() => WriteEventsAsync(token), CancellationToken.None);
            var frame = first;
            while (frame is not null)
            {
                if (!await HandleFrameAsync(session, frame.Value, token).ConfigureAwait(false))
                {
                    return;
                }

                TimeSpan wait = !session.HelloDone ? helloDeadline - DateTime.UtcNow
                    : session.HasSubscriptions ? Timeout.InfiniteTimeSpan
                    : _options.IdleTimeout;
                if (!session.HelloDone && wait <= TimeSpan.Zero)
                {
                    return;
                }

                frame = await ReadFrameAsync(wait, token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or PipeProtocolException or TimeoutException)
        {
            _logger.LogDebug("Pipe connection ended: {Why}", ex.GetType().Name);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(ex, "Pipe connection failed unexpectedly.");
        }
        finally
        {
            _cts.Cancel();
            _events.Writer.TryComplete();
            if (session is not null)
            {
                _handler.Disconnected(session);
                session.Dispose();
            }

            if (writer is not null)
            {
                await writer.ConfigureAwait(false);
            }

            userSlot?.Dispose();
            await _pipe.DisposeAsync().ConfigureAwait(false);
            _cts.Dispose();
        }
    }

    /// <summary>A frame (payload, or null payload for a drained oversized frame), or null at a clean end.</summary>
    private async Task<(byte[]? Payload, bool TooLarge)?> ReadFrameAsync(TimeSpan headerTimeout, CancellationToken token)
    {
        int? length;
        using (var header = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            if (headerTimeout != Timeout.InfiniteTimeSpan)
            {
                header.CancelAfter(headerTimeout);
            }

            length = await PipeFraming.ReadHeaderAsync(_pipe, header.Token).ConfigureAwait(false);
        }

        if (length is null)
        {
            return null;
        }

        if (length.Value > PipeProtocol.MaxDrainBytes || length.Value <= 0)
        {
            await WriteReplyAsync(null, PipeReply.Fail(PipeStatus.TooLarge, $"Requests are at most {PipeProtocol.MaxRequestBytes} bytes."), token)
                .ConfigureAwait(false);
            throw new PipeProtocolException("Invalid frame length.");
        }

        using var body = CancellationTokenSource.CreateLinkedTokenSource(token);
        body.CancelAfter(_options.ReadTimeout);
        var (status, payload) = await PipeFraming.ReadBodyAsync(_pipe, length.Value, PipeProtocol.MaxRequestBytes, PipeProtocol.MaxDrainBytes, body.Token)
            .ConfigureAwait(false);
        return (payload, status == PipeFraming.FrameStatus.TooLargeDrained);
    }

    /// <summary>Handles one frame; false to end the connection.</summary>
    private async Task<bool> HandleFrameAsync(PipeSession session, (byte[]? Payload, bool TooLarge) frame, CancellationToken token)
    {
        if (frame.TooLarge || frame.Payload is null)
        {
            await WriteReplyAsync(null, PipeReply.Fail(PipeStatus.TooLarge, $"Requests are at most {PipeProtocol.MaxRequestBytes} bytes."), token)
                .ConfigureAwait(false);
            return true;
        }

        PipeRequest request;
        try
        {
            request = JsonSerializer.Deserialize<PipeRequest>(frame.Payload, PipeJson.Options) ?? throw new JsonException("Empty request.");
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException)
        {
            await WriteReplyAsync(null, PipeReply.Fail(PipeStatus.BadRequest, PipeMapping.Text(ex.Message)), token).ConfigureAwait(false);
            return true;
        }

        PipeReply reply;
        try
        {
            reply = await _handler.HandleAsync(session, request, token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
        {
            _logger.LogError(ex, "Pipe request {Kind} failed.", request.Kind);
            reply = PipeReply.Fail(PipeStatus.Failed, "The engine could not handle the request.");
        }

        await WriteReplyAsync(request.Id, reply, token).ConfigureAwait(false);
        return !(request.Kind == PipeRequestKind.Hello && reply.Status == PipeStatus.UnsupportedVersion);
    }

    private Task WriteReplyAsync(long? replyTo, PipeReply reply, CancellationToken token)
    {
        PipeFrame frame;
        try
        {
            frame = new PipeFrame(PipeFrameKind.Reply, replyTo, reply.Status, reply.Error,
                Body: reply.Body is null ? null : JsonSerializer.SerializeToElement(reply.Body, reply.Body.GetType(), PipeJson.Options));
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "A pipe reply could not be serialized.");
            frame = new PipeFrame(PipeFrameKind.Reply, replyTo, PipeStatus.Failed, "The reply could not be built.");
        }

        return WriteFrameAsync(frame, token);
    }

    private async Task WriteFrameAsync(PipeFrame frame, CancellationToken token)
    {
        byte[] bytes;
        try
        {
            bytes = PipeJson.Serialize(frame, PipeProtocol.MaxServerFrameBytes);
        }
        catch (PipeProtocolException)
        {
            bytes = PipeJson.Serialize(frame with { Status = PipeStatus.Failed, Error = "The reply is too large.", Body = null },
                PipeProtocol.MaxServerFrameBytes);
        }

        await _writeLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(_options.WriteTimeout);
            await PipeFraming.WriteAsync(_pipe, bytes, PipeProtocol.MaxServerFrameBytes, timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            _cts.Cancel(); // a stuck or broken client: end the connection
            throw;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task WriteEventsAsync(CancellationToken token)
    {
        try
        {
            await foreach (var (kind, body) in _events.Reader.ReadAllAsync(token).ConfigureAwait(false))
            {
                long dropped = Interlocked.Exchange(ref _dropped, 0);
                if (dropped > 0)
                {
                    await WriteFrameAsync(Event(PipeEventKind.EventsDropped, new EventsDroppedEvent(dropped)), token).ConfigureAwait(false);
                }

                await WriteFrameAsync(Event(kind, body), token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or PipeProtocolException)
        {
            _cts.Cancel();
        }
    }

    private static PipeFrame Event(PipeEventKind kind, object body) =>
        new(PipeFrameKind.Event, Event: kind, Body: JsonSerializer.SerializeToElement(body, body.GetType(), PipeJson.Options));
}
