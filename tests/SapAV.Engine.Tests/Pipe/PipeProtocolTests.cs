using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using SapAV.Core.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

public sealed class PipeProtocolTests
{
    [Theory]
    [InlineData("not json at all")]
    [InlineData("""{"Id":5,"Kind":"GetStatus","Kind":"ScanList"}""")]
    [InlineData("""{"Id":5,"Kind":"getstatus"}""")]
    [InlineData("""{"Id":5,"Kind":3}""")]
    [InlineData("""{"Id":5,"Kind":"GetStatus","Admin":true}""")]
    [InlineData("""{"Id":0,"Kind":"GetStatus"}""")]
    [InlineData("\u00FF\u00FE")]
    public async Task MalformedRequest_GetsBadRequest_AndTheConnectionSurvives(string payload)
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(new FakeClientIdentity());

        var reply = await client.SendBytesAsync(null, Encoding.UTF8.GetBytes(payload), Timeout());
        var status = await client.SendAsync<EngineStatusReply>(PipeRequestKind.GetStatus, cancellationToken: Timeout());

        Assert.Equal(PipeStatus.BadRequest, reply.Status);
        Assert.Null(reply.ReplyTo);
        Assert.NotNull(status);
    }

    [Theory]
    [InlineData("""{"Id":9,"Kind":"ScanStart","Body":{"JobId":"not-a-guid"}}""")]
    [InlineData("""{"Id":9,"Kind":"ScanStart","Body":{}}""")]
    [InlineData("""{"Id":9,"Kind":"ScanGet","Body":{"JobId":"00000000-0000-0000-0000-000000000001","ResultsLimit":-1}}""")]
    [InlineData("""{"Id":9,"Kind":"ScanList","Body":{"x":1}}""")]
    public async Task BadBody_GetsBadRequestWithTheRequestId(string payload)
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(new FakeClientIdentity());

        var reply = await client.SendBytesAsync(9, Encoding.UTF8.GetBytes(payload), Timeout());
        await client.SendAsync<ScanListReply>(PipeRequestKind.ScanList, cancellationToken: Timeout());

        Assert.Equal(PipeStatus.BadRequest, reply.Status);
        Assert.Equal(9, reply.ReplyTo);
    }

    [Fact]
    public async Task OversizedRequest_IsDrainedAndRefused_TheConnectionSurvives()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(new FakeClientIdentity());
        string huge = "{\"Id\":3,\"Kind\":\"ScanCreate\",\"Body\":{\"Paths\":[\"C:/" + new string('a', 70_000) + "\"]}}";

        var reply = await client.SendBytesAsync(null, Encoding.UTF8.GetBytes(huge), Timeout());
        var status = await client.SendAsync<EngineStatusReply>(PipeRequestKind.GetStatus, cancellationToken: Timeout());

        Assert.Equal(PipeStatus.TooLarge, reply.Status);
        Assert.NotNull(status);
    }

    [Fact]
    public async Task AbsurdFrameLength_IsRefusedAndTheConnectionClosed()
    {
        await using var server = new PipeTestServer();
        await server.Server.Listening;
        server.Resolver.Enqueue(() => new FakeClientIdentity());
        await using var raw = await RawConnectAsync(server);

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, int.MaxValue);
        await raw.WriteAsync(header);
        var (_, payload) = await PipeFraming.ReadAsync(raw, PipeProtocol.MaxServerFrameBytes, Timeout());
        var end = await PipeFraming.ReadAsync(raw, PipeProtocol.MaxServerFrameBytes, Timeout());

        Assert.Contains("TooLarge", Encoding.UTF8.GetString(payload!));
        Assert.Equal(PipeFraming.FrameStatus.EndOfStream, end.Status);
    }

    [Fact]
    public async Task RequestsBeforeHello_AreRefused_AndAWrongVersionEndsTheConnection()
    {
        await using var server = new PipeTestServer();
        await server.Server.Listening;
        server.Resolver.Enqueue(() => new FakeClientIdentity());
        await using var raw = await RawConnectAsync(server);

        await SendAsync(raw, """{"Id":1,"Kind":"ScanList"}""");
        string first = await ReceiveAsync(raw);
        await SendAsync(raw, """{"Id":2,"Kind":"Hello","Body":{"MinVersion":2,"MaxVersion":5}}""");
        string second = await ReceiveAsync(raw);
        var end = await PipeFraming.ReadAsync(raw, PipeProtocol.MaxServerFrameBytes, Timeout());

        Assert.Contains("HelloRequired", first);
        Assert.Contains("UnsupportedVersion", second);
        Assert.Equal(PipeFraming.FrameStatus.EndOfStream, end.Status);
    }

    [Fact]
    public async Task SilentClient_IsDisconnectedAfterTheHelloTimeout()
    {
        await using var server = new PipeTestServer(o => o.HelloTimeout = TimeSpan.FromMilliseconds(300));
        await server.Server.Listening;
        await using var raw = await RawConnectAsync(server);

        var end = await PipeFraming.ReadAsync(raw, PipeProtocol.MaxServerFrameBytes, Timeout());

        Assert.Equal(PipeFraming.FrameStatus.EndOfStream, end.Status);
        await server.WaitForNoConnectionsAsync();
    }

    [Fact]
    public async Task IdleClient_IsDisconnected_AndAHalfSentFrameTimesOut()
    {
        await using var server = new PipeTestServer(o =>
        {
            o.IdleTimeout = TimeSpan.FromMilliseconds(300);
            o.ReadTimeout = TimeSpan.FromMilliseconds(300);
        });
        var idle = await server.ConnectAsync(new FakeClientIdentity());
        await idle.Completion.WaitAsync(TimeSpan.FromSeconds(10));

        server.Resolver.Enqueue(() => new FakeClientIdentity());
        await using var raw = await RawConnectAsync(server);
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, 100);
        await raw.WriteAsync(header); // the body never comes
        var end = await PipeFraming.ReadAsync(raw, PipeProtocol.MaxServerFrameBytes, Timeout());

        Assert.Equal(PipeFraming.FrameStatus.EndOfStream, end.Status);
        await server.WaitForNoConnectionsAsync();
    }

    [Fact]
    public async Task ConnectionsPerUser_AreCapped()
    {
        await using var server = new PipeTestServer(o => o.MaxConnectionsPerUser = 2);
        var user = FakeClientIdentity.NewUserSid();
        await server.ConnectAsync(new FakeClientIdentity(user));
        await server.ConnectAsync(new FakeClientIdentity(user));

        var third = await Assert.ThrowsAsync<PipeRequestException>(() => server.ConnectAsync(new FakeClientIdentity(user)));
        var otherUser = await server.ConnectAsync(new FakeClientIdentity());

        Assert.Equal(PipeStatus.LimitReached, third.Status);
        Assert.NotNull(otherUser.Hello);
    }

    [Fact]
    public async Task ManyClientsAtOnce_AreServed_WithinMaxClients()
    {
        await using var server = new PipeTestServer(o => o.MaxClients = 4);
        var clients = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => server.ConnectAsync(new FakeClientIdentity())));

        var replies = await Task.WhenAll(clients.Select(c => c.SendAsync<EngineStatusReply>(PipeRequestKind.GetStatus, cancellationToken: Timeout())));

        Assert.Equal(3, replies.Length);
        Assert.Equal(3, server.Server.ActiveConnections);
    }

    [Fact]
    public async Task RequestRate_IsLimitedPerUser()
    {
        await using var server = new PipeTestServer(o =>
        {
            o.RequestBurst = 3;
            o.RequestsPerSecond = 0.01;
        });
        var client = await server.ConnectAsync(new FakeClientIdentity()); // Hello uses one token

        await client.SendAsync<ScanListReply>(PipeRequestKind.ScanList, cancellationToken: Timeout());
        await client.SendAsync<ScanListReply>(PipeRequestKind.ScanList, cancellationToken: Timeout());
        var limited = await client.SendRawAsync(PipeRequestKind.ScanList, cancellationToken: Timeout());

        Assert.Equal(PipeStatus.RateLimited, limited.Status);
    }

    [Fact]
    public async Task DisconnectMidStream_DetachesTheSubscription_AndTheJobFinishes()
    {
        await using var server = new PipeTestServer();
        var gate = new TaskCompletionSource();
        server.Harness.Broker.OnScan = async (_, _, ct) =>
        {
            await gate.Task.WaitAsync(ct);
            return null;
        };
        for (int i = 0; i < 5; i++)
        {
            server.Harness.Write($"mal{i}.bin");
        }

        var client = await server.ConnectAsync(new FakeClientIdentity(isAdmin: true));
        var created = await client.CreateScanAsync([server.Harness.Root], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        await client.StartScanAsync(created.JobId, Timeout());
        var first = await client.Events.ReadAsync(Timeout());
        Assert.Equal(PipeEventKind.JobState, first.Kind);

        await client.DisposeAsync();
        await server.WaitForNoConnectionsAsync();
        gate.SetResult();
        var job = server.Harness.Service.Get(created.JobId)!;
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.Equal(5, job.Results.Count);
    }

    [Fact]
    public async Task DisconnectedClient_ItsNeverStartedJobsAreCancelled()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(new FakeClientIdentity(isAdmin: true));
        var created = await client.CreateScanAsync([server.Harness.Root], Timeout());

        await client.DisposeAsync();
        await server.WaitForNoConnectionsAsync();

        Assert.Equal(ScanJobState.Cancelled, server.Harness.Service.Get(created.JobId)!.State);
    }

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;

    private static async Task<NamedPipeClientStream> RawConnectAsync(PipeTestServer server)
    {
        var pipe = new NamedPipeClientStream(".", server.Options.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(10_000);
        }
        catch (UnauthorizedAccessException)
        {
            // GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE, which the DACL grants only to the server account (us, here).
            throw;
        }

        return pipe;
    }

    private static Task SendAsync(Stream stream, string json) =>
        PipeFraming.WriteAsync(stream, Encoding.UTF8.GetBytes(json), PipeProtocol.MaxRequestBytes, Timeout());

    private static async Task<string> ReceiveAsync(Stream stream)
    {
        var (_, payload) = await PipeFraming.ReadAsync(stream, PipeProtocol.MaxServerFrameBytes, Timeout());
        return Encoding.UTF8.GetString(payload!);
    }
}
