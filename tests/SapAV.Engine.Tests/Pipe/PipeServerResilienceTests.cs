using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>Review B4 H1 / H2 / M1: the accept loop survives hostile clients and never gives the pipe name away.</summary>
public sealed class PipeServerResilienceTests
{
    [Fact]
    public async Task AClientThatLeavesBeforeTheConnectCompletes_DoesNotStopTheServer()
    {
        var gate = new TaskCompletionSource();
        var reached = new TaskCompletionSource();
        await using var server = new PipeTestServer(start: false);
        server.Server.BeforeWaitForConnection = async () =>
        {
            reached.TrySetResult();
            await gate.Task;
        };
        await server.Server.StartAsync(CancellationToken.None);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));

        // Connect and close while the server is not yet in ConnectNamedPipe: it then fails with ERROR_NO_DATA.
        using (var early = RawClient(server))
        {
            await early.ConnectAsync(5000);
        }

        server.Server.BeforeWaitForConnection = null;
        gate.SetResult();
        var client = await server.ConnectAsync(new FakeClientIdentity());

        Assert.NotNull(await client.SendAsync<EngineStatusReply>(PipeRequestKind.GetStatus));
    }

    [Fact]
    public async Task ManyClientsThatConnectAndLeave_LeaveTheServerServing()
    {
        await using var server = new PipeTestServer();
        await server.Server.Listening;
        for (int i = 0; i < 50; i++)
        {
            using var hit = RawClient(server);
            await hit.ConnectAsync(5000);
        }

        var client = await server.ConnectAsync(new FakeClientIdentity());
        Assert.NotNull(await client.SendAsync<EngineStatusReply>(PipeRequestKind.GetStatus));
    }

    [Fact]
    public async Task WithEverySlotInUse_AListeningInstanceStillHoldsTheName()
    {
        await using var server = new PipeTestServer(o => o.MaxClients = 2);
        await server.ConnectAsync(new FakeClientIdentity());
        await server.ConnectAsync(new FakeClientIdentity());
        await WaitAsync(() => server.Server.LiveInstances == 3);

        // A squatter can't take the name: an instance with FIRST_PIPE_INSTANCE fails while the engine holds one.
        var sd = EnginePipeSecurity.ToBytes(EnginePipeSecurity.Create(EnginePipeSecurity.CurrentAccount(), EnginePipeSecurity.CurrentAccount()));
        using (var squat = PipeNative.CreatePipe(server.Server.FullPipeName, PipeNative.PipeAccessDuplex | PipeNative.FileFlagFirstPipeInstance, 0, 8, 4096,
            sd, out int error))
        {
            Assert.True(squat.IsInvalid);
            Assert.Contains(error, new[] { PipeNative.ErrorAccessDenied, PipeNative.ErrorPipeBusy });
        }

        // A third client is refused (no slot) and the name is still held afterwards.
        await Assert.ThrowsAnyAsync<IOException>(() => server.ConnectAsync(new FakeClientIdentity()));
        await WaitAsync(() => server.Server.LiveInstances == 3);
    }

    [Fact]
    public async Task AnInstanceThatJoinsAPipeWithAnotherDacl_IsDetectedAndClosed()
    {
        await using var server = new PipeTestServer(start: false);
        var everyone = new RawAcl(GenericAcl.AclRevision, 1);
        everyone.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, EnginePipeSecurity.FullControl,
            new SecurityIdentifier(WellKnownSidType.WorldSid, null), false, null));
        var attackerSd = EnginePipeSecurity.ToBytes(new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, everyone));
        using var attacker = PipeNative.CreatePipe(server.Server.FullPipeName, PipeNative.PipeAccessDuplex | PipeNative.FileFlagFirstPipeInstance, 0, 8,
            4096, attackerSd, out int attackerError);
        Assert.False(attacker.IsInvalid, $"attacker pipe: Win32 error {attackerError}");

        // As after a drain with a stale count: a non-first create joins the attacker's pipe object; the read-back catches it.
        var joined = server.Server.TryCreateInstance(out var failure, forceFirst: false);

        Assert.Null(joined);
        Assert.IsType<PipeNameTakenException>(failure);
        Assert.Equal(0, server.Server.LiveInstances);
    }

    [Fact]
    public async Task ASquattedName_IsRefused_ThenTakenOverOnceTheSquatterLeaves()
    {
        string name = "sap-AV.engine.test." + Guid.NewGuid().ToString("N");
        var sd = EnginePipeSecurity.ToBytes(EnginePipeSecurity.Create(EnginePipeSecurity.CurrentAccount(), EnginePipeSecurity.CurrentAccount()));
        var squatter = PipeNative.CreatePipe(@"\\.\pipe\" + name, PipeNative.PipeAccessDuplex | PipeNative.FileFlagOverlapped, 0, 8, 4096, sd, out _);
        await using var server = new PipeTestServer(o => o.PipeName = name);
        await Assert.ThrowsAsync<PipeNameTakenException>(() => server.Server.Listening.WaitAsync(TimeSpan.FromSeconds(10)));

        squatter.Dispose();
        server.Resolver.Enqueue(() => new FakeClientIdentity());
        await using var client = await EnginePipeClient.ConnectAsync(name, requireSystemServer: false, TimeSpan.FromSeconds(15));

        Assert.NotNull(client.Hello);
    }

    [Fact]
    public async Task UnidentifiedConnections_AreCapped()
    {
        await using var server = new PipeTestServer(o =>
        {
            o.MaxUnidentifiedConnections = 1;
            o.HelloTimeout = TimeSpan.FromSeconds(10);
        });
        await server.Server.Listening;
        using var silent = RawClient(server);
        await silent.ConnectAsync(5000); // holds the only unidentified slot

        using var second = RawClient(server);
        await second.ConnectAsync(5000);
        var end = await PipeFraming.ReadAsync(second, PipeProtocol.MaxServerFrameBytes, new CancellationTokenSource(10_000).Token);

        Assert.Equal(PipeFraming.FrameStatus.EndOfStream, end.Status);
    }

    [Fact]
    public async Task AFailingEventWriter_EndsOnlyThatConnection_AndReleasesTheUserSlot()
    {
        await using var server = new PipeTestServer(o => o.MaxConnectionsPerUser = 1);
        server.Server.EventFactory = (_, _) => throw new InvalidOperationException("the serializer broke");
        var user = FakeClientIdentity.NewUserSid();
        var client = await server.ConnectAsync(new FakeClientIdentity(user, isAdmin: true));
        var created = await client.CreateScanAsync([server.Harness.Root]);
        await client.SubscribeAsync(created.JobId);
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await client.StartScanAsync(created.JobId); // the reply may or may not beat the failing event
            await client.Completion.WaitAsync(TimeSpan.FromSeconds(10));
            throw new IOException("closed");
        });

        await client.Completion.WaitAsync(TimeSpan.FromSeconds(10));
        await server.WaitForNoConnectionsAsync();
        server.Server.EventFactory = null;
        var again = await server.ConnectAsync(new FakeClientIdentity(user));

        Assert.NotNull(again.Hello);
    }

    [Fact]
    public void Defaults_AreSizedForAsyncConnections()
    {
        var options = new PipeServerOptions();
        Assert.Equal(64, options.MaxClients);
        Assert.Equal(32, options.EffectiveMaxUnidentified);
        Assert.True(options.HelloTimeout <= TimeSpan.FromSeconds(2));
    }

    private static NamedPipeClientStream RawClient(PipeTestServer server) =>
        new(".", server.Options.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);

    private static async Task WaitAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "condition not reached");
            await Task.Delay(20);
        }
    }
}
