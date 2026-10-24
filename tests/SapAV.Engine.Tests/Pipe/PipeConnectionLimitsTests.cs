using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>Review B4 L5 / L6.</summary>
public sealed class PipeConnectionLimitsTests
{
    /// <summary>Wraps the production resolver and keeps what it returned.</summary>
    private sealed class CapturingResolver : IClientIdentityResolver
    {
        private readonly PipeClientIdentityResolver _real = new();

        public TaskCompletionSource<int?> Level { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IClientIdentity? Resolve(NamedPipeServerStream pipe, out string failure)
        {
            var identity = _real.Resolve(pipe, out failure);
            Level.TrySetResult((identity as TokenClientIdentity)?.TokenImpersonationLevel);
            return identity;
        }
    }

    [Fact]
    public async Task AClientThatAllowsImpersonation_IsStillHeldOnlyAtIdentificationLevel()
    {
        var resolver = new CapturingResolver();
        var options = new PipeServerOptions { PipeName = "sap-AV.engine.test." + Guid.NewGuid().ToString("N") };
        using var jobs = new ScanJobHarness();
        using var server = new EnginePipeServer(options, jobs.Service, null, TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, resolver, EnginePipeSecurity.CurrentAccount(), _ => 3);
        await server.StartAsync(CancellationToken.None);
        try
        {
            await using var raw = new NamedPipeClientStream(".", options.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);
            await raw.ConnectAsync(5000);
            await PipeFraming.WriteAsync(raw, Encoding.UTF8.GetBytes("""{"Id":1,"Kind":"Hello","Body":{"MinVersion":1,"MaxVersion":1}}"""),
                PipeProtocol.MaxRequestBytes, default);

            Assert.Equal(1 /* SecurityIdentification */, await resolver.Level.Task.WaitAsync(TimeSpan.FromSeconds(10)));
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task ASubscribedButSilentClient_IsDisconnectedAfterTheSubscribedIdleLimit()
    {
        await using var server = new PipeTestServer(o => o.SubscribedIdleTimeout = TimeSpan.FromMilliseconds(300));
        var client = await server.ConnectAsync(new FakeClientIdentity());
        var created = await client.CreateScanAsync([server.Harness.Root]);
        await client.SubscribeAsync(created.JobId);

        await client.Completion.WaitAsync(TimeSpan.FromSeconds(10));
        await server.WaitForNoConnectionsAsync();
    }

    [Fact]
    public void TheSubscribedIdleLimit_IsLongButFinite_ByDefault()
    {
        var options = new PipeServerOptions();
        Assert.True(options.SubscribedIdleTimeout > options.IdleTimeout);
        Assert.NotEqual(Timeout.InfiniteTimeSpan, options.SubscribedIdleTimeout);
    }
}
