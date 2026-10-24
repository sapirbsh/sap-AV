using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

public sealed class EnginePipeClientTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token;

    [Fact]
    public async Task TypedFlow_CreateSubscribeStartEventsPageAndQuarantine()
    {
        await using var server = new PipeTestServer();
        for (int i = 0; i < 3; i++)
        {
            server.Harness.Write($"mal-{i}.bin");
        }

        server.Harness.Write("clean.txt");
        var client = await server.ConnectAsync(new FakeClientIdentity()); // a standard user with this process's real access

        var created = await client.CreateScanAsync([server.Harness.Root], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        await client.StartScanAsync(created.JobId, Timeout());
        var events = new List<PipeEvent>();
        while (!events.Any(e => e.Kind == PipeEventKind.JobState && e.Read<JobStateEvent>().To == JobState.Completed))
        {
            events.Add(await client.Events.ReadAsync(Timeout()));
        }

        var page1 = await client.GetScanAsync(created.JobId, 0, 2, Timeout());
        var page2 = await client.GetScanAsync(created.JobId, page1.NextResultsOffset!.Value, 2, Timeout());
        var quarantined = await client.QuarantineResultAsync(created.JobId, page1.Results[0].ResultId, Timeout());

        Assert.Equal(3, events.Count(e => e.Kind == PipeEventKind.JobFileResult));
        Assert.Equal(2, page1.Results.Count);
        Assert.Single(page2.Results);
        Assert.Null(page2.NextResultsOffset);
        Assert.All(page1.Results.Concat(page2.Results), r => Assert.Equal(Verdict.Malicious, r.Verdict));
        Assert.True(page1.Results[0].CanQuarantine);
        Assert.Equal(QuarantineOutcome.Quarantined, quarantined.Status);
        Assert.Single(server.Quarantine.Quarantined);
        Assert.True(page1.Summary.OwnedByCaller);
    }

    [Fact]
    public async Task PendingRequests_FailWhenTheEngineGoesAway()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(new FakeClientIdentity());

        await server.Server.StopAsync(CancellationToken.None);

        await client.Completion.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.ThrowsAnyAsync<IOException>(() => client.ListScansAsync(Timeout()));
    }

    [Fact]
    public async Task Errors_AreTypedPipeRequestExceptions()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(new FakeClientIdentity());

        var notFound = await Assert.ThrowsAsync<PipeRequestException>(() => client.StartScanAsync(Guid.NewGuid(), Timeout()));
        var invalid = await Assert.ThrowsAsync<PipeRequestException>(() => client.CreateScanAsync([@"\\evil\share"], Timeout()));

        Assert.Equal(PipeStatus.NotFound, notFound.Status);
        Assert.Equal(PipeStatus.InvalidPath, invalid.Status);
    }
}
