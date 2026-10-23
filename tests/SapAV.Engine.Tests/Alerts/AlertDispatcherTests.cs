using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Engine.Alerts;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Alerts;

/// <summary>B3 / review B1 M4: aggregation, rate limit, summary, and a blocked sink never blocking the caller.</summary>
public sealed class AlertDispatcherTests
{
    private static AlertDispatcher Dispatcher(IAlertSink sink, TimeProvider time, int maxPerWindow = 100, int capacity = 64) =>
        new(sink, time, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), maxPerWindow, capacity);

    [Fact]
    public void SameTypeHashAndPath_IsWrittenOnce_ThenOneSummary()
    {
        var sink = new RecordingAlertSink();
        using var dispatcher = Dispatcher(sink, new ManualTime());

        Assert.True(dispatcher.Post(SampleAlerts.Create(path: @"C:\Users\test\Downloads\a.exe")));
        for (int i = 0; i < 4; i++)
        {
            Assert.False(dispatcher.Post(SampleAlerts.Create(path: @"C:\USERS\test\downloads\A.EXE"))); // same file, other case
        }

        Assert.True(dispatcher.Post(SampleAlerts.Create(path: @"C:\Users\test\Downloads\b.exe")));
        dispatcher.FlushSummary();
        Assert.True(dispatcher.Drain(JobWait.Timeout));

        Assert.Equal(3, sink.Alerts.Count);
        var summary = Assert.Single(sink.Alerts, a => a.Type == AlertType.AlertsSuppressed);
        Assert.StartsWith("4 alert(s) were not written", summary.Reasons[0], StringComparison.Ordinal);
        Assert.Equal(9001, AlertEventCatalog.For(summary.Type).EventId);
    }

    [Fact]
    public void RateLimit_PerWindow_SummaryWhenTheWindowRolls()
    {
        var sink = new RecordingAlertSink();
        var time = new ManualTime();
        using var dispatcher = Dispatcher(sink, time, maxPerWindow: 2);

        var results = Enumerable.Range(0, 4).Select(i => dispatcher.Post(SampleAlerts.Create(path: $@"C:\x\{i}.exe"))).ToArray();
        Assert.Equal([true, true, false, false], results);
        Assert.True(dispatcher.Post(ScanAlerts.RulesDegraded(@"C:\rules", "no rules", Core.Models.ScanTrigger.CustomScan, time.Now), health: true));

        time.Now += TimeSpan.FromMinutes(11);
        Assert.True(dispatcher.Post(SampleAlerts.Create(path: @"C:\x\later.exe")));
        Assert.True(dispatcher.Drain(JobWait.Timeout));

        Assert.Equal(5, sink.Alerts.Count); // 2 + health + summary + later
        Assert.Contains("2 over the limit", Assert.Single(sink.Alerts, a => a.Type == AlertType.AlertsSuppressed).Reasons[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task BlockedSink_NeverBlocksPost_FullQueueIsDroppedAndCounted()
    {
        using var sink = new BlockingAlertSink();
        using var dispatcher = Dispatcher(sink, new ManualTime(), capacity: 2);

        Assert.True(dispatcher.Post(SampleAlerts.Create(path: @"C:\x\first.exe")));
        await sink.Entered.Task.WaitAsync(JobWait.Timeout); // the writer is stuck inside the sink

        // Must return at once even though the sink is hung (a hung Post would time the test out, not hang it).
        var posts = await Task.Run(() => Enumerable.Range(0, 9).Select(i => dispatcher.Post(SampleAlerts.Create(path: $@"C:\x\{i}.exe"))).ToArray())
            .WaitAsync(JobWait.Timeout);
        Assert.Equal(2, posts.Count(p => p));

        sink.Release();
        Assert.True(dispatcher.Drain(JobWait.Timeout));
        Assert.Equal(4, sink.Alerts.Count); // first + 2 queued + summary
        Assert.Contains("7 because the alert queue was full", sink.Alerts[^1].Reasons[0], StringComparison.Ordinal);
    }
}

/// <summary>A sink whose writes hang until released (a hung Event Log RPC).</summary>
internal sealed class BlockingAlertSink : IAlertSink, IDisposable
{
    private readonly ManualResetEventSlim _gate = new(false);

    public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public List<Alert> Alerts { get; } = [];

    public ValueTask WriteAsync(Alert alert, CancellationToken cancellationToken = default)
    {
        Entered.TrySetResult();
        _gate.Wait(JobWait.Timeout);
        lock (Alerts)
        {
            Alerts.Add(alert);
        }

        return ValueTask.CompletedTask;
    }

    public void Release() => _gate.Set();

    public void Dispose()
    {
        _gate.Set();
        _gate.Dispose();
    }
}
