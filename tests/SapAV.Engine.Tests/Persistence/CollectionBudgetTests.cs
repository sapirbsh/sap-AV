using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Scanning;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section C follow-up review M6: inside a scan job, the autostart collection gets min(60 s, about a quarter of the job's time
/// left), and the job's pause / cancel / budget apply between sources (paused time doesn't use the collection's budget).
/// </summary>
public sealed class CollectionBudgetTests : IDisposable
{
    private readonly RegistryTestRoot _root = new();

    public void Dispose() => _root.Dispose();

    [Theory]
    [InlineData(180, 45)] // Quick Scan: a quarter of 3 minutes
    [InlineData(600, 60)] // never more than the collector's own limit
    [InlineData(2, 1)] // a floor, however little is left
    [InlineData(10_000_000, 60)] // Full Scan: no budget to speak of
    public void TheBudget_IsAQuarterOfWhatIsLeft_CappedAtTheLimit(int remainingSeconds, int expectedSeconds)
    {
        var budget = PersistenceCheck.CollectionBudget(TimeSpan.FromSeconds(remainingSeconds), TimeSpan.FromSeconds(60));

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), budget);
    }

    [Fact]
    public async Task AQuickScan_GivesTheCollectorItsShare_AndItsCheckpoint()
    {
        using var q = new QuickScanHarness();

        await q.RunAsync();

        var options = q.Collector!.LastOptions!;
        Assert.InRange(options.TimeBudget!.Value, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(45)); // the 3-minute budget's share
        Assert.NotNull(options.Checkpoint);
    }

    [Fact]
    public void TheCheckpoint_RunsBetweenSources_AndPausedTimeDoesntUseTheBudget()
    {
        int checkpoints = 0;
        var sources = new IPersistenceSource[] { new SlowSource("a", TimeSpan.Zero), new SlowSource("b", TimeSpan.Zero), new SlowSource("c", TimeSpan.Zero) };
        var collector = new PersistenceCollector(_root.View, new SetProbe(), sources, parser: WireTestParser.Instance);

        var result = collector.Collect(default, new PersistenceCollectOptions
        {
            TimeBudget = TimeSpan.FromMilliseconds(200),
            Checkpoint = () =>
            {
                checkpoints++;
                Thread.Sleep(150); // the job is paused: 3 x 150 ms is more than the whole budget
            },
        });

        Assert.Equal(3, checkpoints);
        Assert.Equal(["a", "b", "c"], result.Entries.Select(e => e.ValueName));
        Assert.DoesNotContain(result.Issues, i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded);
    }

    [Fact]
    public void TheBudget_StopsTheCollection_AndACancelledCheckpointEndsIt()
    {
        var slow = new IPersistenceSource[] { new SlowSource("a", TimeSpan.FromMilliseconds(300)), new SlowSource("b", TimeSpan.Zero) };
        var collector = new PersistenceCollector(_root.View, new SetProbe(), slow, parser: WireTestParser.Instance);

        var cut = collector.Collect(default, new PersistenceCollectOptions { TimeBudget = TimeSpan.FromMilliseconds(100) });
        Assert.Throws<OperationCanceledException>(() => collector.Collect(default, new PersistenceCollectOptions
        {
            Checkpoint = () => throw new OperationCanceledException("out of budget"),
        }));

        Assert.Equal(["a"], cut.Entries.Select(e => e.ValueName));
        Assert.Contains(cut.Issues, i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded);
    }

    /// <summary>One machine-wide entry, after a delay.</summary>
    private sealed class SlowSource(string name, TimeSpan delay) : IPersistenceSource
    {
        public string Name => name;

        public void CollectMachine(PersistenceContext context)
        {
            if (delay > TimeSpan.Zero)
            {
                Thread.Sleep(delay);
            }

            context.Add(new PersistenceEntry(PersistenceKind.RunKey, null, @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", name, @"C:\Tools\x.exe",
                ResolvedCommand.Resolved(@"C:\Tools\x.exe"), enabled: true));
        }
    }
}
