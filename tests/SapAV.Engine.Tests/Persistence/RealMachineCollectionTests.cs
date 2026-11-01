using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// One read-only pass over this machine's real persistence locations (ROADMAP C2), with task definitions and shortcuts parsed
/// by a real worker. Asserts no specific entry: only that it completes within the budget, finds services, and returns problems
/// as issues instead of throwing. Every Windows machine (and windows-latest) has services, so this needs no skip. The
/// per-source timings go to the test output and into any failure message: the elevated CI runner is the only place to see
/// an elevated run's cost, and it is what the slow-collection finding needs.
/// </summary>
public class RealMachineCollectionTests(ITestOutputHelper output)
{
    [Fact]
    public void RealMachine_CollectsWithinBudget_AndFindsServices()
    {
        using var broker = new SandboxedScanBroker(new SandboxOptions
        {
            WorkerPath = TestAppContainer.WorkerExe,
            WorkerCount = 1,
            Isolation = WorkerIsolation.UnsandboxedForTests,
        }, new FakeRulesSource(), NullLogger.Instance);
        var collector = PersistenceCollector.CreateDefault(parser: broker);

        var result = collector.Collect();

        string timings = $"Collected {result.Entries.Count} entries, {result.Issues.Count} issues in {result.Duration}. Sources: "
            + string.Join("; ", result.SourceTimings);
        output.WriteLine(timings);

        Assert.True(result.Duration < new PersistenceLimits().TimeBudget + TimeSpan.FromSeconds(5), timings);
        Assert.False(result.Issues.Any(i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded), "Time budget exceeded. " + timings);
        Assert.True(result.Entries.Any(e => e.Kind == PersistenceKind.Service), "No services. " + timings);
        Assert.All(result.Entries, e => Assert.True(e.Resolution.TargetPath is null || Path.IsPathFullyQualified(e.Resolution.TargetPath)));
    }
}
