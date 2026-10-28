using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// One read-only pass over this machine's real persistence locations (ROADMAP C2). Asserts no specific entry: only that
/// it completes within the Quick Scan budget, finds services, and returns problems as issues instead of throwing.
/// Every Windows machine (and windows-latest) has services, so this needs no skip.
/// </summary>
public class RealMachineCollectionTests
{
    [Fact]
    public void RealMachine_CollectsWithinBudget_AndFindsServices()
    {
        var collector = PersistenceCollector.CreateDefault();

        var result = collector.Collect();

        Assert.True(result.Duration < TimeSpan.FromSeconds(30), $"Collection took {result.Duration}.");
        Assert.DoesNotContain(result.Issues, i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded);
        Assert.True(result.Entries.Count(e => e.Kind == PersistenceKind.Service) > 0);
        Assert.All(result.Entries, e => Assert.True(e.Resolution.TargetPath is null || Path.IsPathFullyQualified(e.Resolution.TargetPath)));
    }
}
