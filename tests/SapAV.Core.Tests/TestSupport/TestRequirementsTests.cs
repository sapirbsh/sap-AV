using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>Self-tests for the conditional-skip machinery (<see cref="TestRequirements"/>).</summary>
public sealed class TestRequirementsTests
{
    [Fact]
    public void SimulatedCleanMachine_ReportsEveryRequirementMissing_WithItsName()
    {
        foreach (var requirement in Enum.GetValues<Requires>())
        {
            var reason = TestRequirements.SkipReason([requirement], simulateCleanMachine: true);

            Assert.NotNull(reason);
            Assert.Contains(requirement.ToString(), reason);
            Assert.Contains(TestRequirements.SimulateCleanMachineVariable, reason);
        }
    }

    [Fact]
    public void EveryRequirement_HasAProbe()
    {
        Assert.Equal(Enum.GetValues<Requires>().OrderBy(r => r), TestRequirements.All.OrderBy(r => r));
    }

    [Fact]
    public void NoRequirements_MeansNoSkip_EvenWhenSimulated()
    {
        Assert.Null(TestRequirements.SkipReason([], simulateCleanMachine: true));
    }

    [Fact]
    public void AntivirusBlockReason_OnlyForAnExplicitBlock()
    {
        const int virusInfected = unchecked((int)0x800700E1);
        var blockedWrite = new IOException("Operation did not complete successfully because the file contains a virus", virusInfected);
        Assert.Contains("blocked writing", TestRequirements.AntivirusBlockReason(blockedWrite, null));

        var blockedRead = new HeuristicResult([], 60, contentInspected: false, "virus", HashFailureReason.BlockedByAntivirus);
        Assert.Contains("blocked reading", TestRequirements.AntivirusBlockReason(null, blockedRead));

        // Anything else must not become a skip: the test then runs and fails loudly.
        Assert.Null(TestRequirements.AntivirusBlockReason(new IOException("disk full"), null));
        Assert.Null(TestRequirements.AntivirusBlockReason(new UnauthorizedAccessException(), null));
        Assert.Null(TestRequirements.AntivirusBlockReason(null, new HeuristicResult([], 60, contentInspected: false, "gone", HashFailureReason.NotFound)));
        Assert.Null(TestRequirements.AntivirusBlockReason(null, new HeuristicResult([], 60, contentInspected: true, null)));
    }

    [Fact]
    public void Attributes_CarrySkipReason_ExactlyWhenARequirementIsUnmet()
    {
        var fact = new RequiresFactAttribute(Requires.Windows11, Requires.SignedDotNetRuntime);
        var theory = new RequiresTheoryAttribute(Requires.Windows11);

        Assert.Equal(TestRequirements.SkipReason([Requires.Windows11, Requires.SignedDotNetRuntime]), fact.Skip);
        Assert.Equal(TestRequirements.SkipReason([Requires.Windows11]), theory.Skip);
    }
}
