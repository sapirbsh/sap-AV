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
    public void Attributes_CarrySkipReason_ExactlyWhenARequirementIsUnmet()
    {
        var fact = new RequiresFactAttribute(Requires.Windows11, Requires.SignedDotNetRuntime);
        var theory = new RequiresTheoryAttribute(Requires.Windows11);

        Assert.Equal(TestRequirements.SkipReason([Requires.Windows11, Requires.SignedDotNetRuntime]), fact.Skip);
        Assert.Equal(TestRequirements.SkipReason([Requires.Windows11]), theory.Skip);
    }
}
