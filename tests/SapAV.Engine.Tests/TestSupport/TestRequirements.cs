using System.Security.Principal;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// Things an engine test needs that a normal run or CI doesn't have. Same rules as in SapAV.Core.Tests
/// (<c>TestSupport/TestRequirements.cs</c>): unmet requirements make the test Skipped with a reason, and
/// <c>SAPAV_TEST_SIMULATE_CLEAN_MACHINE=1</c> makes every requirement unmet.
/// </summary>
public enum Requires
{
    /// <summary>
    /// The test process runs elevated (member of Administrators with a full token), e.g. to register a real
    /// Event Log source. Normal <c>dotnet test</c> runs and GitHub Actions don't qualify by design: skip.
    /// </summary>
    RunningElevated,
}

internal static class TestRequirements
{
    public const string SimulateCleanMachineVariable = "SAPAV_TEST_SIMULATE_CLEAN_MACHINE";

    private static readonly Dictionary<Requires, Lazy<string?>> Probes = new()
    {
        [Requires.RunningElevated] = new(ProbeElevated),
    };

    public static IReadOnlyCollection<Requires> All => Probes.Keys;

    public static bool SimulateCleanMachine
    {
        get
        {
            var value = Environment.GetEnvironmentVariable(SimulateCleanMachineVariable)?.Trim();
            return value is not null && (value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase));
        }
    }

    public static string? SkipReason(IEnumerable<Requires> requirements) => SkipReason(requirements, SimulateCleanMachine);

    public static string? SkipReason(IEnumerable<Requires> requirements, bool simulateCleanMachine)
    {
        var unmet = new List<string>();
        foreach (var requirement in requirements.Distinct())
        {
            string? why = simulateCleanMachine
                ? $"simulated clean machine ({SimulateCleanMachineVariable}=1)"
                : Probe(requirement);
            if (why is not null)
            {
                unmet.Add($"{requirement}: {why}");
            }
        }

        return unmet.Count == 0 ? null : "Requirement not met on this machine. " + string.Join("; ", unmet);
    }

    private static string? Probe(Requires requirement)
    {
        try
        {
            return Probes[requirement].Value;
        }
        catch (Exception ex)
        {
            return $"probe failed: {ex.GetType().Name}: {ex.Message}";
        }
    }

    private static string? ProbeElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
            ? null
            : "the test process is not elevated (run the tests from an administrator prompt)";
    }
}

/// <summary>A <see cref="FactAttribute"/> that is reported as Skipped when a <see cref="Requires"/> is not met.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class RequiresFactAttribute : FactAttribute
{
    public RequiresFactAttribute(params Requires[] requirements)
    {
        Requirements = requirements;
        if (TestRequirements.SkipReason(requirements) is { } reason)
        {
            Skip = reason;
        }
    }

    public Requires[] Requirements { get; }
}

/// <summary>Self-tests for the skip machinery.</summary>
public sealed class TestRequirementsTests
{
    [Fact]
    public void EveryRequirement_HasAProbe_AndIsUnmetOnASimulatedCleanMachine()
    {
        Assert.Equal(Enum.GetValues<Requires>().Order(), TestRequirements.All.Order());
        foreach (var requirement in Enum.GetValues<Requires>())
        {
            var reason = TestRequirements.SkipReason([requirement], simulateCleanMachine: true);
            Assert.NotNull(reason);
            Assert.Contains(requirement.ToString(), reason);
        }
    }
}
