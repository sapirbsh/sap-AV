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

    /// <summary>
    /// Opt-in (<c>SAPAV_TEST_ALLOW_HKLM=1</c>): the test may write machine-wide registry keys (e.g. register and remove a
    /// throwaway Event Log source). Needed on top of <see cref="RunningElevated"/> because GitHub Actions
    /// <c>windows-latest</c> runs elevated, and a CI run must not change HKLM.
    /// </summary>
    HklmWritesAllowed,

    /// <summary>A junction can be created in the temp folder (FSCTL_SET_REPARSE_POINT; NTFS).</summary>
    Junctions,

    /// <summary>
    /// Opt-in (<c>SAPAV_TEST_SECOND_VOLUME=X:\some\folder</c>): an existing writable folder on a different volume
    /// than %TEMP%, for the real cross-volume quarantine test. Tests create and remove only a subfolder there.
    /// </summary>
    SecondVolume,

    /// <summary>
    /// The real scan worker starts in a throwaway AppContainer (profile, read/execute grant on the test output's ScanWorker
    /// folder, Job Object) and loads rules. Needs AppContainer support and WRITE_DAC on the build output; the probe removes
    /// its profile and ACL entry again. Expected to work on Windows 10/11 and GitHub Actions windows-latest.
    /// </summary>
    AppContainer,

    /// <summary>
    /// Opt-in (<c>SAPAV_TEST_EICAR_ON_DISK=1</c>, same as SapAV.Core.Tests): the EICAR test file can be written to %TEMP%
    /// and read back (no real antivirus removes it). Off by default because a real antivirus alerts on it.
    /// </summary>
    EicarFileOnDisk,

    /// <summary>
    /// The local administrative share of the temp drive (<c>\\localhost\C$</c>) is reachable from the test process: needs an
    /// elevated administrator and the Server service. Used to exercise the remote-file refusal (A2 W-A) on a real SMB handle.
    /// </summary>
    AdminShare,

    /// <summary>
    /// Opt-in (<c>SAPAV_TEST_SLOW=1</c>): long real-machine runs, e.g. a full Quick Scan of this PC with its per-phase timing
    /// (C4). Off by default so a normal run and CI stay fast.
    /// </summary>
    SlowTests,
}

internal static class TestRequirements
{
    public const string SimulateCleanMachineVariable = "SAPAV_TEST_SIMULATE_CLEAN_MACHINE";

    /// <summary>Set to 1 to allow tests that write HKLM (see <see cref="Requires.HklmWritesAllowed"/>).</summary>
    public const string AllowHklmVariable = "SAPAV_TEST_ALLOW_HKLM";

    /// <summary>Set to 1 to run the long real-machine tests (see <see cref="Requires.SlowTests"/>).</summary>
    public const string SlowTestsVariable = "SAPAV_TEST_SLOW";

    private static readonly Dictionary<Requires, Lazy<string?>> Probes = new()
    {
        [Requires.RunningElevated] = new(ProbeElevated),
        [Requires.HklmWritesAllowed] = new(() => Environment.GetEnvironmentVariable(AllowHklmVariable)?.Trim() == "1"
            ? null
            : $"opt-in: set {AllowHklmVariable}=1 to let the test register and remove a throwaway Event Log source"),
        [Requires.Junctions] = new(ProbeJunctions),
        [Requires.SecondVolume] = new(ProbeSecondVolume),
        [Requires.AppContainer] = new(ProbeAppContainer),
        [Requires.EicarFileOnDisk] = new(ProbeEicarOnDisk),
        [Requires.AdminShare] = new(ProbeAdminShare),
        [Requires.SlowTests] = new(() => Environment.GetEnvironmentVariable(SlowTestsVariable)?.Trim() == "1"
            ? null
            : $"opt-in: set {SlowTestsVariable}=1 to run the long real-machine tests"),
    };

    /// <summary>The <c>\\localhost\X$\…</c> form of a local fully qualified path (valid when <see cref="Requires.AdminShare"/> is met).</summary>
    public static string ToAdminShare(string localPath)
    {
        var full = Path.GetFullPath(localPath);
        return $@"\\localhost\{full[0]}$\{full[3..]}";
    }

    private static string? ProbeAdminShare()
    {
        var temp = Path.GetTempPath();
        if (temp.Length < 3 || temp[1] != ':')
        {
            return "the temp folder isn't on a drive letter";
        }

        return Directory.Exists(ToAdminShare(temp))
            ? null
            : $"{ToAdminShare(temp)} isn't reachable (needs an elevated administrator and the Server service)";
    }

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

    /// <summary>Set to an existing folder on another volume to run the real cross-volume test.</summary>
    public const string SecondVolumeVariable = "SAPAV_TEST_SECOND_VOLUME";

    /// <summary>The <see cref="Requires.SecondVolume"/> folder (valid only when that requirement is met).</summary>
    public static string SecondVolumeFolder => Environment.GetEnvironmentVariable(SecondVolumeVariable)!.Trim();

    private static string? ProbeJunctions()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sapav-tests", "probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(dir, "t")).FullName;
            var why = SapAV.Core.Tests.TestSupport.RawJunction.TryCreate(Path.Combine(dir, "j"), @"\??\" + target);
            return why is null ? null : $"can't create a junction in %TEMP%: {why}";
        }
        finally
        {
            try
            {
                TempDir.DeleteTree(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // best effort
            }
        }
    }

    private static string? ProbeSecondVolume()
    {
        var folder = Environment.GetEnvironmentVariable(SecondVolumeVariable)?.Trim();
        if (string.IsNullOrEmpty(folder))
        {
            return $"opt-in: set {SecondVolumeVariable} to an existing folder on a volume other than %TEMP%'s";
        }

        if (!Directory.Exists(folder) || !Path.IsPathFullyQualified(folder))
        {
            return $"{SecondVolumeVariable}={folder} is not an existing fully qualified folder";
        }

        return string.Equals(Path.GetPathRoot(Path.GetFullPath(folder)), Path.GetPathRoot(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)
            ? $"{SecondVolumeVariable}={folder} is on the same drive as %TEMP%"
            : null;
    }

    public const string EicarOnDiskVariable = "SAPAV_TEST_EICAR_ON_DISK";

    private static string? ProbeEicarOnDisk()
    {
        if (Environment.GetEnvironmentVariable(EicarOnDiskVariable)?.Trim() != "1")
        {
            return $"opt-in: set {EicarOnDiskVariable}=1 to write the EICAR test file to %TEMP% (a real antivirus may alert)";
        }

        var dir = Path.Combine(Path.GetTempPath(), "sapav-tests", "probe-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "probe.txt");
            var bytes = SapAV.Core.Tests.TestSupport.Eicar.Bytes();
            File.WriteAllBytes(path, bytes);
            Thread.Sleep(1000); // give a real-time scanner the chance to act
            return File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes) ? null : "the EICAR test file was changed on disk (by an antivirus?)";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"an antivirus blocked or removed the EICAR test file: {ex.Message}";
        }
        finally
        {
            try
            {
                TempDir.DeleteTree(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // best effort
            }
        }
    }

    private static string? ProbeAppContainer()
    {
        try
        {
            using var container = new TestAppContainer("Probe");
            using var worker = container.Start();
            var response = WorkerTestClient.LoadRulesAsync(worker).GetAwaiter().GetResult();
            worker.Kill();
            return response.Kind == SapAV.Core.Scanning.Isolation.WorkerResponseKind.RulesLoaded
                ? null
                : $"the sandboxed worker answered {response.Kind}: {response.Error}";
        }
        catch (Exception ex)
        {
            return $"the scan worker can't run in an AppContainer here: {ex.GetType().Name}: {ex.Message}";
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

/// <summary>A <see cref="TheoryAttribute"/> that is reported as Skipped when a <see cref="Requires"/> is not met.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class RequiresTheoryAttribute : TheoryAttribute
{
    public RequiresTheoryAttribute(params Requires[] requirements)
    {
        Requirements = requirements;
        if (TestRequirements.SkipReason(requirements) is { } reason)
        {
            Skip = reason;
        }
    }

    public Requires[] Requirements { get; }
}
