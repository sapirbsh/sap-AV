using System.Runtime.CompilerServices;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// Guard (section C tester): the suite must never create or change the real engine data folder
/// (<c>%ProgramData%\sap-AV</c>). A C5 test run once created it, owned by the developer, and the real engine then refused
/// it as "untrusted owner". The state is captured when the test assembly loads and compared by
/// <see cref="RealDataRootGuardTests"/>, which runs after every parallel test collection has finished (a collection with
/// <c>DisableParallelization</c> runs last). Compared: existence, creation time and the names directly inside (not file
/// times, so a real engine service running on a dev PC doesn't trip it by writing its own files).
/// </summary>
internal static class RealDataRootSnapshot
{
    public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "sap-AV");

    public static string AtStart { get; } = Capture();

    [ModuleInitializer]
    internal static void Init() => _ = AtStart;

    public static string Capture()
    {
        if (!Directory.Exists(Root))
        {
            return "absent";
        }

        string names;
        try
        {
            names = string.Join(',', Directory.EnumerateFileSystemEntries(Root).Select(Path.GetFileName).Order(StringComparer.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            names = "unreadable";
        }

        return $"exists; created {Directory.GetCreationTimeUtc(Root):O}; entries [{names}]";
    }
}

[CollectionDefinition("RealDataRootGuard", DisableParallelization = true)]
public sealed class RealDataRootGuardCollection;

[Collection("RealDataRootGuard")]
public sealed class RealDataRootGuardTests
{
    [Fact]
    public void RealProgramDataFolder_WasNotCreatedOrChangedByTheSuite()
    {
        Assert.Equal(RealDataRootSnapshot.AtStart, RealDataRootSnapshot.Capture());
    }
}
