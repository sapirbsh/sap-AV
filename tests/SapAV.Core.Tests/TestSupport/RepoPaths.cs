namespace SapAV.Core.Tests.TestSupport;

/// <summary>Locates the repository (the folder with SapAV.sln) from the test output folder.</summary>
internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    /// <summary><c>data/rules</c> in the repository.</summary>
    public static string RulesDirectory => Path.Combine(Root, "data", "rules");

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "SapAV.sln")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Repository root (SapAV.sln) not found.");
    }
}
