using System.Text;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Guards for the test-data rules: the AV test string must never be stored whole in the repo or in the
/// compiled test assembly, and temp folders must be cleaned up.
/// </summary>
public sealed class TestHygieneTests
{
    private static readonly string[] SkippedDirs = ["bin", "obj", ".git", ".vs", "TestResults", "node_modules"];

    [Fact]
    public void AvTestString_IsNotStoredWhole_InAnyRepoFile()
    {
        var needle = Eicar.Bytes();
        var root = FindRepoRoot();
        var hits = new List<string>();

        foreach (var file in EnumerateRepoFiles(new DirectoryInfo(root)))
        {
            if (file.Length > 50 * 1024 * 1024)
            {
                continue;
            }

            var bytes = File.ReadAllBytes(file.FullName);
            if (bytes.AsSpan().IndexOf(needle) >= 0 ||
                bytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes(Encoding.ASCII.GetString(needle))) >= 0)
            {
                hits.Add(Path.GetRelativePath(root, file.FullName));
            }
        }

        Assert.Empty(hits);
    }

    [Fact]
    public void AvTestString_IsNotStoredWhole_InTestAssembly()
    {
        var needle = Eicar.Bytes();
        var dll = File.ReadAllBytes(typeof(Eicar).Assembly.Location);

        Assert.True(dll.AsSpan().IndexOf(needle) < 0, "ASCII form found in test DLL");
        Assert.True(dll.AsSpan().IndexOf(Encoding.Unicode.GetBytes(Encoding.ASCII.GetString(needle))) < 0,
            "UTF-16 form found in test DLL");
    }

    [Fact]
    public void TempDirectory_IsUnderSapAvTestsFolder_AndDeletedOnDispose()
    {
        string path;
        using (var dir = new TempDirectory())
        {
            path = dir.Path;
            Assert.StartsWith(Path.Combine(Path.GetTempPath(), "sapav-tests"), path);
            Assert.True(Directory.Exists(path));

            dir.WriteFile("a.bin", [1, 2, 3]);
            Directory.CreateDirectory(Path.Combine(path, "nested"));
            File.WriteAllBytes(Path.Combine(path, "nested", "b.bin"), [4]);
        }

        Assert.False(Directory.Exists(path));
    }

    [Fact]
    public void TempDirectory_EachInstanceIsUnique()
    {
        using var a = new TempDirectory();
        using var b = new TempDirectory();

        Assert.NotEqual(a.Path, b.Path);
    }

    private static IEnumerable<FileInfo> EnumerateRepoFiles(DirectoryInfo dir)
    {
        foreach (var file in dir.EnumerateFiles())
        {
            yield return file;
        }

        foreach (var sub in dir.EnumerateDirectories())
        {
            if (SkippedDirs.Contains(sub.Name, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var file in EnumerateRepoFiles(sub))
            {
                yield return file;
            }
        }
    }

    private static string FindRepoRoot()
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
