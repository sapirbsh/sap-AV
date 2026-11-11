using System.Text.RegularExpressions;

namespace SapAV.Engine.Tests.Defender;

/// <summary>
/// Guard (E5): Defender is only ever read. System.Management may be used only in <c>ManagementWmiReader.cs</c>, that file may
/// not use a WMI API that calls methods or writes (InvokeMethod, Put, Delete, ManagementClass, CreateInstance), and nothing in
/// the engine may name a Defender cmdlet that changes the configuration (Set-MpPreference, Add-MpPreference, Remove-MpPreference).
/// Comment lines are ignored. E11 ("Remove threat") will need a reviewed, separate exception here.
/// </summary>
public sealed partial class DefenderReadOnlyGuardTests
{
    [Fact]
    public void Src_UsesWmiReadOnly_AndOnlyInTheReader()
    {
        // The patterns themselves catch what they are for.
        Assert.Matches(WriteApi(), "using var c = new ManagementClass(scope, path, null); c.InvokeMethod(\"Add\", args);");
        Assert.Matches(WriteApi(), "instance.Put(new PutOptions());");
        Assert.Matches(DefenderWrite(), "\"Add-MpPreference -ExclusionPath C:\\\\\"");

        var src = Path.Combine(FindRepoRoot(), "src");
        var hits = new List<string>();

        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(src, file);
            if (relative.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj"))
            {
                continue;
            }

            bool isReader = Path.GetFileName(file) == "ManagementWmiReader.cs";
            bool isEngine = relative.StartsWith("SapAV.Engine" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
            var lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].TrimStart();
                if (line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith("///", StringComparison.Ordinal))
                {
                    continue;
                }

                // System.Management is confined to the reader, so WMI write APIs can only appear there.
                // Detection rules in Core legitimately name the cmdlets as strings to look for; the engine (SYSTEM) may not.
                if ((isReader && WriteApi().IsMatch(line)) || (isEngine && DefenderWrite().IsMatch(line)) || (!isReader && ManagementUsage().IsMatch(line)))
                {
                    hits.Add($"{relative}:{i + 1}: {line}");
                }
            }
        }

        Assert.Empty(hits);
    }

    [GeneratedRegex(@"\bInvokeMethod\b|\bManagementClass\b|\bMethodData\b|\bCreateInstance\s*\(\s*\)|\bManagementObject\b|\.Put\s*\(|\bPutOptions\b|\bDeleteOptions\b")]
    private static partial Regex WriteApi();

    [GeneratedRegex(@"\b(Set|Add|Remove)-MpPreference\b|""(Set|Add|Remove)""\s*,\s*.*MSFT_Mp", RegexOptions.IgnoreCase)]
    private static partial Regex DefenderWrite();

    [GeneratedRegex(@"\bSystem\.Management\b")]
    private static partial Regex ManagementUsage();

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SapAV.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("SapAV.sln not found above the test output folder.");
    }
}
