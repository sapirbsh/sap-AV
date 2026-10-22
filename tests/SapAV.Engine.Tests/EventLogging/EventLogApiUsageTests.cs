using System.Text.RegularExpressions;

namespace SapAV.Engine.Tests.EventLogging;

/// <summary>
/// Guard: nothing in src/ may use an Event Log API that registers a missing source as a side effect
/// (<c>EventLog.WriteEntry</c> / <c>WriteEvent</c>, an <c>EventLog</c> instance, the ILogger EventLog provider).
/// Registration calls (<c>CreateEventSource</c> / <c>DeleteEventSource</c>) may only appear in
/// <c>WindowsEventLog.cs</c>, which the elevated installer command uses. Comment lines are ignored.
/// </summary>
public sealed partial class EventLogApiUsageTests
{
    [Fact]
    public void Src_UsesNoSourceRegisteringEventLogApi_OutsideTheInstallerWrapper()
    {
        var src = Path.Combine(FindRepoRoot(), "src");
        var hits = new List<string>();

        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(src, file);
            if (relative.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj"))
            {
                continue;
            }

            bool isWrapper = Path.GetFileName(file) == "WindowsEventLog.cs";
            var lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].TrimStart();
                if (line.StartsWith("//", StringComparison.Ordinal))
                {
                    continue;
                }

                if (ForbiddenEverywhere().IsMatch(line) || (!isWrapper && RegistrationCall().IsMatch(line)))
                {
                    hits.Add($"{relative}:{i + 1}: {line}");
                }
            }
        }

        Assert.Empty(hits);
    }

    [GeneratedRegex(@"\.WriteEntry\s*\(|\.WriteEvent\s*\(|new\s+EventLog\s*\(|AddEventLog\s*\(")]
    private static partial Regex ForbiddenEverywhere();

    [GeneratedRegex(@"\b(CreateEventSource|DeleteEventSource)\b")]
    private static partial Regex RegistrationCall();

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
