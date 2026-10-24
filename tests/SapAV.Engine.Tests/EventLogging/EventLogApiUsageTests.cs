using System.Text.RegularExpressions;

namespace SapAV.Engine.Tests.EventLogging;

/// <summary>
/// Guard: nothing in src/ may use an Event Log API that registers a missing source as a side effect
/// (<c>EventLog.WriteEntry</c> / <c>WriteEvent</c>, an <c>EventLog</c> instance, the ILogger EventLog provider).
/// Registration and log-management code (<c>CreateEventSource</c> / <c>DeleteEventSource</c>, the <c>Services\EventLog</c>
/// registry key, <c>EventLogConfiguration</c>, <c>ClearLog</c>, <c>EventLog.Delete</c>) may only appear in
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
            bool isInstaller = isWrapper || Path.GetFileName(file) == "EventLogSourceInstaller.cs";
            var lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].TrimStart();
                if (line.StartsWith("//", StringComparison.Ordinal))
                {
                    continue;
                }

                if (ForbiddenEverywhere().IsMatch(line)
                    || (!isWrapper && (RegistrationCall().IsMatch(line) || LogManagement().IsMatch(line)))
                    || (!isInstaller && WrapperMutation().IsMatch(line)))
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

    /// <summary>B6: the classic-log registry key (any spelling of the separator), the channel config API, clear and delete.</summary>
    [GeneratedRegex(@"Services(\\|\\\\|/)+EventLog\b|\bEventLogConfiguration\b|\bEventLogSession\b|\bEventLog\.Delete\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex LogManagement();

    /// <summary>The HKLM-changing <c>IWindowsEventLog</c> methods: only <c>EventLogSourceInstaller</c> calls them.</summary>
    [GeneratedRegex(@"\.(WriteLogSettings|WriteSource|DeleteSource|DeleteLog|ClearLog)\s*\(")]
    private static partial Regex WrapperMutation();

    [Theory]
    [InlineData(@"var key = @""SYSTEM\CurrentControlSet\Services\EventLog\sap-AV"";")]
    [InlineData(@"var key = ""SYSTEM\\CurrentControlSet\\services\\eventlog"";")]
    [InlineData("using var config = new EventLogConfiguration(name);")]
    [InlineData("EventLogSession.GlobalSession.ClearLog(name);")]
    public void LogManagementPattern_CatchesTheRegistryKeyAndTheLogApis(string line)
    {
        Assert.Matches(LogManagement(), line);
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
