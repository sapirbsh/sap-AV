using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Persistence;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section C review M3, M4, M5 and the slow-collection finding: one item's problem stays that item's, machine-wide locations
/// come first and users have sub-budgets, listings stop at their caps, sources report what they cost.
/// </summary>
public sealed class CollectionRobustnessTests : IDisposable
{
    private const string Sid = RegistryTestRoot.UserSid;
    private const string OtherSid = "S-1-5-21-1000-2000-3000-1002";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private readonly RegistryTestRoot _root = new();
    private readonly TempDir _folder = new();
    private readonly SetProbe _probe = new();

    public void Dispose()
    {
        _root.Dispose();
        TempDir.DeleteTree(_folder.Path);
    }

    private const string GoodTask = "<Task><Actions><Exec><Command>C:\\Tools\\ok.exe</Command></Exec></Actions></Task>";

    /// <summary>Throws for one file, like a parser hitting an I/O error mid-read.</summary>
    private sealed class ThrowingForOneParser(string pathEnd) : IPersistenceFileParser
    {
        public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken) =>
            displayPath.EndsWith(pathEnd, StringComparison.Ordinal)
                ? throw new IOException("A locked region.")
                : WireTestParser.Instance.ParseAsync(file, kind, displayPath, cancellationToken);
    }

    [Fact]
    public void AFileThatThrowsWhileParsing_OnlyCostsThatFile()
    {
        File.WriteAllText(Path.Combine(_folder.Path, "Locked"), GoodTask);
        File.WriteAllText(Path.Combine(_folder.Path, "Next"), GoodTask);
        File.WriteAllText(Path.Combine(_folder.Path, "Zlast"), GoodTask);

        var result = new PersistenceCollector(_root.View, _probe, [new ScheduledTaskSource(_folder.Path)], parser: new ThrowingForOneParser("Locked")).Collect();

        Assert.Equal(2, result.Entries.Count);
        var issue = Assert.Single(result.Issues);
        Assert.Equal((@"\Locked", PersistenceIssueReason.Malformed), (issue.Location, issue.Reason));
    }

    [Fact]
    public void AFileHeldExclusively_IsAnIssue_AndTheOthersAreCollected()
    {
        File.WriteAllText(Path.Combine(_folder.Path, "Held"), GoodTask);
        File.WriteAllText(Path.Combine(_folder.Path, "Other"), GoodTask);
        using var holder = new FileStream(Path.Combine(_folder.Path, "Held"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var result = _root.Collect(_probe, new ScheduledTaskSource(_folder.Path));

        Assert.Single(result.Entries);
        Assert.Contains(result.Issues, i => i.Location == @"\Held");
    }

    [Fact]
    public void MachineWideEntriesComeFirst_AndAFloodingUser_IsCutOff_WithoutCostingAnyoneElse()
    {
        _root.AddUser(Sid, @"C:\Users\flood", loaded: true);
        _root.AddUser(OtherSid, @"C:\Users\other", loaded: true);
        using (var run = _root.Users($@"{Sid}\{RunKey}"))
        {
            for (int i = 0; i < 20; i++)
            {
                run.SetValue("Flood" + i, $@"C:\f{i}.exe");
            }
        }

        _root.Users($@"{OtherSid}\{RunKey}").SetValue("Other", @"C:\other.exe");
        _root.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").SetValue("Machine", @"C:\machine.exe");
        _root.Machine(@"SYSTEM\CurrentControlSet\Services\Svc").SetValue("ImagePath", @"C:\svc.exe");
        var limits = new PersistenceLimits { MaxEntriesPerUser = 5 };

        var result = new PersistenceCollector(_root.View, _probe, [new RegistryAutorunSource(), new ServiceSource()], limits).Collect();

        Assert.Equal(["Machine", "ImagePath"], result.Entries.Take(2).Select(e => e.ValueName));
        Assert.Equal(5, result.Entries.Count(e => e.UserSid == Sid));
        Assert.Single(result.Entries, e => e.UserSid == OtherSid);
        var cut = Assert.Single(result.Issues, i => i.UserSid is not null && i.Reason == PersistenceIssueReason.LimitReached);
        Assert.Contains("own locations", cut.Message);
    }

    [Fact]
    public void AUsersSubBudget_DoesntStopTheNextUser()
    {
        _root.AddUser(Sid, @"C:\Users\flood", loaded: true);
        _root.AddUser(OtherSid, @"C:\Users\other", loaded: true);
        using (var run = _root.Users($@"{Sid}\{RunKey}"))
        {
            run.SetValue("A", @"C:\a.exe");
            run.SetValue("B", @"C:\b.exe");
            run.SetValue("C", @"C:\c.exe");
        }

        _root.Users($@"{OtherSid}\{RunKey}").SetValue("Other", @"C:\other.exe");

        var result = new PersistenceCollector(_root.View, _probe, [new RegistryAutorunSource()], new PersistenceLimits { MaxEntriesPerUser = 1 }).Collect();

        Assert.Single(result.Entries, e => e.UserSid == OtherSid);
        Assert.Single(result.Entries, e => e.UserSid == Sid);
    }

    [Fact]
    public async Task FilesOfMachineEntries_AreScannedFirst_AndFindingsRankByOutcomeThenScope()
    {
        var user = new PersistenceEntry(PersistenceKind.RunKey, Sid, $@"HKU\{Sid}\{RunKey}", "U", "u", ResolvedCommand.Resolved(@"C:\u.exe"), true);
        var machine = new PersistenceEntry(PersistenceKind.RunKey, null, @"HKLM\" + RunKey, "M", "m", ResolvedCommand.Resolved(@"C:\m.exe"), true);

        Assert.Equal([@"C:\m.exe", @"C:\u.exe"], PersistenceScanner.DistinctFiles([user, machine]));

        var files = Path.Combine(_folder.Path, "malware.exe");
        File.WriteAllText(files, "x");
        PersistenceEntry Entry(string? sid, string value, ResolvedCommand resolution) =>
            new(PersistenceKind.RunKey, sid, sid is null ? @"HKLM\" + RunKey : $@"HKU\{Sid}\{RunKey}", value, "c", resolution, true);
        var collection = new PersistenceCollection(
        [
            Entry(Sid, "UserUnverified", ResolvedCommand.Unresolved(TargetUnresolvedReason.NotFullyQualified)),
            Entry(Sid, "UserBad", ResolvedCommand.Resolved(files)),
            Entry(null, "MachineUnverified", ResolvedCommand.Unresolved(TargetUnresolvedReason.NotFullyQualified)),
            Entry(null, "MachineBad", ResolvedCommand.Resolved(files)),
        ], [], TimeSpan.Zero);

        var scanner = new PersistenceScanner(new FakeScanBroker(), null, TimeProvider.System, NullLogger.Instance,
            new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" }), () => new AdminOnlyWritability());
        var result = await scanner.ScanAsync(collection);

        Assert.Equal(["MachineBad", "UserBad", "MachineUnverified", "UserUnverified"], result.Ranked.Select(f => f.Entry.ValueName));
    }

    [Fact]
    public void ListingStopsAtItsCap_AndSaysSo()
    {
        for (int i = 0; i < 20; i++)
        {
            File.WriteAllText(Path.Combine(_folder.Path, $"f{i}.txt"), "x");
        }

        using var folder = SafeFolderReader.OpenFolder(_folder.Path, out _)!;

        var capped = SafeTree.List(folder, 5, out bool truncated);
        var whole = SafeTree.List(folder, 20, out bool exact);

        Assert.Equal(5, capped.Count);
        Assert.True(truncated);
        Assert.Equal(20, whole.Count);
        Assert.False(exact);
    }

    [Fact]
    public void AnOverfullStartupFolder_ReportsTheCap_AndTheItemsUpToIt()
    {
        for (int i = 0; i < StartupFolderSource.MaxItems + 5; i++)
        {
            File.WriteAllText(Path.Combine(_folder.Path, $"f{i}.bat"), "x");
        }

        var result = _root.Collect(_probe, new StartupFolderSource([(_folder.Path, null)]));

        Assert.Equal(StartupFolderSource.MaxItems, result.Entries.Count);
        Assert.Contains(result.Issues, i => i.Reason == PersistenceIssueReason.LimitReached);
    }

    [Fact]
    public void Collection_ReportsWhatEachSourceCost()
    {
        File.WriteAllText(Path.Combine(_folder.Path, "Daily"), GoodTask);
        _root.AddUser(Sid, @"C:\Users\alice", loaded: true);
        _root.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").SetValue("A", @"C:\a.exe");
        _root.Users($@"{Sid}\{RunKey}").SetValue("B", @"C:\b.exe");

        var result = _root.Collect(_probe, new RegistryAutorunSource(), new ScheduledTaskSource(_folder.Path));

        var registry = result.SourceTimings.Single(t => t.Source == "registry autoruns");
        var tasks = result.SourceTimings.Single(t => t.Source == "scheduled tasks");
        Assert.Equal(2, registry.Entries); // the machine and the user part added up
        Assert.Equal(0, registry.ParsedFiles);
        Assert.Equal((1, 1), (tasks.Entries, tasks.ParsedFiles));
        Assert.Contains("scheduled tasks:", tasks.ToString());
        Assert.True(tasks.Duration >= tasks.ParseTime);
    }

    [Fact]
    public void TheProbe_AnswersFromOneFolderHandle_LikeAFullOpen_AndADeadFolderForEverythingBelowIt()
    {
        var real = Path.Combine(_folder.Path, "real.exe");
        File.WriteAllText(real, "x");
        using var probe = new SafePathProbe();

        Assert.Equal(PathProbeResult.Exists, probe.Probe(real));
        Assert.Equal(PathProbeResult.Exists, probe.Probe(real)); // cached
        Assert.Equal(PathProbeResult.Missing, probe.Probe(Path.Combine(_folder.Path, "gone.exe")));
        Assert.Equal(PathProbeResult.Missing, probe.Probe(Path.Combine(_folder.Path, "nope", "deeper", "gone.exe")));
        Assert.Equal(PathProbeResult.Missing, probe.Probe(Path.Combine(_folder.Path, "nope", "deeper", "gone2.exe")));
        Assert.True(probe.FileExists(real));
        Assert.Equal(PathProbeResult.Missing, probe.Probe(@"\\?\C:\sapav-no-such-file-at-the-root.exe")); // a drive root is a folder too
    }

    [Fact]
    public void TheProbe_ThrowsNothing_PastItsFolderCap()
    {
        using var probe = new SafePathProbe();
        for (int i = 0; i < SafePathProbe.MaxFolders + 10; i++)
        {
            Assert.Equal(PathProbeResult.Missing, probe.Probe(Path.Combine(_folder.Path, "d" + i, "x.exe")));
        }

        var real = Path.Combine(_folder.Path, "real.exe");
        File.WriteAllText(real, "x");
        Assert.Equal(PathProbeResult.Exists, probe.Probe(real));
    }
}
