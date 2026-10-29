using Microsoft.Win32;
using SapAV.Engine.Persistence;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// C4 Quick Scan sources: the process list seam, per-profile folders from (fake) registry data, the recent-files filter on
/// the listing's own timestamps, cache-folder patterns and the Mark-of-the-Web ranking. Temp files and a throwaway HKCU key only.
/// </summary>
public sealed class QuickScanSourceTests : IDisposable
{
    private readonly TempDir _temp = new();

    public void Dispose() => TempDir.DeleteTree(_temp.Path);

    [Fact]
    public void ProcessImages_AreDedupedCaseInsensitively_AndInaccessibleOnesAreReportedNotCollected()
    {
        var (images, notCollected) = ProcessImageCheck.Summarize(
        [
            new(100, "app", @"C:\Apps\App.exe"),
            new(101, "app", @"c:\apps\app.EXE"),
            new(102, "svc", @"C:\Windows\System32\svchost.exe"),
            new(4, "System", null, "no image file (system process)"),
            new(666, "MsMpEng", null, "access denied (protected process)"),
            new(700, "odd", @"\Device\HarddiskVolume9\x.exe"),
        ]);

        Assert.Equal([@"C:\Apps\App.exe", @"C:\Windows\System32\svchost.exe"], images);
        Assert.Equal([4, 666, 700], notCollected.Select(p => p.ProcessId));
        Assert.All(notCollected, p => Assert.False(string.IsNullOrEmpty(p.Problem)));
    }

    [Fact]
    public void RealProcessSource_FindsThisTestProcess_WithItsImagePath()
    {
        var snapshot = new WindowsProcessSource().Snapshot(CancellationToken.None);

        var self = Assert.Single(snapshot, p => p.ProcessId == Environment.ProcessId);
        Assert.Equal(Environment.ProcessPath, self.ImagePath, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(snapshot, p => p.ProcessId == 4 && p.ImagePath is null); // System: no image, not an error
    }

    [Fact]
    public void ProfileFolders_ComeFromProfileListAndEachUsersShellFolders_NeverTheEnginesEnvironment()
    {
        using var registry = new RegistryTestRoot();
        const string loaded = RegistryTestRoot.UserSid;
        const string unloaded = "S-1-5-21-1000-2000-3000-1002";
        const string redirected = "S-1-5-21-1000-2000-3000-1003";
        using (var env = registry.Machine(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
        {
            env.SetValue("TEMP", @"%SystemRoot%\TEMP", RegistryValueKind.ExpandString);
        }

        using (var list = registry.Machine(RegistryEnvironment.ProfileListPath))
        {
            list.SetValue("ProgramData", @"C:\ProgramData");
            list.SetValue("Public", @"C:\Users\Public");
        }

        registry.AddUser(loaded, @"C:\Users\alice", loaded: true);
        registry.AddUser(unloaded, @"C:\Users\bob", loaded: false);
        registry.AddUser(redirected, @"C:\Users\carol", loaded: true);
        using (var shell = registry.Users($@"{loaded}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            shell.SetValue(RegistryProfileFolders.DownloadsValue, @"%USERPROFILE%\My Downloads", RegistryValueKind.ExpandString);
            shell.SetValue("Desktop", @"%USERPROFILE%\OneDrive\Desktop", RegistryValueKind.ExpandString);
        }

        using (var env = registry.Users($@"{loaded}\Environment"))
        {
            env.SetValue("TEMP", @"%USERPROFILE%\AppData\Local\Temp2", RegistryValueKind.ExpandString);
        }

        using (var shell = registry.Users($@"{redirected}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            shell.SetValue(RegistryProfileFolders.DownloadsValue, @"\\fileserver\carol\Downloads");
        }

        var set = new RegistryProfileFolders(registry.View).Resolve();

        // Review C4 M1: the defaults under the profile always, plus the user's redirections inside their own profile.
        var alice = Assert.Single(set.Users, u => u.Sid == loaded);
        Assert.Equal(@"C:\Users\alice\Downloads", alice.Downloads);
        Assert.Equal([@"C:\Users\alice\Downloads", @"C:\Users\alice\My Downloads"], alice.Folders(UserFolderKind.Downloads));
        Assert.Equal([@"C:\Users\alice\Desktop", @"C:\Users\alice\OneDrive\Desktop"], alice.Folders(UserFolderKind.Desktop));
        Assert.Equal([@"C:\Users\alice\AppData\Local\Temp", @"C:\Users\alice\AppData\Local\Temp2"], alice.Folders(UserFolderKind.Temp));
        Assert.Equal(@"C:\Users\alice\AppData\Roaming", alice.RoamingAppData);

        var bob = Assert.Single(set.Users, u => u.Sid == unloaded); // hive not loaded: the defaults under the profile
        Assert.Equal(@"C:\Users\bob\Downloads", bob.Downloads);
        Assert.Equal(@"C:\Users\bob\AppData\Local\Temp", bob.Temp);

        var carol = Assert.Single(set.Users, u => u.Sid == redirected);
        Assert.Equal([@"C:\Users\carol\Downloads"], carol.Folders(UserFolderKind.Downloads)); // the share is never walked; the default is
        Assert.Contains(set.Notes, n => n.Contains("network share", StringComparison.Ordinal));

        Assert.Equal(@"C:\Windows\TEMP", set.MachineTemp);
        Assert.Equal(@"C:\Users\Public\Downloads", set.PublicDownloads);
        Assert.Equal(@"C:\ProgramData", set.ProgramData);
        Assert.DoesNotContain(set.Users.SelectMany(u => new[] { u.Desktop, u.Downloads, u.Temp }),
            p => p is not null && Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is { Length: > 0 } mine
                && p.StartsWith(mine, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UserRedirections_OutsideTheProfile_ToCDriveWindowsOrAnotherProfile_AreRefused_AndTheDefaultsStay()
    {
        using var registry = new RegistryTestRoot();
        const string sid = RegistryTestRoot.UserSid;
        using (var list = registry.Machine(RegistryEnvironment.ProfileListPath))
        {
            list.SetValue("ProgramData", @"C:\ProgramData");
        }

        registry.AddUser(sid, @"C:\Users\alice", loaded: true);
        using (var shell = registry.Users($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            shell.SetValue("Desktop", @"C:\");
            shell.SetValue(RegistryProfileFolders.DownloadsValue, @"C:\Users\bob\Downloads");
            shell.SetValue("AppData", @"C:\Users\alice\..\bob\AppData\Roaming"); // normalized first: another profile
            shell.SetValue("Local AppData", @"D:\Data\alice"); // the fake owner check says alice owns it
        }

        using (var env = registry.Users($@"{sid}\Environment"))
        {
            env.SetValue("TEMP", @"C:\Windows");
        }

        // The real owner check refuses C:\ and Windows; a fake answers for D:\Data\alice only.
        var policy = new UserFolderPolicy((folder, owner) =>
            owner == sid && folder.Equals(@"D:\Data\alice", StringComparison.OrdinalIgnoreCase) || UserFolderPolicy.IsOwnedOnFixedDrive(folder, owner));
        var set = new RegistryProfileFolders(registry.View, policy: policy).Resolve();

        var alice = Assert.Single(set.Users);
        Assert.Equal([@"C:\Users\alice\Desktop"], alice.Folders(UserFolderKind.Desktop));
        Assert.Equal([@"C:\Users\alice\Downloads"], alice.Folders(UserFolderKind.Downloads));
        Assert.Equal([@"C:\Users\alice\AppData\Roaming"], alice.Folders(UserFolderKind.RoamingAppData));
        Assert.Equal([@"C:\Users\alice\AppData\Local\Temp"], alice.Folders(UserFolderKind.Temp));
        Assert.Equal([@"C:\Users\alice\AppData\Local", @"D:\Data\alice"], alice.Folders(UserFolderKind.LocalAppData));
        Assert.Equal(4, set.Notes.Count(n => n.Contains("outside that user's profile", StringComparison.Ordinal)));
    }

    [Fact]
    public void OwnerCheck_AcceptsAFolderOwnedByTheUser_OnAFixedDrive_FromItsHandle()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_temp.Path, "owned")).FullName;
        var owner = new DirectoryInfo(folder).GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier))!.Value;

        Assert.True(UserFolderPolicy.IsOwnedOnFixedDrive(folder, owner)); // as elevated admin the owner is Administrators: still that SID
        Assert.False(UserFolderPolicy.IsOwnedOnFixedDrive(folder, "S-1-5-21-1-2-3-4242"));
        Assert.False(UserFolderPolicy.IsOwnedOnFixedDrive(Path.Combine(_temp.Path, "missing"), owner));
        Assert.True(UserFolderPolicy.IsInside(@"C:\Users\alice\Sub", @"C:\Users\alice"));
        Assert.False(UserFolderPolicy.IsInside(@"C:\Users\alice2\Sub", @"C:\Users\alice")); // a name prefix isn't inside
    }

    [Fact]
    public void RootDeadlines_SplitThePhasesTimeLeftOverTheRootsLeft()
    {
        Assert.Equal(TimeSpan.FromSeconds(12), ScanJobCheckDeadline(TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(18), 4));
        Assert.Equal(TimeSpan.FromSeconds(18), ScanJobCheckDeadline(TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(18), 1));
        Assert.Equal(TimeSpan.FromSeconds(20), ScanJobCheckDeadline(TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(18), 3)); // nothing left
        Assert.Equal(TimeSpan.MaxValue, ScanJobCheckDeadline(TimeSpan.FromSeconds(1), TimeSpan.MaxValue, 3));
    }

    private static TimeSpan ScanJobCheckDeadline(TimeSpan now, TimeSpan phaseDeadline, int rootsLeft) =>
        ScanJob.RootDeadlineOf(now, phaseDeadline, rootsLeft);

    [Fact]
    public void Placeholders_AreCountedFromTheListing_NotQueued()
    {
        var rules = new QuickScanFileRules(new QuickScanOptions());

        Assert.True(rules.CountPlaceholder(new SafeTreeEntry("cloud.exe", FileAttributes.Offline, 0, 10)));
        Assert.True(rules.CountPlaceholder(new SafeTreeEntry("od.exe", SafeTreeEntry.RecallOnDataAccess | FileAttributes.Archive, 0, 10)));
        Assert.False(rules.CountPlaceholder(new SafeTreeEntry("local.exe", FileAttributes.Archive, 0, 10)));
        Assert.Equal(2, rules.Placeholders);
    }

    [Fact]
    public void IdentityKeys_AreCompactValues_EqualForTheSameObject()
    {
        var a = new SapAV.Core.Scanning.FileIdentity(7, "000102030405060708090a0b0c0d0e0f", @"C:\a");
        var b = new SapAV.Core.Scanning.FileIdentity(7, "000102030405060708090A0B0C0D0E0F", @"C:\other-name");

        Assert.Equal(IdentityKey.Of(a), IdentityKey.Of(b));
        Assert.NotEqual(IdentityKey.Of(a), IdentityKey.Of(a with { VolumeSerialNumber = 8 }));
        var dedupe = new ScanDedupe();
        Assert.True(dedupe.TryClaim(a, out _));
        Assert.False(dedupe.TryClaim(b, out _)); // a hard link / 8.3 spelling of the same object
    }

    [Fact]
    public void RecentFilter_UsesTheNewestListedTime_AgainstTheInjectedClock()
    {
        var old = Path.Combine(_temp.Path, "old.dat");
        var fresh = Path.Combine(_temp.Path, "fresh.dat");
        File.WriteAllText(old, "x");
        File.WriteAllText(fresh, "x");
        File.SetLastWriteTimeUtc(fresh, DateTime.UtcNow.AddDays(29)); // relative to a clock 30 days ahead: 1 day old
        File.SetCreationTimeUtc(fresh, DateTime.UtcNow.AddDays(29));
        var clock = new ManualTime { Now = DateTimeOffset.UtcNow.AddDays(30) };
        var rules = new QuickScanFileRules(new QuickScanOptions { RecentDays = 7 });

        var listed = ListFolder(_temp.Path);

        var cutoff = rules.Cutoff(clock);
        Assert.False(QuickScanFileRules.IsRecent(listed["old.dat"], cutoff)); // every time (also the change time) is ~30 days back
        Assert.True(QuickScanFileRules.IsRecent(listed["fresh.dat"], cutoff));
        Assert.False(QuickScanFileRules.IsRecent(new SafeTreeEntry("unknown.dat", FileAttributes.Normal, 0, 1), cutoff)); // no times: not recent
    }

    [Fact]
    public void SkipPatterns_MatchOneFolderNamePerStar_AndExactFolders()
    {
        var skip = QuickScanFileRules.SkipPredicate([@"C:\Users\a\Downloads"],
            [@"C:\Users\a\AppData\Local\Google\Chrome\User Data\*\Cache"]);

        Assert.True(skip(@"\\?\C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Cache"));
        Assert.True(skip(@"\\?\C:\USERS\A\appdata\local\google\chrome\user data\Profile 1\cache"));
        Assert.True(skip(@"\\?\C:\Users\a\Downloads"));
        Assert.False(skip(@"\\?\C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions")); // only the cache itself
        Assert.False(skip(@"\\?\C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Cache\Sub\Deeper")); // the walk never gets there
        Assert.False(skip(@"\\?\C:\Users\a\Downloads\Sub")); // descendants of a skipped root are never reached
    }

    [Fact]
    public void Rank_PutsDownloadedFilesFirst_ThenExecutables_ArchivesAndOfficeFiles()
    {
        var rules = new QuickScanFileRules(new QuickScanOptions());
        var downloaded = Path.Combine(_temp.Path, "report.pdf");
        File.WriteAllText(downloaded, "x");
        File.WriteAllText(downloaded + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
        foreach (var name in new[] { "tool.exe", "pack.zip", "sheet.xlsm", "notes.txt" })
        {
            File.WriteAllText(Path.Combine(_temp.Path, name), "x");
        }

        using var folder = OpenFolder(_temp.Path);
        int Rank(string name) => rules.Rank(new ScanTreeEntry(Path.Combine(_temp.Path, name), ScanTreeEntryKind.File, Folder: folder, Name: name), probeMotw: true);

        var order = new[] { "notes.txt", "sheet.xlsm", "pack.zip", "tool.exe", "report.pdf" }.OrderBy(Rank).ToArray();

        Assert.Equal(["report.pdf", "tool.exe", "pack.zip", "sheet.xlsm", "notes.txt"], order);
        Assert.True(QuickScanFileRules.HasMarkOfTheWeb(new ScanTreeEntry(downloaded, ScanTreeEntryKind.File, Folder: folder, Name: "report.pdf")));
        Assert.False(QuickScanFileRules.HasMarkOfTheWeb(new ScanTreeEntry("x", ScanTreeEntryKind.File, Folder: folder, Name: "tool.exe")));
    }

    [Fact]
    public void WalkFilter_LimitsDepth_SkipsFolders_AndFiltersFiles_WithCounts()
    {
        Directory.CreateDirectory(Path.Combine(_temp.Path, @"a\b\c"));
        Directory.CreateDirectory(Path.Combine(_temp.Path, "cache"));
        File.WriteAllText(Path.Combine(_temp.Path, "top.exe"), "x");
        File.WriteAllText(Path.Combine(_temp.Path, "top.txt"), "x");
        File.WriteAllText(Path.Combine(_temp.Path, @"a\one.exe"), "x");
        File.WriteAllText(Path.Combine(_temp.Path, @"a\b\two.exe"), "x");
        File.WriteAllText(Path.Combine(_temp.Path, @"a\b\c\three.exe"), "x");
        File.WriteAllText(Path.Combine(_temp.Path, @"cache\hidden.exe"), "x");
        var filter = new ScanWalkFilter
        {
            MaxDepth = 2,
            IncludeFile = e => e.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase),
            SkipFolder = QuickScanFileRules.SkipPredicate([Path.Combine(_temp.Path, "cache")], []),
        };
        var found = new List<string>();

        new ScanTreeWalker(new FolderSet([])).Walk([_temp.Path], e =>
        {
            if (e.Kind == ScanTreeEntryKind.File)
            {
                found.Add(Path.GetFileName(e.Path));
                e.Folder?.Release();
            }
        }, CancellationToken.None, filter: filter);

        Assert.Equal(["one.exe", "top.exe", "two.exe"], found.Order());
        Assert.Equal(1, filter.FilesFiltered);
        Assert.Equal(1, filter.FoldersSkipped);
        Assert.Equal(1, filter.FoldersTooDeep);
    }

    private static Dictionary<string, SafeTreeEntry> ListFolder(string path)
    {
        using var folder = OpenFolder(path);
        return SafeTree.List(folder.Handle).ToDictionary(e => e.Name, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>A listed-folder reference for tests; disposing releases it.</summary>
    private static TestFolder OpenFolder(string path) =>
        new(SafeTree.Open(path, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _) ?? throw new IOException("folder"));

    private sealed class TestFolder(Microsoft.Win32.SafeHandles.SafeFileHandle handle) : IDisposable
    {
        private readonly SharedFolder _folder = new(handle);

        public Microsoft.Win32.SafeHandles.SafeFileHandle Handle => _folder.Handle;

        public static implicit operator SharedFolder(TestFolder folder) => folder._folder;

        public void Dispose() => _folder.Release();
    }
}
