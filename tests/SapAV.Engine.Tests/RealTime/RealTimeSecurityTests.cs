using SapAV.Core.Hashing;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.RealTime;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>
/// D1 security edge cases: a watched folder that is, or becomes, a junction never redirects SYSTEM; events are resolved
/// relative to the watched folder's handle; links under it are never followed. Plus which folders are watched.
/// </summary>
public sealed class RealTimeSecurityTests : IDisposable
{
    private readonly RealTimeHarness _rt = new();

    public void Dispose() => _rt.Dispose();

    private static void Junction(string link, string target) =>
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + target));

    [RequiresFact(Requires.Junctions)]
    public void AFileReachedThroughAJunctionInsideAWatchedFolder_IsNeverOpened()
    {
        File.WriteAllText(Path.Combine(_rt.Outside, "mal-target.exe"), "outside the watched tree");
        Junction(Path.Combine(_rt.Watched, "link"), _rt.Outside);
        _rt.Start();

        _rt.Events.Added(_rt.Watched, @"link\mal-target.exe", "link");

        Assert.Equal(RealTimeOutcome.SkippedLink, _rt.WaitFor("mal-target.exe").Outcome);
        Assert.Equal(RealTimeOutcome.SkippedLink, _rt.WaitFor("link").Outcome);
        Assert.Equal(0, _rt.Broker.Calls);
    }

    [RequiresFact(Requires.Junctions)]
    public void AWatchedFolderThatIsAJunction_IsNotWatched_AndItsTargetIsNeverOpened()
    {
        var link = Path.Combine(_rt.Base, "Downloads-link");
        Junction(link, _rt.Outside);
        _rt.Folders.Folders.Clear();
        _rt.Folders.Folders.Add(new WatchedFolder(link, WatchedFolderKind.Downloads));

        _rt.Start();

        Assert.Equal(0, _rt.Events.Started);
        Assert.Contains("junction", _rt.Monitor.Problems[ExactPath.ToExtended(link)!], StringComparison.Ordinal);
        Assert.Equal(1, _rt.Monitor.Status.RefusedFolders);
    }

    [RequiresFact(Requires.Junctions)]
    public void AWatchedFolderSwappedForAJunction_KeepsResolvingIntoTheOriginalFolder_AndIsDroppedAtRevalidation()
    {
        File.WriteAllText(Path.Combine(_rt.Outside, "mal-swap.exe"), "the junction's target");
        _rt.Write("kept.txt");
        _rt.Start();
        Assert.True(_rt.Events.IsWatching(_rt.Watched));
        var root = _rt.Events.Root(_rt.Watched);

        // The user (or malware) renames the watched folder away and puts a junction to another folder in its place.
        Directory.Move(_rt.Watched, _rt.Watched + ".moved");
        Junction(_rt.Watched, _rt.Outside);
        _rt.Events.Added(_rt.Watched, "mal-swap.exe", "kept.txt");

        // Resolved against the original folder object (now Watched.moved): the target's file isn't there; kept.txt is, but
        // under another path than the event's, so the pipeline refuses to judge it as the requested file.
        Assert.Equal(RealTimeOutcome.Gone, _rt.WaitFor("mal-swap.exe").Outcome);
        var kept = _rt.WaitFor("kept.txt");
        Assert.Equal(ScanSkipReason.DifferentFile, kept.Scan?.SkipReason);
        Assert.Equal(0, _rt.Broker.Calls);

        _rt.Monitor.Revalidate();

        Assert.True(root.Closed);
        Assert.False(_rt.Events.IsWatching(_rt.Watched));
        Assert.Contains("junction", _rt.Monitor.Problems[ExactPath.ToExtended(_rt.Watched)!], StringComparison.Ordinal);
        Directory.Delete(_rt.Watched); // the junction itself (not its target)
    }

    [Fact]
    public void WatchedFolders_AreEveryProfilesDownloadsDesktopDocumentsTempAndStartup_PlusMachineFolders_OutermostOnly()
    {
        var alice = new UserFolders("S-1-5-21-1-2-3-1001", @"C:\Users\alice", @"C:\Users\alice\Desktop", @"C:\Users\alice\Downloads",
            @"C:\Users\alice\AppData\Local\Temp", @"C:\Users\alice\AppData\Roaming", @"C:\Users\alice\AppData\Local")
        {
            Documents = @"C:\Users\alice\Documents",
            Redirected = [new RedirectedFolder(UserFolderKind.Desktop, @"C:\Users\alice\OneDrive\Desktop"), new RedirectedFolder(UserFolderKind.Downloads, @"C:\Users\alice\Desktop\dl")],
        };
        var set = new ProfileFolderSet([alice], @"C:\Windows\Temp", @"C:\Users\Public\Desktop", @"C:\Users\Public\Downloads", @"C:\ProgramData",
            ["Downloads of S-1-5-21-1-2-3-1002 is on a network share; the engine doesn't scan network locations."])
        {
            Public = @"C:\Users\Public",
        };
        var options = new RealTimeOptions { ExtraFolders = [@"D:\Drop", @"\\server\share\in", @"C:\Users\alice\Documents\Projects"] };

        var resolved = new ProfileWatchedFolders(new FixedProfiles(set), options).Resolve();

        Assert.Equal(
        [
            @"C:\Users\alice\Downloads", @"C:\Users\alice\Desktop", @"C:\Users\alice\OneDrive\Desktop", @"C:\Users\alice\Documents",
            @"C:\Users\alice\AppData\Local\Temp", @"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            @"C:\Windows\Temp", @"C:\Users\Public", @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", @"D:\Drop",
        ], resolved.Folders.Select(f => f.Path));
        Assert.All(resolved.Folders.Take(6), f => Assert.Equal(alice.Sid, f.Sid));
        Assert.Contains(resolved.Notes, n => n.Contains("network share", StringComparison.Ordinal)); // the share is never watched
        Assert.Equal(2, resolved.Notes.Count);

        Assert.Single(new ProfileWatchedFolders(new FixedProfiles(set), new RealTimeOptions { MaxWatchedFolders = 1 }).Resolve().Folders);
        Assert.Equal([@"D:\Drop"], new ProfileWatchedFolders(new FixedProfiles(set), new RealTimeOptions { WatchDefaultFolders = false, ExtraFolders = [@"D:\Drop"] })
            .Resolve().Folders.Select(f => f.Path));
    }

    [Fact]
    public void ProfileFolders_ResolveDocumentsAndPublic_WithTheSameRedirectionPolicy()
    {
        using var registry = new Persistence.RegistryTestRoot();
        const string sid = Persistence.RegistryTestRoot.UserSid;
        using (var list = registry.Machine(SapAV.Engine.Persistence.RegistryEnvironment.ProfileListPath))
        {
            list.SetValue("Public", @"C:\Users\Public");
        }

        registry.AddUser(sid, @"C:\Users\alice", loaded: true);
        using (var shell = registry.Users($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
        {
            shell.SetValue("Personal", @"%USERPROFILE%\OneDrive\Documents", Microsoft.Win32.RegistryValueKind.ExpandString);
        }

        var set = new RegistryProfileFolders(registry.View).Resolve();

        var alice = Assert.Single(set.Users);
        Assert.Equal([@"C:\Users\alice\Documents", @"C:\Users\alice\OneDrive\Documents"], alice.Folders(UserFolderKind.Documents));
        Assert.Equal(@"C:\Users\Public", set.Public);
    }

    private sealed class FixedProfiles(ProfileFolderSet set) : IProfileFolderSource
    {
        public ProfileFolderSet Resolve() => set;
    }
}
