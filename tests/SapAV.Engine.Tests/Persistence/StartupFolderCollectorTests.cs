using SapAV.Core.Persistence;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Persistence;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>Startup folder collection (ROADMAP C2) on a temp folder with synthetic shortcuts built at test time.</summary>
public sealed class StartupFolderCollectorTests : IDisposable
{
    private const string Sid = RegistryTestRoot.UserSid;
    private readonly RegistryTestRoot _root = new();
    private readonly TempDir _folder = new();
    private readonly SetProbe _probe = new();

    public void Dispose()
    {
        _root.Dispose();
        _folder.Dispose();
    }

    private PersistenceCollection Collect(string? sid = null) =>
        _root.Collect(_probe, new StartupFolderSource([(_folder.Path, sid)]));

    private void Write(string name, byte[] content) => File.WriteAllBytes(Path.Combine(_folder.Path, name), content);

    [Fact]
    public void Shortcut_IsResolvedFromTheFile_WithArguments()
    {
        Write("Updater.lnk", new ShellLinkBuilder { IdListPath = @"C:\Users\alice\AppData\Roaming\upd.exe", Arguments = "/background" }.Build());

        var entry = Collect(Sid).Single("Updater.lnk");

        Assert.Equal(PersistenceKind.StartupFolder, entry.Kind);
        Assert.Equal(Sid, entry.UserSid);
        Assert.Equal(_folder.Path, entry.Location);
        Assert.Equal(@"C:\Users\alice\AppData\Roaming\upd.exe", entry.Resolution.TargetPath);
        Assert.Equal("/background", entry.Resolution.Arguments);
        Assert.Equal("T1547.001", entry.TechniqueId);
    }

    [Fact]
    public void ShortcutToAHost_IsUnwrapped_AndMismatchIsFlagged()
    {
        Write("ps.lnk", new ShellLinkBuilder
        {
            IdListPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            LocalBasePath = @"C:\Windows\System32\notepad.exe",
            Arguments = @"-w hidden -File C:\Users\Public\x.ps1",
        }.Build());

        var entry = Collect().Single("ps.lnk");

        Assert.Equal(@"C:\Users\Public\x.ps1", entry.Resolution.TargetPath);
        Assert.Equal(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", entry.Resolution.HostPath);
        Assert.Contains(ResolutionFlag.ShortcutTargetMismatch, entry.Resolution.Flags);
    }

    [Fact]
    public void OtherFiles_AreTheirOwnTarget_DesktopIniAndFoldersAreSkipped()
    {
        Write("run.bat", "@echo off"u8.ToArray());
        Write("desktop.ini", "[.ShellClassInfo]"u8.ToArray());
        Directory.CreateDirectory(Path.Combine(_folder.Path, "sub"));

        var result = Collect();

        var entry = Assert.Single(result.Entries);
        Assert.Equal("run.bat", entry.ValueName);
        Assert.Equal(Path.Combine(_folder.Path, "run.bat"), entry.Resolution.TargetPath);
    }

    [Fact]
    public void BrokenAndNetworkShortcuts_AreReportedUnresolved()
    {
        Write("broken.lnk", [0x4C, 0, 0, 0, 1, 2, 3]);
        Write("share.lnk", new ShellLinkBuilder { NetworkShare = @"\\server\share" }.Build());

        var result = Collect();

        Assert.Equal(TargetUnresolvedReason.ShortcutUnreadable, result.Single("broken.lnk").Resolution.UnresolvedReason);
        var share = result.Single("share.lnk").Resolution;
        Assert.Equal(TargetUnresolvedReason.NetworkPath, share.UnresolvedReason);
        Assert.Contains(ResolutionFlag.RemotePayload, share.Flags);
    }

    [Fact]
    public void ARealShortcutWrittenByTheShell_IsParsed()
    {
        var target = Path.Combine(_folder.Path, "real target.txt");
        File.WriteAllText(target, "x");
        var type = Type.GetTypeFromProgID("WScript.Shell");
        Assert.NotNull(type); // present on every Windows edition the engine supports
        dynamic shell = Activator.CreateInstance(type)!;
        dynamic link = shell.CreateShortcut(Path.Combine(_folder.Path, "real.lnk"));
        link.TargetPath = target;
        link.Arguments = "--flag";
        link.Save();

        var entry = Collect().Single("real.lnk");

        Assert.Equal(target, entry.Resolution.TargetPath, ignoreCase: true);
        Assert.Equal("--flag", entry.Resolution.Arguments);
        Assert.DoesNotContain(ResolutionFlag.ShortcutTargetMismatch, entry.Resolution.Flags);
    }

    [RequiresFact(Requires.Junctions)]
    public void AStartupFolderThatIsAJunction_IsNotFollowed()
    {
        var real = Directory.CreateDirectory(Path.Combine(_folder.Path, "real")).FullName;
        File.WriteAllText(Path.Combine(real, "hidden.bat"), "x");
        var link = Directory.CreateDirectory(Path.Combine(_folder.Path, "link")).FullName;
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + real));

        var result = _root.Collect(_probe, new StartupFolderSource([(link, null)]));

        Assert.Empty(result.Entries);
        Assert.Contains(result.Issues, i => i.Reason == PersistenceIssueReason.LinkNotFollowed);
    }
}
