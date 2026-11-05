using SapAV.Core.Alerts;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section D review H4: a Startup folder value that points off the machine (UNC, WebDAV) or that the user-folder policy refuses
/// is a Suspicious finding (T1547.001), alerted once per value; the remote path is never opened and the scope isn't complete.
/// </summary>
public sealed class UncheckableStartupFolderTests : IDisposable
{
    private const string Alice = MonitorHarness.Alice;
    private const string ShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private readonly MonitorHarness _m = new(registryStartupFolders: true);

    public UncheckableStartupFolderTests() => _m.Registry.AddUser(Alice, Path.Combine(_m.Base, "alice"), loaded: true);

    public void Dispose() => _m.Dispose();

    private Alert[] Uncheckable() =>
        [.. _m.Alerts.Alerts.Where(a => a.Type == AlertType.SuspiciousPersistence && a.Reasons.Any(r => r.StartsWith("Uncheckable Startup folder", StringComparison.Ordinal)))];

    [Theory]
    [InlineData(@"\\attacker.invalid\share\Startup")]
    [InlineData(@"\\attacker.invalid@SSL\DavWWWRoot\Startup")]
    public void AUsersStartupFolderOffTheMachine_IsFlaggedOnce_AndTheScopeIsntComplete(string folder)
    {
        _m.Registry.Users($@"{Alice}\{ShellFolders}").SetValue("Startup", folder);

        _m.Baseline();
        _m.MarkAndRun(new PersistenceScope("startup folders", Alice)); // seen again: no second alert

        var alert = Assert.Single(Uncheckable());
        Assert.Equal(("T1547.001", folder, Alice), (alert.TechniqueId, alert.FilePath, alert.Autostart!.UserSid));
        var collected = _m.Collector.Inner.CollectScoped([new PersistenceScope("startup folders", Alice)]);
        Assert.False(collected.Outcomes[new PersistenceScope("startup folders", Alice)].IsComplete);
    }

    [Fact]
    public void AUsersStartupFolderTheyDontOwn_OutsideTheirProfile_IsFlagged_AndNotListed()
    {
        string elsewhere = Directory.CreateDirectory(Path.Combine(_m.Base, "someone-elses")).FullName;
        File.WriteAllText(Path.Combine(elsewhere, "item.cmd"), "@echo synthetic");
        _m.Registry.Users($@"{Alice}\{ShellFolders}").SetValue("Startup", elsewhere); // owned by this test's account, not by Alice's SID

        _m.Baseline();

        Assert.Single(Uncheckable());
        Assert.DoesNotContain(_m.Collector.Inner.Collect().Entries, e => e.ValueName == "item.cmd");
    }

    [Fact]
    public void TheAllUsersStartupFolderOnAShare_IsFlagged()
    {
        _m.Registry.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders").SetValue("Common Startup", @"\\attacker.invalid\all");

        _m.Baseline();

        var alert = Assert.Single(Uncheckable());
        Assert.Null(alert.Autostart!.UserSid);
    }
}
