using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Quarantine.Native;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Pipe;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

/// <summary>
/// C1: quarantine visibility by the recorded DACL (section B L3), restored files owned by the requester (section B M3),
/// and counts-only rule warnings for standard users (section B L4).
/// </summary>
public sealed class QuarantineVisibilityAndOwnerTests
{
    private static string Me
    {
        get
        {
            using var me = WindowsIdentity.GetCurrent();
            return me.User!.Value;
        }
    }

    [Theory]
    [InlineData("O:BAG:BAD:(A;;FR;;;{me})", true)]
    [InlineData("O:BAG:BAD:(D;;FR;;;{me})(A;;FA;;;WD)", false)] // a deny entry for the user wins
    [InlineData("D:(A;;FA;;;WD)", false)] // no owner: fails closed
    [InlineData("not an sddl", false)]
    public void StoredDescriptor_IsCheckedWithTheClientsRealToken(string sddl, bool expected)
    {
        using var client = new FakeClientIdentity(new SecurityIdentifier(Me), isAdmin: false); // real AccessCheck with this process's token
        Assert.Equal(expected, ClientAccess.IsGrantedByStoredDescriptor(client, sddl.Replace("{me}", Me, StringComparison.Ordinal), 0x1));
    }

    [Fact]
    public async Task Restore_ThroughThePipe_PassesTheRequester()
    {
        using var h = new HandlerHarness();
        h.Quarantine.Entries.Add(RecordingQuarantine.Entry(Path.Combine(h.Jobs.Root, "restored.bin")));
        var user = h.Session(new FakeClientIdentity());

        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(user, PipeRequestKind.QuarantineRestore, new QuarantineItemRequest("item1"))).Status);

        Assert.Equal(user.Identity.User, Assert.Single(h.Quarantine.RestoreRequesters));
    }

    [Fact]
    public async Task RestoredFile_IsOwnedByTheRequester()
    {
        using var ctx = new QuarantineTestContext();
        var (id, path) = await QuarantineOneAsync(ctx);

        var restored = await ctx.Manager.RestoreAsync(id, requester: QuarantineTestContext.CurrentUser);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        Assert.Equal(QuarantineTestContext.CurrentUser, new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        Assert.Empty(restored.Notes);
    }

    [Fact]
    public async Task GivingTheFileToAnotherUser_UsesSeRestorePrivilegeOnThatThreadOnly_OrRestoresWithANote()
    {
        using var ctx = new QuarantineTestContext();
        var (id, path) = await QuarantineOneAsync(ctx);
        var other = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null); // stands in for another requesting user

        var restored = await ctx.Manager.RestoreAsync(id, requester: other);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        var owner = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier));
        if (restored.Notes.Count == 0)
        {
            Assert.Equal(other, owner); // the process holds SeRestorePrivilege (SYSTEM, an elevated run)
        }
        else
        {
            // A normal test run doesn't hold the privilege: the restore still succeeds, says why, and the file stays the caller's.
            Assert.Contains(restored.Notes, n => n.Contains(other.Value, StringComparison.Ordinal) && n.Contains("1300", StringComparison.Ordinal));
            Assert.Equal(QuarantineTestContext.CurrentUser, owner);
        }
    }

    [Fact]
    public void RestorePrivilege_LeavesNoThreadToken_AndDoesntRunTheActionWithoutThePrivilege()
    {
        bool ran = false;
        int result = RestorePrivilege.Run(() =>
        {
            ran = true;
            Assert.True(RestorePrivilege.ThreadHasToken()); // on a private copy of the token, not the process token
            return 0;
        });

        Assert.False(RestorePrivilege.ThreadHasToken());
        Assert.True(result == 0 ? ran : !ran && result == 1300, $"result {result}, ran {ran}");
    }

    [Fact]
    public async Task RuleErrors_AreCountsOnly_ForAStandardUsersJob_ButNamedForOthers()
    {
        using var h = new ScanJobHarness();
        h.Broker.Rules = new RulesLoadSummary(5, [@"secret-rule.yar: syntax error near 'leaked text'"], 0, "fp", 1, 0);
        h.Preflight = new RulesPreflight(h.Broker, new RecordingAlertSink(), "rules", TimeProvider.System);
        h.Write("a.txt");

        var user = h.Service.Create(new ScanJobRequest([h.Root], ScanTrigger.CustomScan) { Origin = ScanJobOrigin.StandardUser });
        var admin = h.Service.Create(new ScanJobRequest([h.Root], ScanTrigger.CustomScan) { Origin = ScanJobOrigin.Administrator });
        h.Service.Start(user.Id);
        await JobWait.Done(user);
        h.Service.Start(admin.Id);
        await JobWait.Done(admin);

        var userWarning = Assert.Single(user.Warnings).Message;
        Assert.Contains("1 YARA rule file(s) failed to load", userWarning, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-rule", userWarning, StringComparison.Ordinal);
        Assert.Contains("secret-rule.yar", Assert.Single(admin.Warnings).Message, StringComparison.Ordinal);
    }

    private static async Task<(string Id, string Path)> QuarantineOneAsync(QuarantineTestContext ctx)
    {
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("owned.bin", content);
        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        Assert.Equal(QuarantineStatus.Quarantined, result.Status);
        return (result.Entry!.Id, path);
    }
}
