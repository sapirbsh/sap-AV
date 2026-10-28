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
    public async Task AUsersOwnFile_IsRestoredToThem()
    {
        using var ctx = new QuarantineTestContext();
        var (id, path) = await QuarantineOneAsync(ctx);
        // The recorded owner is whatever Windows gave the file this process created: the user's own SID normally, but
        // BUILTIN\Administrators when the test runs elevated (the default owner for objects made by an elevated admin,
        // as on GitHub's windows-latest). A probe file created the same way shows which one applies here.
        var expectedOwner = OwnerOfNewFileIn(Path.GetDirectoryName(path)!);

        var restored = await ctx.Manager.RestoreAsync(id, requester: QuarantineTestContext.CurrentUser);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        Assert.Equal(expectedOwner, OwnerOf(path));
        Assert.Empty(restored.Notes);
    }

    /// <summary>
    /// Review C1 H1: an administrator restoring a TrustedInstaller / SYSTEM / Administrators file, or user B restoring user
    /// A's file, never becomes its owner: the recorded original owner is restored. Giving a file to those accounts needs
    /// SeRestorePrivilege (SYSTEM, an elevated run); without it the restore says so and the file is never the requester's.
    /// </summary>
    [Theory]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")] // TrustedInstaller
    [InlineData("S-1-5-18")] // SYSTEM
    [InlineData("S-1-5-32-544")] // Administrators
    [InlineData("S-1-5-21-1111-2222-3333-4444")] // user A
    public async Task TheRecordedOriginalOwner_IsRestored_NeverTheRequester(string originalOwner)
    {
        using var ctx = new QuarantineTestContext();
        var (id, path) = await QuarantineOneAsync(ctx);
        var original = new SecurityIdentifier(originalOwner);
        RewriteRecordedOwner(ctx, id, original);
        var requester = FakeClientIdentity.NewUserSid(); // the admin or user B

        var restored = await ctx.Manager.RestoreAsync(id, requester: requester);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        var owner = OwnerOf(path);
        Assert.NotEqual(requester, owner);
        Assert.DoesNotContain(restored.Notes, n => n.Contains(requester.Value, StringComparison.Ordinal));
        if (restored.Notes.Count == 0)
        {
            Assert.Equal(original, owner); // the process holds SeRestorePrivilege
        }
        else
        {
            Assert.Contains(restored.Notes, n => n.Contains($"the original owner ({original.Value})", StringComparison.Ordinal));
            Assert.Equal(QuarantineTestContext.CurrentUser, owner);
        }
    }

    [Fact]
    public async Task WithNoRecordedOwner_TheFileGoesToTheRequester()
    {
        using var ctx = new QuarantineTestContext();
        var (id, path) = await QuarantineOneAsync(ctx);
        RewriteRecordedOwner(ctx, id, null);
        var requester = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null); // needs SeRestorePrivilege to be made owner

        var restored = await ctx.Manager.RestoreAsync(id, requester: requester);

        Assert.Equal(RestoreStatus.Restored, restored.Status);
        if (restored.Notes.Count == 0)
        {
            Assert.Equal(requester, OwnerOf(path));
        }
        else
        {
            Assert.Contains(restored.Notes, n => n.Contains($"the requesting user ({requester.Value})", StringComparison.Ordinal) && n.Contains("1300", StringComparison.Ordinal));
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
    public void RestorePrivilege_LeavesNoThreadToken_WhenTheActionThrows()
    {
        // SeChangeNotifyPrivilege is held by every token, so the action really runs on the private thread token here.
        Assert.Throws<IOException>(() => RestorePrivilege.Run(() =>
        {
            Assert.True(RestorePrivilege.ThreadHasToken());
            throw new IOException("simulated failure inside the privileged call");
        }, "SeChangeNotifyPrivilege"));

        Assert.False(RestorePrivilege.ThreadHasToken());
    }

    [Fact]
    public void RestorePrivilege_RefusesAnImpersonatingThread_AndLeavesItsTokenAlone()
    {
        using var me = WindowsIdentity.GetCurrent();
        bool ran = false;

        WindowsIdentity.RunImpersonated(me.AccessToken, () =>
        {
            Assert.True(RestorePrivilege.ThreadHasToken());
            Assert.Throws<InvalidOperationException>(() => RestorePrivilege.Run(() => { ran = true; return 0; }, "SeChangeNotifyPrivilege"));
            Assert.True(RestorePrivilege.ThreadHasToken()); // still impersonating: nothing was reverted
        });

        Assert.False(ran);
        Assert.False(RestorePrivilege.ThreadHasToken());
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

    private static SecurityIdentifier OwnerOf(string path) =>
        (SecurityIdentifier)new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier))!;

    private static SecurityIdentifier OwnerOfNewFileIn(string folder)
    {
        var probe = Path.Combine(folder, $"owner-probe-{Guid.NewGuid():N}.tmp");
        File.WriteAllBytes(probe, [0]);
        try { return OwnerOf(probe); }
        finally { File.Delete(probe); }
    }

    /// <summary>Re-signs the item's metadata with another recorded owner (null = none), as if the original file had had it.</summary>
    private static void RewriteRecordedOwner(QuarantineTestContext ctx, string id, SecurityIdentifier? owner)
    {
        string file = Path.Combine(ctx.StoreRoot, id + ".json");
        var metadata = Core.Quarantine.QuarantineMetadataCodec.Decode(File.ReadAllBytes(file), id, ctx.Key);
        var sd = new RawSecurityDescriptor(metadata.SecurityDescriptor!) { Owner = owner };
        var changed = metadata with { SecurityDescriptor = sd.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access) };
        File.WriteAllBytes(file, Core.Quarantine.QuarantineMetadataCodec.Encode(changed, ctx.Key));
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
