using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

public sealed class QuarantineStoreTests
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    [Fact]
    public void NewRoot_HasInheritanceOff_AndOnlyTrustedSids_FilesWithoutExecute()
    {
        // Non-elevated runs trust the test user as well (test seam), otherwise the store couldn't be pinned.
        using var temp = new TempDir();
        var root = Path.Combine(temp.Path, "sap-AV", "Quarantine");

        using (var store = QuarantineStore.Open(root, TrustingPolicy()))
        {
            Assert.Equal(root, store.RootPath, ignoreCase: true);
        }

        AssertRootAcl(root, [System, Admins, QuarantineTestContext.CurrentUser]);
    }

    [RequiresFact(Requires.RunningElevated)]
    public void NewRoot_ProductionPolicy_IsSystemAndAdministratorsOnly()
    {
        using var temp = new TempDir();
        var root = Path.Combine(temp.Path, "sap-AV", "Quarantine");

        using (QuarantineStore.Open(root, QuarantineAccessPolicy.Default))
        {
        }

        AssertRootAcl(root, [System, Admins]);
    }

    [Fact]
    public void ExistingEmptyRootWithWiderAcl_IsFixed()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "Quarantine")).FullName; // inherits from %TEMP%

        using (QuarantineStore.Open(root, TrustingPolicy()))
        {
        }

        AssertRootAcl(root, [System, Admins, QuarantineTestContext.CurrentUser]);
    }

    private static void AssertRootAcl(string root, SecurityIdentifier[] sids)
    {
        var security = new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access);
        Assert.True(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.Equal(sids.Length * 2, rules.Length);
        Assert.All(rules, r =>
        {
            Assert.False(r.IsInherited);
            Assert.Equal(AccessControlType.Allow, r.AccessControlType);
            Assert.Contains(r.IdentityReference, sids);
        });
        Assert.Equal(sids.Length, rules.Count(r => r.InheritanceFlags == InheritanceFlags.None && (int)r.FileSystemRights == QuarantineAccessPolicy.FullControl));
        Assert.Equal(sids.Length, rules.Count(r => r.InheritanceFlags == InheritanceFlags.ObjectInherit
            && r.PropagationFlags == PropagationFlags.InheritOnly && ((int)r.FileSystemRights & 0x20) == 0));
    }

    [Fact]
    public void ExistingNonEmptyRootWithWiderAcl_IsRefused_AndLeftAlone()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "Quarantine")).FullName;
        File.WriteAllBytes(Path.Combine(root, "metadata.key"), [1, 2, 3]); // e.g. planted before the engine ran

        var ex = Assert.Throws<QuarantineStoreException>(() => QuarantineStore.Open(root, QuarantineAccessPolicy.Default));

        Assert.Contains("not empty", ex.Message);
        Assert.False(new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected);
    }

    [RequiresTheory(Requires.Junctions)]
    [InlineData(false)] // the root is a junction
    [InlineData(true)]  // the parent is a junction
    public void RootOrParentReparsePoint_IsRefused(bool parent)
    {
        using var temp = new TempDir();
        var target = Directory.CreateDirectory(Path.Combine(temp.Path, "target", "Quarantine")).FullName;
        var link = Path.Combine(temp.Path, "link");
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + (parent ? Path.GetDirectoryName(target)! : target)));
        var root = parent ? Path.Combine(link, "Quarantine") : link;

        Assert.Throws<QuarantineStoreException>(() => QuarantineStore.Open(root, TrustingPolicy()));
    }

    [Fact]
    public void OpenStore_PinsRoot_SoItCantBeRenamedOrReplaced()
    {
        using var temp = new TempDir();
        var root = Path.Combine(temp.Path, "Quarantine");
        using (QuarantineStore.Open(root, TrustingPolicy()))
        {
            Assert.ThrowsAny<IOException>(() => Directory.Move(root, root + "-moved"));
        }

        Directory.Move(root, root + "-moved"); // released on dispose
    }

    [Fact]
    public void NotFullyQualifiedOrNetworkRoot_IsRefused()
    {
        Assert.Throws<QuarantineStoreException>(() => QuarantineStore.Open(@"relative\Quarantine", TrustingPolicy()));
        Assert.Throws<QuarantineStoreException>(() => QuarantineStore.Open(@"\\server\share\Quarantine", TrustingPolicy()));
    }

    [Fact]
    public void DpapiKey_IsCreatedOnce_ReloadedIdentically_AndATamperedBlobIsRefused()
    {
        using var temp = new TempDir();
        var provider = new DpapiQuarantineKeyProvider();
        var policy = TrustingPolicy();

        var first = provider.GetOrCreateKey(temp.Path, policy);
        var second = provider.GetOrCreateKey(temp.Path, policy);

        Assert.Equal(32, first.Length);
        Assert.Equal(first, second);
        var keyFile = Path.Combine(temp.Path, DpapiQuarantineKeyProvider.KeyFileName);
        Assert.DoesNotContain(Convert.ToHexString(first), Convert.ToHexString(File.ReadAllBytes(keyFile)));

        var blob = File.ReadAllBytes(keyFile);
        blob[^5] ^= 0xFF;
        File.WriteAllBytes(keyFile, blob);
        Assert.Throws<QuarantineStoreException>(() => provider.GetOrCreateKey(temp.Path, policy));
    }

    [Fact]
    public async Task MetadataSignedWithOtherKey_IsInvalidAfterRestart()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(ctx.WriteFile("k.exe", content), content));
        ctx.Manager.Dispose();

        using var other = new QuarantineManager(
            Microsoft.Extensions.Options.Options.Create(new QuarantineOptions { Root = ctx.StoreRoot, AdditionalTrustedSids = [QuarantineTestContext.CurrentUser] }),
            ctx.Alerts, ctx.Log, ctx.Time, new FixedKeyProvider(RandomNumberGenerator.GetBytes(32)));
        var actions = other.Initialize();

        Assert.Contains(actions, a => a.Action.Contains("invalid", StringComparison.Ordinal));
        Assert.Equal(QuarantineEntryIntegrity.Invalid, Assert.Single(other.List()).Integrity);
        Assert.Equal(2, ctx.StoreFiles().Length); // untouched
    }

    private static QuarantineAccessPolicy TrustingPolicy() => new([QuarantineTestContext.CurrentUser]);
}
