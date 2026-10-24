using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

/// <summary>
/// Review B H1 (ROADMAP D3 M3 / M-B): <c>%ProgramData%\sap-AV</c> is created with the protected SYSTEM + Administrators DACL,
/// fixed only when nothing a user could have planted is in it, and refused otherwise. Temp roots stand in for ProgramData;
/// non-elevated runs trust the test user too (test seam), so the folders stay usable and deletable.
/// </summary>
public sealed class EngineDataRootTests
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static QuarantineAccessPolicy TrustingPolicy() => new([QuarantineTestContext.CurrentUser]);

    private static void AssertDataRootAcl(string root, SecurityIdentifier[] sids)
    {
        var security = new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access);
        Assert.True(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.Equal(sids.Length, rules.Length);
        Assert.All(rules, r =>
        {
            Assert.False(r.IsInherited);
            Assert.Equal(AccessControlType.Allow, r.AccessControlType);
            Assert.Contains(r.IdentityReference, sids);
            Assert.Equal(QuarantineAccessPolicy.FullControl, (int)r.FileSystemRights);
            Assert.Equal(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, r.InheritanceFlags);
        });
    }

    [Fact]
    public void NewRoot_IsCreatedWithTheProtectedDacl_AndWhatIsCreatedInsideInheritsOnlyThat()
    {
        using var temp = new TempDir();
        var root = Path.Combine(temp.Path, "sap-AV");

        EngineDataRoot.Ensure(root, TrustingPolicy());
        EngineDataRoot.Ensure(root, TrustingPolicy()); // idempotent

        AssertDataRootAcl(root, [System, Admins, QuarantineTestContext.CurrentUser]);
        var child = Directory.CreateDirectory(Path.Combine(root, "later")).GetAccessControl(AccessControlSections.Access);
        Assert.All(child.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            r => Assert.Contains(r.IdentityReference, new[] { System, Admins, QuarantineTestContext.CurrentUser }));
    }

    [RequiresFact(Requires.RunningElevated)]
    public void NewRoot_ProductionPolicy_IsSystemAndAdministratorsOnly()
    {
        using var temp = new TempDir();
        var root = Path.Combine(temp.Path, "sap-AV");

        EngineDataRoot.Ensure(root, QuarantineAccessPolicy.Default);

        AssertDataRootAcl(root, [System, Admins]);
    }

    [Fact]
    public void PreCreatedEmptyRoot_WithTheInheritedAcl_IsFixed()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV")).FullName; // inherits, like a user-made one

        EngineDataRoot.Ensure(root, TrustingPolicy());

        AssertDataRootAcl(root, [System, Admins, QuarantineTestContext.CurrentUser]);
    }

    [Fact]
    public void PreCreatedRoot_WithAUserAclAndContent_IsRefused_AndLeftAsItWas()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV")).FullName;
        var planted = Path.Combine(root, "x", "dropped.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(planted)!);
        File.WriteAllText(planted, "planted before the engine ran");

        var ex = Assert.Throws<QuarantineStoreException>(() => EngineDataRoot.Ensure(root, TrustingPolicy()));

        Assert.Contains("'x'", ex.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(planted)); // never deleted
        Assert.False(new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected); // left as it was
        Assert.Throws<QuarantineStoreException>(() => EngineDataRoot.Ensure(root, TrustingPolicy())); // stays refused
    }

    [Fact]
    public void PreCreatedRoot_HoldingOnlyVerifiedEngineSubfolders_IsFixed()
    {
        // An install from before the fix: the root inherited ProgramData's ACL, but its Quarantine and Sandbox folders were
        // created by the engine with the protected DACL, so nothing in them can have been planted.
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV")).FullName;
        QuarantineStore.Open(Path.Combine(root, "Quarantine"), TrustingPolicy(), parentIsDataRoot: false).Dispose();
        QuarantineStore.Open(Path.Combine(root, "Sandbox"), TrustingPolicy(), parentIsDataRoot: false).Dispose();

        EngineDataRoot.Ensure(root, TrustingPolicy());

        AssertDataRootAcl(root, [System, Admins, QuarantineTestContext.CurrentUser]);
    }

    [Fact]
    public void PreCreatedRoot_WithAUserMadeQuarantineFolder_IsRefused()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV")).FullName;
        Directory.CreateDirectory(Path.Combine(root, "Quarantine")); // inherited ACL: a user could have made it

        var ex = Assert.Throws<QuarantineStoreException>(() => EngineDataRoot.Ensure(root, TrustingPolicy()));

        Assert.Contains("Quarantine", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheStore_IsUnavailable_WhenItsDataRootIsRefused()
    {
        using var temp = new TempDir();
        var root = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV")).FullName;
        File.WriteAllText(Path.Combine(root, "settings.json"), "{}");

        Assert.Throws<QuarantineStoreException>(() => QuarantineStore.Open(Path.Combine(root, "Quarantine"), TrustingPolicy(), parentIsDataRoot: true));
        Assert.False(Directory.Exists(Path.Combine(root, "Quarantine")));
    }

    [RequiresFact(Requires.Junctions)]
    public void ADataRootThatIsAJunction_IsRefused()
    {
        using var temp = new TempDir();
        var target = Directory.CreateDirectory(Path.Combine(temp.Path, "elsewhere")).FullName;
        var root = Path.Combine(temp.Path, "sap-AV");
        Assert.Null(RawJunction.TryCreate(root, @"\??\" + target));
        try
        {
            Assert.Throws<QuarantineStoreException>(() => EngineDataRoot.Ensure(root, TrustingPolicy()));
            Assert.False(new DirectoryInfo(target).GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected);
        }
        finally
        {
            Directory.Delete(root);
        }
    }
}
