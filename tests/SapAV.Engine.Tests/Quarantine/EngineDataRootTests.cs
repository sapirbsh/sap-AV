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

    [Fact]
    public void PreCreatedEmptyRoot_WithAnExtraUsersWriteEntry_IsFixed_ToOnlyTheTrustedSids()
    {
        using var temp = new TempDir();
        var dir = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV"));
        var security = dir.GetAccessControl(AccessControlSections.Access);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(QuarantineTestContext.CurrentUser, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(security);

        EngineDataRoot.Ensure(dir.FullName, TrustingPolicy());

        AssertDataRootAcl(dir.FullName, [System, Admins, QuarantineTestContext.CurrentUser]);
    }

    [Fact]
    public void TheAclCheck_RefusesAnUntrustedOwner_AndAnyNonTrustedAllowEntry()
    {
        var policy = QuarantineAccessPolicy.Default;
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        byte[] Descriptor(SecurityIdentifier owner, params SecurityIdentifier[] allowed)
        {
            var acl = new RawAcl(GenericAcl.AclRevision, allowed.Length);
            foreach (var sid in allowed)
            {
                acl.InsertAce(acl.Count, new CommonAce(AceFlags.ObjectInherit | AceFlags.ContainerInherit, AceQualifier.AccessAllowed,
                    QuarantineAccessPolicy.FullControl, sid, false, null));
            }

            var sd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected, owner, null, null, acl);
            var bytes = new byte[sd.BinaryLength];
            sd.GetBinaryForm(bytes, 0);
            return bytes;
        }

        Assert.Equal(StoreAclStatus.Ok, policy.Check(Descriptor(Admins, System, Admins), out _));
        Assert.Equal(StoreAclStatus.Ok, policy.Check(Descriptor(System, System, Admins), out _));
        Assert.Equal(StoreAclStatus.UntrustedOwner, policy.Check(Descriptor(users, System, Admins), out _)); // owner can rewrite the DACL
        Assert.Equal(StoreAclStatus.Wider, policy.Check(Descriptor(Admins, System, Admins, users), out var why));
        Assert.Contains(users.Value, why, StringComparison.Ordinal);
    }

    [RequiresFact(Requires.RunningElevated)]
    public void PreCreatedRoot_OwnedByAStandardUserGroup_IsRefused_AndItsAclIsLeftAlone()
    {
        using var temp = new TempDir();
        var dir = Directory.CreateDirectory(Path.Combine(temp.Path, "sap-AV"));
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        Assert.Equal(0, SapAV.Engine.Quarantine.Native.RestorePrivilege.Run(() =>
        {
            var owner = new DirectorySecurity();
            owner.SetOwner(users);
            dir.SetAccessControl(owner);
            return 0;
        }));

        var ex = Assert.Throws<QuarantineStoreException>(() => EngineDataRoot.Ensure(dir.FullName, QuarantineAccessPolicy.Default));

        Assert.Contains("owner", ex.Message, StringComparison.Ordinal);
        Assert.False(dir.GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected); // nothing changed
        Assert.Equal(users, dir.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)));
    }

    [Fact]
    public void TheVirusTotalFolder_IsCreatedProtected_AndAPreCreatedWiderOneIsRefused_NotFixed()
    {
        using var temp = new TempDir();
        var root = Path.Combine(temp.Path, "sap-AV");
        var folder = EngineDataSubfolder.Ensure(Path.Combine(root, "VirusTotal"), TrustingPolicy(), "VirusTotal", parentIsDataRoot: true);
        AssertDataRootAcl(folder, [System, Admins, QuarantineTestContext.CurrentUser]);
        File.WriteAllText(Path.Combine(folder, "vt-usage.json"), "{}");
        Assert.All(new FileInfo(Path.Combine(folder, "vt-usage.json")).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>(), r => Assert.Contains(r.IdentityReference, new[] { System, Admins, QuarantineTestContext.CurrentUser }));

        // A subfolder that inherits instead of having the protected DACL may hold what a user put there: refused, never fixed.
        var wider = Directory.CreateDirectory(Path.Combine(temp.Path, "other", "VirusTotal")).FullName;
        File.WriteAllText(Path.Combine(wider, "vt-apikey.bin"), "planted");
        var ex = Assert.Throws<QuarantineStoreException>(() => EngineDataSubfolder.Ensure(wider, TrustingPolicy(), "VirusTotal", parentIsDataRoot: false));
        Assert.Contains("inherits", ex.Message, StringComparison.Ordinal);
        Assert.False(new DirectoryInfo(wider).GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected);
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
