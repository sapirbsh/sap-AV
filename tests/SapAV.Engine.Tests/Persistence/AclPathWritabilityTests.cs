using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>C3: writability is read from the ACL (owner + DACL), on temp folders with a user-writable vs an admin-only ACL.</summary>
public sealed class AclPathWritabilityTests : IDisposable
{
    private static readonly SecurityIdentifier Me = WindowsIdentity.GetCurrent().User!;
    private readonly TempDir _temp = new();

    public void Dispose() => TempDir.DeleteTree(_temp.Path);

    /// <summary>A folder with a protected DACL: SYSTEM, Administrators and the test user (trusted through the seam), plus <paramref name="extra"/>.</summary>
    private string Folder(string name, params FileSystemAccessRule[] extra)
    {
        var path = Directory.CreateDirectory(Path.Combine(_temp.Path, name)).FullName;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), Me })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }

        foreach (var rule in extra)
        {
            security.AddAccessRule(rule);
        }

        new DirectoryInfo(path).SetAccessControl(security);
        File.WriteAllText(Path.Combine(path, "app.exe"), "x");
        return path;
    }

    private static FileSystemAccessRule Users(FileSystemRights rights, InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) =>
        new(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), rights, inherit, PropagationFlags.None, AccessControlType.Allow);

    private static AclPathWritability Acl() => new([Me]);

    [Fact]
    public void AdminOnlyFolder_IsAdminOnly_ForTheFileAndForNewFiles()
    {
        var folder = Folder("locked", Users(FileSystemRights.ReadAndExecute));
        var acl = Acl();

        Assert.Equal(Writability.AdminOnly, acl.FileModifiable(Path.Combine(folder, "app.exe")));
        Assert.Equal(Writability.AdminOnly, acl.FileCreatable(Path.Combine(folder, "planted.dll")));
        Assert.Equal(Writability.AdminOnly, acl.FileCreatable(Path.Combine(folder, "missing", "deeper", "x.exe")));
    }

    [Fact]
    public void UserWritableFolder_IsUserWritable_ForTheInheritedFileAndForNewFiles()
    {
        var folder = Folder("open", Users(FileSystemRights.Modify));
        var acl = Acl();

        Assert.Equal(Writability.UserWritable, acl.FileModifiable(Path.Combine(folder, "app.exe")));
        Assert.Equal(Writability.UserWritable, acl.FileCreatable(Path.Combine(folder, "planted.dll")));
    }

    [Fact]
    public void CreateFoldersOnly_LikeTheDriveRoot_AllowsMissingFolders_ButNotFilesInIt()
    {
        // C:\ gives Authenticated Users "create folders / append data" on the folder itself, not "create files".
        var folder = Folder("root-like", Users(FileSystemRights.AppendData, InheritanceFlags.None));
        var acl = Acl();

        Assert.Equal(Writability.AdminOnly, acl.FileCreatable(Path.Combine(folder, "Program.exe")));
        Assert.Equal(Writability.UserWritable, acl.FileCreatable(Path.Combine(folder, "Vendor", "agent.exe")));
    }

    [Fact]
    public void WithoutTheSeam_AFolderOwnedByAStandardUser_IsUserWritable_AndMissingIsUnknown()
    {
        var folder = Folder("mine");
        var acl = new AclPathWritability();

        Assert.Equal(Writability.UserWritable, acl.FileCreatable(Path.Combine(folder, "x.exe"))); // the owner can rewrite the DACL
        Assert.Equal(Writability.Unknown, acl.FileModifiable(Path.Combine(folder, "missing.exe")));
        Assert.Equal(Writability.Unknown, acl.FileCreatable(@"\\server\share\x.exe")); // never contacts a server
    }

    [Theory]
    [InlineData("O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", AclPathWritability.AddFileRights, Writability.AdminOnly)]
    [InlineData("O:BAG:SY", AclPathWritability.AddFileRights, Writability.UserWritable)] // no DACL
    [InlineData("O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;SY)", AclPathWritability.AddFileRights, Writability.UserWritable)] // user owner
    [InlineData("O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;SY)(A;;0x1200a9;;;OW)", AclPathWritability.AddFileRights, Writability.AdminOnly)] // OWNER RIGHTS limit it
    [InlineData("O:BAG:SYD:(A;OICIIO;FA;;;BU)(A;OICIIO;FA;;;CO)", AclPathWritability.AddFileRights, Writability.AdminOnly)] // inherit-only
    [InlineData("O:BAG:SYD:(A;;FA;;;S-1-5-80-1-2-3-4-5)(A;;FA;;;S-1-15-2-1)", AclPathWritability.AddFileRights, Writability.AdminOnly)] // service / package SIDs
    [InlineData("O:BAG:SYD:(A;;0x4;;;AU)", AclPathWritability.AddFileRights, Writability.AdminOnly)]
    [InlineData("O:BAG:SYD:(A;;0x4;;;AU)", AclPathWritability.AddFolderRights, Writability.UserWritable)]
    [InlineData("O:BAG:SYD:(A;;WD;;;WD)", AclPathWritability.ModifyFileRights, Writability.UserWritable)] // WRITE_DAC for Everyone
    public void Evaluate_ReadsOwnerAndDacl(string sddl, int rights, Writability expected)
    {
        var sd = new RawSecurityDescriptor(sddl);
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);

        Assert.Equal(expected, new AclPathWritability().Evaluate(bytes, rights));
    }
}
