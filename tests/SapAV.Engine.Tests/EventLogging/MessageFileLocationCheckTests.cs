using System.Security.AccessControl;
using SapAV.Engine.EventLogging;

namespace SapAV.Engine.Tests.EventLogging;

public sealed class MessageFileLocationCheckTests
{
    private const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// <summary>The real ACL of C:\Program Files on Windows 11 (owner TrustedInstaller; Users read + execute).</summary>
    private const string ProgramFiles =
        $"O:{TrustedInstaller}G:{TrustedInstaller}D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)" +
        $"(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;;FA;;;{TrustedInstaller})(A;;0x1200a9;;;AC)";

    /// <summary>The real ACL of C:\ (Authenticated Users may create folders, and modify what they create: inherit-only).</summary>
    private const string DriveRoot =
        $"O:{TrustedInstaller}G:{TrustedInstaller}D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    [Theory]
    [InlineData(ProgramFiles, null)]
    [InlineData("O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;SY)(A;;FA;;;BA)", "is owned by")]              // a user owns it
    [InlineData("O:SYG:SYD:(A;;FA;;;SY)(A;;0x1301bf;;;BU)", "can be changed by")]                   // Users: modify
    [InlineData("O:BAG:SYD:(A;;FA;;;BA)(A;;0x1301bf;;;S-1-5-21-1-2-3-1001)", "can be changed by")]  // the dev's build output
    [InlineData("O:SYG:SYD:(A;;FA;;;SY)(A;OICIIO;FA;;;BU)", null)]                                  // inherit-only: not on the object
    [InlineData("O:SYG:SY", "no DACL")]                                                            // NULL DACL
    public void Judge_FileOrFolder_AcceptsOnlyAdminOwnedAndAdminWritable(string sddl, string? expectedProblem)
    {
        var problem = MessageFileLocationCheck.Judge(new RawSecurityDescriptor(sddl), MessageFileLocationCheck.TargetWriteMask);

        if (expectedProblem is null)
        {
            Assert.Null(problem);
        }
        else
        {
            Assert.Contains(expectedProblem, problem);
        }
    }

    [Fact]
    public void Judge_Ancestor_AllowsCreatingFolders_ButNotRenamingOrDeletingChildren()
    {
        var root = new RawSecurityDescriptor(DriveRoot);
        var deleteChild = new RawSecurityDescriptor("O:SYG:SYD:(A;;FA;;;SY)(A;;0x1200e9;;;AU)"); // read + FILE_DELETE_CHILD

        Assert.Null(MessageFileLocationCheck.Judge(root, MessageFileLocationCheck.AncestorWriteMask));
        Assert.NotNull(MessageFileLocationCheck.Judge(root, MessageFileLocationCheck.TargetWriteMask)); // never for the DLL's own folder
        Assert.Contains("can be changed by", MessageFileLocationCheck.Judge(deleteChild, MessageFileLocationCheck.AncestorWriteMask));
    }

    [Theory]
    [InlineData(@"C:\Program Files\sap-AV\System.Diagnostics.EventLog.Messages.dll", true)]
    [InlineData(@"System.Diagnostics.EventLog.Messages.dll", false)]
    [InlineData(@"\\server\share\messages.dll", false)]
    [InlineData(@"%ProgramFiles%\sap-AV\messages.dll", false)]
    [InlineData(@"C:\Program Files\sap-AV\..\..\Users\bob\messages.dll", false)]
    [InlineData(@"\\?\C:\Program Files\sap-AV\messages.dll", false)]
    public void PathProblem_AcceptsOnlyPlainFullyQualifiedLocalPaths(string path, bool accepted)
    {
        Assert.Equal(accepted, MessageFileLocationCheck.PathProblem(path) is null);
    }

    [Fact]
    public void FindProblem_DllInTheUsersTempFolder_IsRefused()
    {
        var folder = Directory.CreateTempSubdirectory("sapav-msgdll-");
        try
        {
            var dll = Path.Combine(folder.FullName, "System.Diagnostics.EventLog.Messages.dll");
            File.WriteAllBytes(dll, [0x4D, 0x5A]);

            Assert.NotNull(MessageFileLocationCheck.Instance.FindProblem(dll));
            Assert.Contains("does not exist", MessageFileLocationCheck.Instance.FindProblem(dll + ".missing"));
        }
        finally
        {
            folder.Delete(recursive: true);
        }
    }
}
