using System.Security.AccessControl;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>
/// The worker-folder grant is a read-modify-write of one DACL. Concurrent grants/revokes (test classes in parallel,
/// or the requirement probe) must not lose each other's entries: a lost entry means that container's workers can't
/// load their exe and every test using it fails (the cold-start flake of the first B5 runs).
/// </summary>
public sealed class WorkerFolderAccessTests
{
    [RequiresFact(Requires.AppContainer)]
    public async Task ConcurrentGrantsAndRevokes_NeverLoseAnotherContainersEntry()
    {
        var containers = new TestAppContainer[8];
        try
        {
            await Task.WhenAll(Enumerable.Range(0, containers.Length).Select(i => Task.Run(() => containers[i] = new TestAppContainer("Acl"))));

            var security = new DirectoryInfo(Path.GetDirectoryName(TestAppContainer.WorkerExe)!).GetAccessControl(AccessControlSections.Access);
            Assert.All(containers, c => Assert.True(WorkerFolderAccess.Grants(security, c.Sid), $"{c.Sid} lost its grant"));

            // Revoking half of them concurrently must leave the other half intact.
            await Task.WhenAll(containers.Take(4).Select(c => Task.Run(c.Dispose)));
            security = new DirectoryInfo(Path.GetDirectoryName(TestAppContainer.WorkerExe)!).GetAccessControl(AccessControlSections.Access);
            Assert.All(containers.Skip(4), c => Assert.True(WorkerFolderAccess.Grants(security, c.Sid), $"{c.Sid} lost its grant"));
        }
        finally
        {
            foreach (var c in containers.Skip(4))
            {
                c?.Dispose();
            }
        }
    }
}

/// <summary>Review M4: when and where the worker-folder grant may change an ACL.</summary>
public sealed class WorkerFolderAccessPolicyTests : IDisposable
{
    private static readonly System.Security.Principal.SecurityIdentifier FakeContainer = new("S-1-15-2-11-22-33-44-55-66-77");

    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"))).FullName;

    public void Dispose() => TempDir.DeleteTree(_dir);

    private string FakeWorker(string folder)
    {
        Directory.CreateDirectory(folder);
        var exe = Path.Combine(folder, "SapAV.ScanWorker.exe");
        File.WriteAllText(exe, "not a real exe");
        return exe;
    }

    private static bool HasEntryFor(string folder, System.Security.Principal.SecurityIdentifier sid) =>
        new DirectoryInfo(folder).GetAccessControl(AccessControlSections.Access)
            .GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<FileSystemAccessRule>().Any(r => r.IdentityReference == sid);

    [Fact]
    public void AsSystem_AMissingGrant_IsNeverAdded_TheSandboxIsUnavailable()
    {
        var folder = Path.Combine(_dir, "ScanWorker");
        var exe = FakeWorker(folder);

        var ex = Assert.Throws<SandboxUnavailableException>(() => WorkerFolderAccess.Ensure(exe, FakeContainer, runningAsSystem: true, folder));

        Assert.Contains("never changes", ex.Message, StringComparison.Ordinal);
        Assert.False(HasEntryFor(folder, FakeContainer));
    }

    [Fact]
    public void AsSystem_AnInstallerGrantToAllApplicationPackages_IsAccepted()
    {
        var folder = Path.Combine(_dir, "ScanWorker");
        var exe = FakeWorker(folder);
        var info = new DirectoryInfo(folder);
        var security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(WorkerFolderAccess.AllApplicationPackages, FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(security);

        Assert.Equal(FolderGrantResult.AlreadyGranted, WorkerFolderAccess.Ensure(exe, FakeContainer, runningAsSystem: true, folder));
    }

    [Fact]
    public void AnyFolderOtherThanTheEnginesScanWorkerFolder_IsRefused()
    {
        var exe = FakeWorker(Path.Combine(_dir, "elsewhere"));

        var ex = Assert.Throws<SandboxUnavailableException>(() =>
            WorkerFolderAccess.Ensure(exe, FakeContainer, runningAsSystem: false, WorkerFolderAccess.ExpectedFolder));

        Assert.Contains("only the worker folder", ex.Message, StringComparison.Ordinal);
        Assert.False(HasEntryFor(Path.GetDirectoryName(exe)!, FakeContainer));
    }

    [RequiresFact(Requires.Junctions)]
    public void AJunctionToTheFolder_IsRefused_AndTheTargetIsUntouched()
    {
        var real = Path.Combine(_dir, "real");
        FakeWorker(real);
        var link = Path.Combine(_dir, "ScanWorker");
        Assert.Null(SapAV.Core.Tests.TestSupport.RawJunction.TryCreate(link, @"\??\" + real));

        var ex = Assert.Throws<SandboxUnavailableException>(() =>
            WorkerFolderAccess.Ensure(Path.Combine(link, "SapAV.ScanWorker.exe"), FakeContainer, runningAsSystem: false, link));

        Assert.Contains("reparse", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(HasEntryFor(real, FakeContainer));
    }
}
