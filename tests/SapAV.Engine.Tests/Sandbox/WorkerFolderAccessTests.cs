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
