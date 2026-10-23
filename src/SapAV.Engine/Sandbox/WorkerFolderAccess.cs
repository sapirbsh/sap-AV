using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Quarantine;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Sandbox;

/// <summary>What <see cref="WorkerFolderAccess.Ensure"/> did.</summary>
internal enum FolderGrantResult
{
    /// <summary>The folder already grants read/execute to ALL APPLICATION PACKAGES or to this AppContainer (e.g. Program Files).</summary>
    AlreadyGranted,

    /// <summary>An inheritable read/execute entry for this AppContainer's SID was added to the folder.</summary>
    Granted,
}

/// <summary>
/// The AppContainer must be able to <b>read and execute</b> the worker's own folder (the worker exe, its assemblies,
/// <c>SapAV.Core.dll</c>, <c>yara_x_capi.dll</c>). The .NET runtime in <c>Program Files\dotnet</c> already allows ALL
/// APPLICATION PACKAGES, and so does an install under Program Files.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><b>As SYSTEM (the service) no ACL is ever changed</b> (review M4): the installer places the worker where the
/// container can read it. If the folder doesn't grant read/execute, the sandbox is unavailable (files NotScanned) and
/// the reason is logged.</item>
/// <item>Console / dev / CI runs under a user account may add one inheritable ReadAndExecute entry for the specific
/// AppContainer SID (never ALL APPLICATION PACKAGES, never write access), and only on exactly
/// <c>AppContext.BaseDirectory\ScanWorker</c>. That folder is opened through <see cref="SafeDirectory"/> (no reparse
/// point anywhere on the path), and the DACL is read and written <b>by that handle</b>, so a junction swapped in can't
/// redirect the change.</item>
/// <item>Grant and revoke are serialized in-process (a read-modify-write of one DACL).</item>
/// </list>
/// </remarks>
internal static class WorkerFolderAccess
{
    public static readonly SecurityIdentifier AllApplicationPackages = new("S-1-15-2-1");

    private const FileSystemRights Needed = FileSystemRights.ReadAndExecute;
    private const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    /// <summary>
    /// Grant and revoke are a read-modify-write of one DACL; without this, two concurrent callers (test classes in
    /// parallel, the requirement probe) can each write back a DACL missing the other's entry, or re-add a revoked one.
    /// </summary>
    private static readonly object DaclGate = new();

    /// <summary>The only folder a grant may touch: the worker folder next to the running engine.</summary>
    public static string ExpectedFolder => Path.TrimEndingDirectorySeparator(Path.Combine(AppContext.BaseDirectory, "ScanWorker"));

    /// <exception cref="SandboxUnavailableException">Not granted and not allowed to grant, the folder is refused, or the ACL can't be changed.</exception>
    public static FolderGrantResult Ensure(string workerExe, SecurityIdentifier appContainerSid) =>
        Ensure(workerExe, appContainerSid, AppContainerName.IsLocalSystem(), ExpectedFolder);

    /// <summary>Test seam: the SYSTEM decision and the expected folder are parameters.</summary>
    internal static FolderGrantResult Ensure(string workerExe, SecurityIdentifier appContainerSid, bool runningAsSystem, string expectedFolder)
    {
        string folder = WorkerFolder(workerExe);
        try
        {
            if (runningAsSystem)
            {
                // Read only (by path is fine: nothing is changed).
                var current = new DirectoryInfo(folder).GetAccessControl(AccessControlSections.Access);
                if (Grants(current, AllApplicationPackages) || Grants(current, appContainerSid))
                {
                    return FolderGrantResult.AlreadyGranted;
                }

                throw new SandboxUnavailableException(
                    $"The scan worker folder {folder} doesn't let the worker's AppContainer read and execute it, and the engine never changes " +
                    "ACLs when running as SYSTEM. Install sap-AV under Program Files (or let the installer grant ALL APPLICATION PACKAGES read/execute).");
            }

            using var handle = OpenExpected(folder, expectedFolder);
            lock (DaclGate)
            using (CrossProcessGate.Acquire())
            {
                var security = ReadDacl(handle, folder);
                if (Grants(security, AllApplicationPackages) || Grants(security, appContainerSid))
                {
                    return FolderGrantResult.AlreadyGranted;
                }

                security.AddAccessRule(new FileSystemAccessRule(appContainerSid, Needed, Inherit, PropagationFlags.None, AccessControlType.Allow));
                WriteDacl(handle, security, folder);
                return FolderGrantResult.Granted;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or PrivilegeNotHeldException)
        {
            throw new SandboxUnavailableException($"Could not give the scan worker's AppContainer read/execute on {folder}: {ex.Message}", ex);
        }
    }

    /// <summary>Removes the explicit entry <see cref="Ensure"/> added for <paramref name="appContainerSid"/> (tests). Idempotent.</summary>
    public static void Revoke(string workerExe, SecurityIdentifier appContainerSid) => Revoke(workerExe, appContainerSid, ExpectedFolder);

    internal static void Revoke(string workerExe, SecurityIdentifier appContainerSid, string expectedFolder)
    {
        string folder = WorkerFolder(workerExe);
        using var handle = OpenExpected(folder, expectedFolder);
        lock (DaclGate)
        using (CrossProcessGate.Acquire())
        {
            var security = ReadDacl(handle, folder);
            security.PurgeAccessRules(appContainerSid);
            WriteDacl(handle, security, folder);
        }
    }

    /// <summary>True if the folder's DACL (explicit or inherited) allows <paramref name="sid"/> ReadAndExecute on itself and its files.</summary>
    internal static bool Grants(DirectorySecurity security, SecurityIdentifier sid)
    {
        FileSystemRights allowed = 0;
        bool inherits = false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.IdentityReference is not SecurityIdentifier ruleSid || ruleSid != sid || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
            {
                continue;
            }

            if (rule.AccessControlType == AccessControlType.Deny && (rule.FileSystemRights & Needed) != 0)
            {
                return false;
            }

            if (rule.AccessControlType == AccessControlType.Allow)
            {
                allowed |= rule.FileSystemRights;
                inherits |= rule.InheritanceFlags.HasFlag(InheritanceFlags.ObjectInherit);
            }
        }

        return inherits && (allowed & Needed) == Needed;
    }

    private static string WorkerFolder(string workerExe)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExe);
        var exe = Path.GetFullPath(workerExe);
        if (!File.Exists(exe))
        {
            throw new SandboxUnavailableException($"The scan worker is missing: {exe}");
        }

        return Path.TrimEndingDirectorySeparator(Path.GetDirectoryName(exe)!);
    }

    /// <summary>The folder must be exactly <paramref name="expected"/>, reached without any reparse point; then READ_CONTROL | WRITE_DAC on it.</summary>
    private static SafeFileHandle OpenExpected(string folder, string expected)
    {
        if (!string.Equals(folder, Path.TrimEndingDirectorySeparator(Path.GetFullPath(expected)), StringComparison.OrdinalIgnoreCase))
        {
            throw new SandboxUnavailableException(
                $"Refusing to change the ACL of {folder}: only the worker folder next to the engine ({expected}) may be granted.");
        }

        using var validated = SafeDirectory.TryOpen(folder, out var failure, out string reason)
            ?? throw new SandboxUnavailableException($"Refusing to change the ACL of {folder}: {failure}: {reason}");

        // Reopen the same directory object (empty name relative to the validated handle) with the rights to change its DACL.
        return N.OpenRelative(validated, string.Empty, N.ReadControl | N.WriteDac, N.ShareRead | N.ShareWrite | N.ShareDelete,
                N.FileOpen, N.FileDirectoryFile | N.FileOpenReparsePoint, out int error, N.ObjCaseInsensitive | N.ObjDontReparse)
            ?? throw new SandboxUnavailableException($"Could not open {folder} to change its ACL (Win32 error {error}).");
    }

    private static DirectorySecurity ReadDacl(SafeFileHandle handle, string folder)
    {
        var bytes = N.TryGetSecurity(handle, N.DaclSecurityInformation, out int error)
            ?? throw new SandboxUnavailableException($"Could not read the ACL of {folder} (Win32 error {error}).");
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);
        return security;
    }

    private static void WriteDacl(SafeFileHandle handle, DirectorySecurity security, string folder)
    {
        var sd = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        var dacl = new byte[sd.DiscretionaryAcl!.BinaryLength];
        sd.DiscretionaryAcl.GetBinaryForm(dacl, 0);

        // Keep the folder's protected/unprotected state as it was; only the explicit entries change.
        uint info = N.DaclSecurityInformation | (security.AreAccessRulesProtected ? N.ProtectedDaclSecurityInformation : N.UnprotectedDaclSecurityInformation);
        int error = N.SetSecurity(handle, info, null, dacl);
        if (error != 0)
        {
            throw new SandboxUnavailableException($"Could not change the ACL of {folder} (Win32 error {error}).");
        }
    }
}

/// <summary>
/// The DACL read-modify-write is also serialized across processes (two test runs, or a console engine next to a test
/// run, granting on the same folder). Only used on the non-SYSTEM path: as SYSTEM nothing is ever changed, so a user
/// squatting on the mutex name can at most delay a developer's console run.
/// </summary>
internal static class CrossProcessGate
{
    private const string Name = @"Local\sap-AV.WorkerFolderDacl";

    /// <exception cref="SandboxUnavailableException">Not acquired within 30 seconds.</exception>
    public static IDisposable Acquire()
    {
        var mutex = new Mutex(initiallyOwned: false, Name);
        try
        {
            if (!mutex.WaitOne(TimeSpan.FromSeconds(30)))
            {
                throw new SandboxUnavailableException($"Timed out waiting for {Name} to change the scan worker folder's ACL.");
            }
        }
        catch (AbandonedMutexException)
        {
            // the previous holder died mid-change; we own it now and the DACL is re-read under it
        }
        catch
        {
            mutex.Dispose();
            throw;
        }

        return new Releaser(mutex);
    }

    private sealed class Releaser(Mutex mutex) : IDisposable
    {
        public void Dispose()
        {
            mutex.ReleaseMutex();
            mutex.Dispose();
        }
    }
}
