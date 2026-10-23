using System.Security.AccessControl;
using System.Security.Principal;

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
/// The one ACL change the sandbox makes: the AppContainer must be able to <b>read and execute</b> the worker's own folder
/// (the worker exe, its assemblies, <c>SapAV.Core.dll</c> and <c>yara_x_capi.dll</c>). The .NET runtime in
/// <c>Program Files\dotnet</c> already allows ALL APPLICATION PACKAGES, and so does an install under Program Files, so
/// in production this is normally a no-op. On a development or CI build folder it adds one inheritable
/// ReadAndExecute entry for the specific AppContainer SID (not ALL APPLICATION PACKAGES), on that folder only.
/// </summary>
/// <remarks>
/// Never on user data: the folder must contain the worker exe, and the drive root, the profile folder, Desktop,
/// Documents, Downloads, Temp and the Windows folder are refused outright. No write access is ever granted.
/// </remarks>
internal static class WorkerFolderAccess
{
    public static readonly SecurityIdentifier AllApplicationPackages = new("S-1-15-2-1");

    private const FileSystemRights Needed = FileSystemRights.ReadAndExecute;
    private const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    /// <exception cref="SandboxUnavailableException">The folder is refused, or the ACL can't be read or changed.</exception>
    public static FolderGrantResult Ensure(string workerExe, SecurityIdentifier appContainerSid)
    {
        var folder = CheckedFolder(workerExe);
        try
        {
            var info = new DirectoryInfo(folder);
            var security = info.GetAccessControl(AccessControlSections.Access);
            if (Grants(security, AllApplicationPackages) || Grants(security, appContainerSid))
            {
                return FolderGrantResult.AlreadyGranted;
            }

            security.AddAccessRule(new FileSystemAccessRule(appContainerSid, Needed, Inherit, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);
            return FolderGrantResult.Granted;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or PrivilegeNotHeldException)
        {
            throw new SandboxUnavailableException($"Could not give the scan worker's AppContainer read/execute on {folder}: {ex.Message}", ex);
        }
    }

    /// <summary>Removes the explicit entry <see cref="Ensure"/> added for <paramref name="appContainerSid"/> (tests). Idempotent.</summary>
    public static void Revoke(string workerExe, SecurityIdentifier appContainerSid)
    {
        var info = new DirectoryInfo(CheckedFolder(workerExe));
        var security = info.GetAccessControl(AccessControlSections.Access);
        security.PurgeAccessRules(appContainerSid);
        info.SetAccessControl(security);
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

    private static string CheckedFolder(string workerExe)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExe);
        var exe = Path.GetFullPath(workerExe);
        if (!File.Exists(exe))
        {
            throw new SandboxUnavailableException($"The scan worker is missing: {exe}");
        }

        var folder = Path.TrimEndingDirectorySeparator(Path.GetDirectoryName(exe)!);
        var refused = new[]
            {
                Path.GetPathRoot(folder),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
            }
            .Where(p => !string.IsNullOrEmpty(p))
            .Select(p => Path.TrimEndingDirectorySeparator(Path.GetFullPath(p!)));
        if (refused.Any(p => string.Equals(p, folder, StringComparison.OrdinalIgnoreCase)))
        {
            throw new SandboxUnavailableException($"Refusing to change the ACL of {folder}: the scan worker must live in its own folder.");
        }

        return folder;
    }
}
