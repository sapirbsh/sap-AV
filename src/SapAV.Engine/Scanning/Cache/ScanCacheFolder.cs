using SapAV.Engine.Quarantine;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning.Cache;

/// <summary>
/// The cache's folder (C5): <c>%ProgramData%\sap-AV\Cache</c>, created atomically with the protected SYSTEM + Administrators
/// DACL (inherited by <c>scan.db</c>, its <c>-wal</c> / <c>-shm</c> files and the key file), inside the verified data root
/// (<see cref="EngineDataRoot"/>). A tampered database could make a file look Clean, so a folder that exists with another
/// owner, a wider DACL or as a reparse point is refused and the cache stays off (scans run uncached). The GUI never reads it.
/// </summary>
internal static class ScanCacheFolder
{
    private const uint CheckAccess = N.ReadControl | N.FileReadAttributes | N.FileListDirectory | N.FileTraverse | N.Synchronize;

    /// <summary>Creates or verifies the folder; returns its full path.</summary>
    /// <param name="parentIsDataRoot">Verify / create the parent with <see cref="EngineDataRoot.Ensure"/> first (default: when it is the real data root).</param>
    /// <exception cref="QuarantineStoreException">The folder can't be used safely (the message says why).</exception>
    public static string Ensure(string folder, QuarantineAccessPolicy policy, bool? parentIsDataRoot = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (string.IsNullOrWhiteSpace(folder) || folder.Contains('\0') || !Path.IsPathFullyQualified(folder))
        {
            throw new QuarantineStoreException($"The scan cache folder '{folder}' must be a fully qualified local path.");
        }

        string full = Path.GetFullPath(folder).TrimEnd('\\');
        string parent = Path.GetDirectoryName(full) ?? throw new QuarantineStoreException($"The scan cache folder {full} has no parent.");
        if (parentIsDataRoot ?? string.Equals(FolderSet.Normalize(parent), FolderSet.Normalize(EngineDataFolders.ProgramDataRoot), StringComparison.OrdinalIgnoreCase))
        {
            EngineDataRoot.Ensure(parent, policy);
        }

        if (!N.CreateDirectoryWithSecurity(full, policy.CreateDataRootSecurityDescriptor(), out int error) && error != N.ErrorAlreadyExists)
        {
            throw new QuarantineStoreException($"Can't create the scan cache folder {full} (Win32 error {error}).");
        }

        using var handle = N.OpenDirectoryNoReparse(full, CheckAccess, N.ShareRead | N.ShareWrite | N.ShareDelete, out error);
        if (handle.IsInvalid)
        {
            throw new QuarantineStoreException($"Can't open the scan cache folder {full} (Win32 error {error}).");
        }

        if (!SafeDirectory.IsPlainDirectory(handle))
        {
            throw new QuarantineStoreException($"The scan cache folder {full} is a reparse point or not a directory; refusing it.");
        }

        var sd = N.TryGetSecurity(handle, N.OwnerSecurityInformation | N.DaclSecurityInformation, out error)
            ?? throw new QuarantineStoreException($"Can't read the ACL of the scan cache folder {full} (Win32 error {error}).");
        if (policy.Check(sd, out var why) != StoreAclStatus.Ok)
        {
            throw new QuarantineStoreException($"Refusing the scan cache folder {full}: {why}. An administrator must check and remove it.");
        }

        return full;
    }
}
