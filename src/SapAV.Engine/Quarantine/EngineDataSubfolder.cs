using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

/// <summary>
/// One of the engine's own folders inside the data root (<c>%ProgramData%\sap-AV\Cache</c>, <c>…\VirusTotal</c>, <c>…\Rules</c>,
/// <c>…\Blocklist</c>): created atomically with the protected SYSTEM + Administrators DACL (inherited by every file the engine
/// writes in it), inside the verified data root (<see cref="EngineDataRoot"/>). What these folders hold decides verdicts (the
/// blocklist, rules, cached answers) or is secret (the VirusTotal key), so a folder that exists with an untrusted owner, a wider
/// DACL or as a reparse point is <b>refused</b>, never fixed: a user could have put content in it. Only an empty data root, or
/// one holding nothing but verified engine subfolders, is fixed (<see cref="EngineDataRoot.Ensure"/>).
/// </summary>
internal static class EngineDataSubfolder
{
    private const uint CheckAccess = N.ReadControl | N.FileReadAttributes | N.FileListDirectory | N.FileTraverse | N.Synchronize;

    /// <summary>Creates or verifies the folder; returns its full path.</summary>
    /// <param name="label">What the folder is, for messages ("scan cache", "VirusTotal").</param>
    /// <param name="parentIsDataRoot">Verify / create the parent with <see cref="EngineDataRoot.Ensure"/> first (default: when it is the real data root).</param>
    /// <exception cref="QuarantineStoreException">The folder can't be used safely (the message says why).</exception>
    public static string Ensure(string folder, QuarantineAccessPolicy policy, string label, bool? parentIsDataRoot = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (string.IsNullOrWhiteSpace(folder) || folder.Contains('\0') || !Path.IsPathFullyQualified(folder))
        {
            throw new QuarantineStoreException($"The {label} folder '{folder}' must be a fully qualified local path.");
        }

        string full = Path.GetFullPath(folder).TrimEnd('\\');
        string parent = Path.GetDirectoryName(full) ?? throw new QuarantineStoreException($"The {label} folder {full} has no parent.");
        if (parentIsDataRoot ?? IsInRealDataRoot(full))
        {
            EngineDataRoot.Ensure(parent, policy);
        }

        if (!N.CreateDirectoryWithSecurity(full, policy.CreateDataRootSecurityDescriptor(), out int error) && error != N.ErrorAlreadyExists)
        {
            throw new QuarantineStoreException($"Can't create the {label} folder {full} (Win32 error {error}).");
        }

        using var handle = N.OpenDirectoryNoReparse(full, CheckAccess, N.ShareRead | N.ShareWrite | N.ShareDelete, out error);
        if (handle.IsInvalid)
        {
            throw new QuarantineStoreException($"Can't open the {label} folder {full} (Win32 error {error}).");
        }

        if (!SafeDirectory.IsPlainDirectory(handle))
        {
            throw new QuarantineStoreException($"The {label} folder {full} is a reparse point or not a directory; refusing it.");
        }

        var sd = N.TryGetSecurity(handle, N.OwnerSecurityInformation | N.DaclSecurityInformation, out error)
            ?? throw new QuarantineStoreException($"Can't read the ACL of the {label} folder {full} (Win32 error {error}).");
        if (policy.Check(sd, out var why) != StoreAclStatus.Ok)
        {
            throw new QuarantineStoreException($"Refusing the {label} folder {full}: {why}. An administrator must check and remove it.");
        }

        return full;
    }

    /// <summary>True if <paramref name="folder"/> is directly inside <see cref="EngineDataFolders.ProgramDataRoot"/>.</summary>
    public static bool IsInRealDataRoot(string folder) =>
        Path.GetDirectoryName(Path.GetFullPath(folder).TrimEnd('\\')) is { } parent
        && string.Equals(FolderSet.Normalize(parent), FolderSet.Normalize(EngineDataFolders.ProgramDataRoot), StringComparison.OrdinalIgnoreCase);
}
