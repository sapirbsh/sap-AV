using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Quarantine;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

/// <summary>
/// The engine's data root, <c>%ProgramData%\sap-AV</c> (review B H1, ROADMAP D3 M3 / M-B). <c>%ProgramData%</c> lets every
/// user create folders and files (<c>BUILTIN\Users:(CI)(WD,AD,WEA,WA)</c>), so a root created with normal inheritance would
/// let users plant files in it or pre-create the engine's future subfolders.
/// </summary>
/// <remarks>
/// <see cref="Ensure"/>:
/// <list type="bullet">
/// <item>Missing: created atomically with the protected SYSTEM + Administrators DACL
/// (<see cref="QuarantineAccessPolicy.CreateDataRootSecurityDescriptor"/>).</item>
/// <item>Exists with the protected DACL and a trusted owner: used as is.</item>
/// <item>Untrusted owner (the owner can always rewrite the DACL): refused, nothing changed.</item>
/// <item>Wider DACL (inherited from ProgramData, or extra entries), trusted owner: fixed only if it is empty or holds nothing
/// but the engine's own subfolders (<see cref="EngineSubfolders"/>) that are themselves plain folders with a trusted owner
/// and the protected DACL (an install from before this fix). The content is listed from the pinned handle, the DACL is
/// replaced on this folder only (no propagation into its content), and the content is listed again, so nothing added
/// between the check and the fix slips through (ROADMAP D3 L4); then the original DACL is put back, so the folder stays
/// refused. Anything else could have been planted by a user: refused, and an administrator must check it. The content
/// is never deleted.</item>
/// </list>
/// </remarks>
public static class EngineDataRoot
{
    /// <summary>Subfolders the engine itself creates in the root (each with its own protected DACL).</summary>
    public static IReadOnlyList<string> EngineSubfolders { get; } = ["Quarantine", "Sandbox"];

    private const uint CheckAccess = N.ReadControl | N.WriteDac | N.FileReadAttributes | N.FileListDirectory | N.FileTraverse;

    /// <summary>Creates or verifies (and if possible fixes) the data root at <paramref name="path"/>.</summary>
    /// <exception cref="QuarantineStoreException">The root can't be used safely (the message says why).</exception>
    public static void Ensure(string path, QuarantineAccessPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        string full = ValidatePath(path);
        if (!N.CreateDirectoryWithSecurity(full, policy.CreateDataRootSecurityDescriptor(), out int error) && error != N.ErrorAlreadyExists)
        {
            throw new QuarantineStoreException($"Can't create the sap-AV data folder {full} (Win32 error {error}).");
        }

        using var handle = N.OpenDirectoryNoReparse(full, CheckAccess | N.Synchronize, N.ShareRead | N.ShareWrite, out error);
        if (handle.IsInvalid)
        {
            throw new QuarantineStoreException($"Can't open the sap-AV data folder {full} (Win32 error {error}).");
        }

        if (!SafeDirectory.IsPlainDirectory(handle))
        {
            throw new QuarantineStoreException($"The sap-AV data folder {full} is a reparse point or not a directory; refusing it.");
        }

        var sd = N.TryGetSecurity(handle, N.OwnerSecurityInformation | N.DaclSecurityInformation, out error)
            ?? throw new QuarantineStoreException($"Can't read the ACL of the sap-AV data folder {full} (Win32 error {error}).");
        switch (policy.Check(sd, out var reason))
        {
            case StoreAclStatus.Ok:
                return;
            case StoreAclStatus.UntrustedOwner:
                throw new QuarantineStoreException($"Refusing the sap-AV data folder {full}: {reason}. An administrator must check and remove it.");
            default:
                FixIfContentTrusted(handle, full, policy, reason, sd);
                return;
        }
    }

    /// <summary>
    /// Content check, DACL fix, content check again (something added between the first check and the fix, D3 L4). If the
    /// second check fails the original DACL is put back, so the folder stays "wider" and is refused again on the next start,
    /// instead of looking verified with planted content inside.
    /// </summary>
    private static void FixIfContentTrusted(SafeFileHandle handle, string full, QuarantineAccessPolicy policy, string reason, byte[] original)
    {
        if (UntrustedContent(handle, policy) is { } before)
        {
            throw Refused(full, reason, before);
        }

        int result = N.SetSecurityObject(handle, N.DaclSecurityInformation | N.ProtectedDaclSecurityInformation,
            policy.CreateDataRootSecurityDescriptor());
        if (result != 0)
        {
            throw new QuarantineStoreException($"Can't fix the ACL of the sap-AV data folder {full} ({reason}; Win32 error {result}).");
        }

        if (UntrustedContent(handle, policy) is { } after)
        {
            RestoreDacl(handle, original);
            throw Refused(full, reason, after);
        }
    }

    /// <summary>Null if the folder is empty or holds only verified engine subfolders; otherwise what doesn't belong.</summary>
    private static string? UntrustedContent(SafeFileHandle handle, QuarantineAccessPolicy policy)
    {
        List<SafeTreeEntry> entries;
        try
        {
            entries = SafeTree.List(handle);
        }
        catch (IOException)
        {
            return "content that can't be listed";
        }

        return entries.Select(e => UntrustedEntry(handle, e, policy)).FirstOrDefault(w => w is not null);
    }

    private static QuarantineStoreException Refused(string full, string reason, string what) =>
        new($"Refusing the sap-AV data folder {full}: its ACL is too wide ({reason}) and it contains {what}, which a user could have " +
            "planted, so its content can't be trusted. An administrator must check and fix or remove it.");

    private static void RestoreDacl(SafeFileHandle handle, byte[] original)
    {
        var sd = new RawSecurityDescriptor(original, 0);
        bool wasProtected = (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
        var daclOnly = new RawSecurityDescriptor(sd.ControlFlags & (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected
            | ControlFlags.DiscretionaryAclAutoInherited), null, null, null, sd.DiscretionaryAcl);
        var bytes = new byte[daclOnly.BinaryLength];
        daclOnly.GetBinaryForm(bytes, 0);
        N.SetSecurityObject(handle, N.DaclSecurityInformation
            | (wasProtected ? N.ProtectedDaclSecurityInformation : N.UnprotectedDaclSecurityInformation), bytes);
    }

    /// <summary>Null if <paramref name="entry"/> is one of the engine's own, verified subfolders; otherwise what it is.</summary>
    private static string? UntrustedEntry(SafeFileHandle root, SafeTreeEntry entry, QuarantineAccessPolicy policy)
    {
        string what = $"'{entry.Name}'";
        if (!entry.IsDirectory || entry.Attributes.HasFlag(FileAttributes.ReparsePoint)
            || !EngineSubfolders.Contains(entry.Name, StringComparer.OrdinalIgnoreCase))
        {
            return what;
        }

        using var child = SafeTree.OpenChild(root, entry.Name, SafeTree.InspectAccess, SafeTree.ShareAll, N.FileDirectoryFile, out _, out _);
        if (child is null || !SafeDirectory.IsPlainDirectory(child)
            || N.TryGetSecurity(child, N.OwnerSecurityInformation | N.DaclSecurityInformation, out _) is not { } sd)
        {
            return what;
        }

        return policy.Check(sd, out var why) == StoreAclStatus.Ok ? null : $"{what} ({why})";
    }

    private static string ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0') || !Path.IsPathFullyQualified(path))
        {
            throw new QuarantineStoreException($"The sap-AV data folder '{path}' must be a fully qualified local path.");
        }

        string full = Path.GetFullPath(path).TrimEnd('\\');
        if (!QuarantinePath.TryValidateOriginalPath(full, out var why))
        {
            throw new QuarantineStoreException($"The sap-AV data folder '{path}' is not a local drive path: {why}.");
        }

        return full;
    }
}
