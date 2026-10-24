using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning;

/// <summary>Decides whether an engine folder may be excluded from scanning (review B H1, ROADMAP D3 M5). Fake it in tests.</summary>
public interface IFolderTrust
{
    /// <summary>Null if <paramref name="folder"/> is verified; otherwise why not (engine text).</summary>
    string? Problem(string folder);
}

/// <summary>
/// An engine folder is trusted only if no standard user can have put anything in it: owned by SYSTEM, Administrators or
/// TrustedInstaller, no allow entry that gives anyone else a write-type right (on the folder itself, or inheritable to what
/// is created in it), reached without any junction / symlink / mount point (<see cref="SafeTree"/>, bound to handles),
/// and a parent that no one else can rename it out of (no FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER or GENERIC_ALL for
/// others, trusted owner). Deny entries are ignored (fails safe: a folder only looks less trusted).
/// </summary>
public sealed class FolderTrust : IFolderTrust
{
    public static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>Rights that let a holder change a folder's content, attributes, ACL or owner.</summary>
    internal const int WriteRights = 0x0002 /* FILE_ADD_FILE */ | 0x0004 /* FILE_ADD_SUBDIRECTORY */ | 0x0010 /* FILE_WRITE_EA */
        | 0x0040 /* FILE_DELETE_CHILD */ | 0x0100 /* FILE_WRITE_ATTRIBUTES */ | 0x00010000 /* DELETE */ | 0x00040000 /* WRITE_DAC */
        | 0x00080000 /* WRITE_OWNER */ | 0x10000000 /* GENERIC_ALL */ | 0x40000000 /* GENERIC_WRITE */;

    /// <summary>Rights on the parent that would let a holder rename or replace the folder.</summary>
    internal const int ParentRights = 0x0040 /* FILE_DELETE_CHILD */ | 0x00040000 | 0x00080000 | 0x10000000;

    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    private readonly HashSet<SecurityIdentifier> _trusted;

    /// <param name="additionalTrusted">Test seam only: extra SIDs trusted like SYSTEM (a non-elevated test owns its folders).</param>
    internal FolderTrust(IEnumerable<SecurityIdentifier>? additionalTrusted = null)
    {
        _trusted = [new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            TrustedInstaller, .. additionalTrusted ?? []];
    }

    /// <summary>SYSTEM, Administrators and TrustedInstaller.</summary>
    public static FolderTrust Default { get; } = new();

    public string? Problem(string folder)
    {
        string trimmed = folder.TrimEnd('\\');
        using (var handle = Open(trimmed, out var failure))
        {
            if (handle is null)
            {
                return $"it can't be opened without following links ({failure})";
            }

            if (Judge(handle, WriteRights, inheritable: true) is { } problem)
            {
                return problem;
            }
        }

        string? parent = Path.GetDirectoryName(Core.Hashing.ExactPath.StripPrefix(Core.Hashing.ExactPath.ToExtended(trimmed) ?? trimmed));
        if (parent is null)
        {
            return null;
        }

        using var parentHandle = Open(parent, out var parentFailure);
        if (parentHandle is null)
        {
            return $"its parent folder can't be opened without following links ({parentFailure})";
        }

        return Judge(parentHandle, ParentRights, inheritable: false) is { } parentProblem ? "its parent folder: " + parentProblem : null;
    }

    /// <summary>Null if the descriptor is admin-only for <paramref name="rights"/>; otherwise why not.</summary>
    internal string? Judge(byte[] descriptor, int rights, bool inheritable)
    {
        var sd = new RawSecurityDescriptor(descriptor, 0);
        if (sd.Owner is null || !_trusted.Contains(sd.Owner))
        {
            return $"owner {sd.Owner?.Value ?? "none"} is not SYSTEM, Administrators or TrustedInstaller";
        }

        if (sd.DiscretionaryAcl is null || (sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
        {
            return "it has no DACL (everyone has full access)";
        }

        foreach (var ace in sd.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce qualified)
            {
                return $"an unsupported access entry ({ace.AceType})";
            }

            if (qualified.AceQualifier != AceQualifier.AccessAllowed || _trusted.Contains(qualified.SecurityIdentifier)
                || qualified.SecurityIdentifier == CreatorOwner || qualified.SecurityIdentifier == OwnerRights)
            {
                continue; // deny entries; trusted SIDs; CREATOR OWNER / OWNER RIGHTS stand for a (trusted) owner or creator
            }

            bool here = (qualified.AceFlags & AceFlags.InheritOnly) == 0;
            bool inherits = (qualified.AceFlags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) != 0;
            if ((here || (inheritable && inherits)) && (qualified.AccessMask & rights) != 0)
            {
                return $"{qualified.SecurityIdentifier.Value} may write to it (access mask 0x{qualified.AccessMask:X})";
            }
        }

        return null;
    }

    private string? Judge(SafeFileHandle handle, int rights, bool inheritable)
    {
        var descriptor = N.TryGetSecurity(handle, N.OwnerSecurityInformation | N.DaclSecurityInformation, out int error);
        return descriptor is null ? $"its ACL can't be read (Win32 error {error})" : Judge(descriptor, rights, inheritable);
    }

    private static SafeFileHandle? Open(string path, out SafeTreeFailure failure) =>
        SafeTree.Open(path, SafeTree.InspectAccess, SafeTree.ShareAll, N.FileDirectoryFile, out failure, out _);
}
