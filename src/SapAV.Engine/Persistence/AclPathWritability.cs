using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Persistence;

/// <summary>
/// The engine's <see cref="IPathWritability"/> (ROADMAP C3): reads the owner and DACL of a file or folder and decides
/// whether a <b>non-administrator</b> principal can write it, never from the folder's name.
/// </summary>
/// <remarks>
/// <para><b>Opening.</b> Attributes + READ_CONTROL only, through <see cref="SafeTree"/>: component by component, no
/// junction / symlink / mount point followed, never a UNC path or network drive (so SYSTEM never authenticates to a server),
/// no cloud recall, no content read. Anything that can't be opened that way is <see cref="Writability.Unknown"/>.</para>
/// <para><b>Who counts as an administrator.</b> SYSTEM, Administrators, TrustedInstaller and other service SIDs
/// (<c>S-1-5-80-…</c>), LocalService / NetworkService, Backup and Server Operators, Hyper-V VMs (<c>S-1-5-83-…</c>), and
/// AppContainer / capability SIDs (<c>S-1-15-…</c>, sandboxed apps rather than users). Everyone else (users, Users,
/// Authenticated Users, Everyone, INTERACTIVE, domain groups) is a standard user.</para>
/// <para><b>Rules.</b> A descriptor is user-writable for a set of rights when it has no DACL, or an allow entry that applies
/// to the object itself (not inherit-only) gives a standard user one of those rights, or the owner is a standard user (an
/// owner can always rewrite the DACL) unless an OWNER RIGHTS entry limits it to rights outside the set. CREATOR OWNER
/// entries only shape what is created later and are skipped. <b>Deny entries are ignored</b>: that can only make an object
/// look more writable (more findings), never hide one.</para>
/// <para>Rights: modifying a file = write data, append data, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE / GENERIC_ALL; creating a
/// file in a folder = add file (same bit as write data) or those owner / generic rights; creating a missing folder = add
/// subdirectory (same bit as append data) on the nearest existing ancestor. Answers are cached per instance (use one per
/// scan, so later changes are seen). Thread-safe.</para>
/// </remarks>
internal sealed class AclPathWritability : IPathWritability
{
    internal const int WriteData = 0x0002; // FILE_WRITE_DATA / FILE_ADD_FILE
    internal const int AppendData = 0x0004; // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    internal const int OwnerAndGeneric = 0x00040000 /* WRITE_DAC */ | 0x00080000 /* WRITE_OWNER */ | 0x10000000 /* GENERIC_ALL */ | 0x40000000 /* GENERIC_WRITE */;
    internal const int ModifyFileRights = WriteData | AppendData | OwnerAndGeneric;
    internal const int AddFileRights = WriteData | OwnerAndGeneric;
    internal const int AddFolderRights = AppendData | OwnerAndGeneric;

    private const int MaxDepth = 64;

    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    private static readonly HashSet<string> AdminSids = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544", "S-1-5-32-549", "S-1-5-32-551",
    };

    private readonly HashSet<SecurityIdentifier> _additionalTrusted;
    private readonly Dictionary<string, Writability> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    /// <param name="additionalTrusted">Test seam only: SIDs treated like administrators (a non-elevated test owns its folders).</param>
    internal AclPathWritability(IEnumerable<SecurityIdentifier>? additionalTrusted = null) => _additionalTrusted = [.. additionalTrusted ?? []];

    public AclPathWritability()
        : this(null)
    {
    }

    public Writability FileModifiable(string filePath) =>
        Cached("M|" + filePath, () => Check(filePath, N.FileNonDirectoryFile | SafeTree.OpenNoRecall, ModifyFileRights));

    public Writability FileCreatable(string filePath) => Cached("C|" + filePath, () => Creatable(filePath));

    /// <summary>Whether <paramref name="descriptor"/> (self-relative, with owner and DACL) gives a standard user any of <paramref name="rights"/>.</summary>
    internal Writability Evaluate(byte[] descriptor, int rights)
    {
        RawSecurityDescriptor sd;
        try
        {
            sd = new RawSecurityDescriptor(descriptor, 0);
        }
        catch (ArgumentException)
        {
            return Writability.Unknown;
        }

        if ((sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || sd.DiscretionaryAcl is null)
        {
            return Writability.UserWritable; // no DACL: everyone has full access
        }

        bool ownerIsUser = sd.Owner is null || !IsAdmin(sd.Owner);
        bool ownerRightsLimited = false;
        foreach (var ace in sd.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce allowed || allowed.AceQualifier != AceQualifier.AccessAllowed || (allowed.AceFlags & AceFlags.InheritOnly) != 0)
            {
                continue;
            }

            var sid = allowed.SecurityIdentifier;
            bool grants = (allowed.AccessMask & rights) != 0;
            if (sid == OwnerRights)
            {
                ownerRightsLimited = true;
                if (ownerIsUser && grants)
                {
                    return Writability.UserWritable;
                }

                continue;
            }

            if (sid == CreatorOwner || IsAdmin(sid))
            {
                continue;
            }

            if (grants)
            {
                return Writability.UserWritable;
            }
        }

        return ownerIsUser && !ownerRightsLimited ? Writability.UserWritable : Writability.AdminOnly;
    }

    private bool IsAdmin(SecurityIdentifier sid)
    {
        string value = sid.Value;
        return AdminSids.Contains(value) || _additionalTrusted.Contains(sid)
            || value.StartsWith("S-1-5-80-", StringComparison.Ordinal) || value.StartsWith("S-1-5-83-", StringComparison.Ordinal)
            || value.StartsWith("S-1-15-", StringComparison.Ordinal);
    }

    /// <summary>The folder allows new files; a missing folder: the nearest existing ancestor allows new subfolders.</summary>
    private Writability Creatable(string filePath)
    {
        string? folder = Parent(filePath);
        int rights = AddFileRights;
        for (int depth = 0; folder is not null && depth < MaxDepth; depth++)
        {
            using var handle = SafeTree.Open(folder, SafeTree.InspectAccess, SafeTree.ShareAll, N.FileDirectoryFile, out var failure, out _);
            if (handle is not null)
            {
                return Describe(handle, rights);
            }

            if (failure != SafeTreeFailure.NotFound)
            {
                return Writability.Unknown; // a link on the way, access denied, a remote or odd path
            }

            rights = AddFolderRights;
            folder = Parent(folder);
        }

        return Writability.Unknown;
    }

    private Writability Check(string path, uint options, int rights)
    {
        using var handle = SafeTree.Open(path, SafeTree.InspectAccess, SafeTree.ShareAll, options, out _, out _);
        return handle is null ? Writability.Unknown : Describe(handle, rights);
    }

    private Writability Describe(SafeFileHandle handle, int rights)
    {
        var descriptor = N.TryGetSecurity(handle, N.OwnerSecurityInformation | N.DaclSecurityInformation, out _);
        return descriptor is null ? Writability.Unknown : Evaluate(descriptor, rights);
    }

    private static string? Parent(string path)
    {
        try
        {
            return Path.GetDirectoryName(path.TrimEnd('\\'));
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private Writability Cached(string key, Func<Writability> compute)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var known))
            {
                return known;
            }
        }

        Writability value;
        try
        {
            value = compute();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.ComponentModel.Win32Exception)
        {
            value = Writability.Unknown;
        }

        lock (_lock)
        {
            if (_cache.Count > 20_000)
            {
                _cache.Clear();
            }

            _cache[key] = value;
        }

        return value;
    }
}
