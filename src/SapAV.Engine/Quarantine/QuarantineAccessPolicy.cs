using System.Security.AccessControl;
using System.Security.Principal;

namespace SapAV.Engine.Quarantine;

/// <summary>Result of checking the store root's security descriptor.</summary>
public enum StoreAclStatus
{
    /// <summary>Protected DACL, only trusted SIDs allowed, trusted owner.</summary>
    Ok,

    /// <summary>The DACL allows someone else, inherits, or is missing.</summary>
    Wider,

    /// <summary>The owner is not SYSTEM, Administrators or the engine's own account (the owner can rewrite the DACL).</summary>
    UntrustedOwner,
}

/// <summary>
/// Who may access the quarantine store: <b>SYSTEM and Administrators only</b>. The root has a protected DACL (no
/// inheritance from <c>%ProgramData%</c>) with full control on the folder, and an inherit-only entry for files that
/// is full control <b>without FILE_EXECUTE</b>, so every stored file gets a no-execute ACL.
/// </summary>
public sealed class QuarantineAccessPolicy
{
    /// <summary>FILE_ALL_ACCESS.</summary>
    public const int FullControl = 0x001F01FF;

    /// <summary>FILE_ALL_ACCESS without FILE_EXECUTE (0x20), for stored files.</summary>
    public const int FullControlNoExecute = FullControl & ~0x20;

    public static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    public static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private readonly SecurityIdentifier[] _trusted;
    private readonly HashSet<SecurityIdentifier> _trustedOwners;

    /// <param name="additionalTrustedSids">
    /// Test seam only: extra SIDs treated like SYSTEM/Administrators, so a non-elevated test can use a temp store.
    /// Never set in production (<see cref="QuarantineOptions"/> keeps it internal, so configuration can't set it).
    /// </param>
    internal QuarantineAccessPolicy(IEnumerable<SecurityIdentifier>? additionalTrustedSids = null)
    {
        _trusted = new[] { LocalSystem, Administrators }.Concat(additionalTrustedSids ?? []).Distinct().ToArray();
        using var self = WindowsIdentity.GetCurrent();
        _trustedOwners = [.. _trusted, self.User!];
    }

    /// <summary>The production policy: SYSTEM + Administrators.</summary>
    public static QuarantineAccessPolicy Default { get; } = new();

    /// <summary>SIDs that get access to the store.</summary>
    public IReadOnlyList<SecurityIdentifier> TrustedSids => _trusted;

    /// <summary>Accepted owners of the store and its files: the trusted SIDs and the engine's own account.</summary>
    public bool IsTrustedOwner(SecurityIdentifier? owner) => owner is not null && _trustedOwners.Contains(owner);

    /// <summary>The store root's DACL (see the class remarks).</summary>
    public RawAcl CreateRootDacl()
    {
        var acl = new RawAcl(GenericAcl.AclRevision, _trusted.Length * 2);
        foreach (var sid in _trusted)
        {
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, FullControl, sid, false, null));
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.ObjectInherit | AceFlags.InheritOnly, AceQualifier.AccessAllowed,
                FullControlNoExecute, sid, false, null));
        }

        return acl;
    }

    /// <summary>A self-relative descriptor with only the protected DACL (owner = the creating account).</summary>
    public byte[] CreateRootSecurityDescriptor()
    {
        var sd = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected, null, null, null, CreateRootDacl());
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>The root DACL in binary form, for <c>SetSecurityInfo</c>.</summary>
    public byte[] CreateRootDaclBytes()
    {
        var acl = CreateRootDacl();
        var bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>
    /// Checks a directory's descriptor (owner + DACL). Wider = no DACL, not protected, or any allow entry for a SID
    /// outside <see cref="TrustedSids"/> (deny entries never widen access).
    /// </summary>
    public StoreAclStatus Check(byte[] securityDescriptor, out string reason)
    {
        var sd = new RawSecurityDescriptor(securityDescriptor, 0);
        if (!IsTrustedOwner(sd.Owner))
        {
            reason = $"owner {sd.Owner?.Value ?? "none"} is not SYSTEM, Administrators or the engine account";
            return StoreAclStatus.UntrustedOwner;
        }

        if (sd.DiscretionaryAcl is null || (sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
        {
            reason = "no DACL (everyone has full access)";
            return StoreAclStatus.Wider;
        }

        if ((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
        {
            reason = "the DACL inherits from the parent folder";
            return StoreAclStatus.Wider;
        }

        foreach (var ace in sd.DiscretionaryAcl)
        {
            switch (ace)
            {
                case QualifiedAce q when q.AceQualifier == AceQualifier.AccessDenied:
                    continue;
                case KnownAce k when k is QualifiedAce { AceQualifier: AceQualifier.AccessAllowed } && _trusted.Contains(k.SecurityIdentifier):
                    continue;
                case KnownAce k:
                    reason = $"an access entry allows {k.SecurityIdentifier.Value}";
                    return StoreAclStatus.Wider;
                default:
                    reason = $"an unsupported access entry ({ace.AceType})";
                    return StoreAclStatus.Wider;
            }
        }

        reason = string.Empty;
        return StoreAclStatus.Ok;
    }
}
