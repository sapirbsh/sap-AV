using System.Security.AccessControl;
using System.Security.Principal;

namespace SapAV.Engine.Pipe;

/// <summary>
/// The engine pipe's security descriptor (B4), built explicitly, never from defaults:
/// <list type="bullet">
/// <item>SYSTEM: full control.</item>
/// <item>The engine's own account, when it isn't SYSTEM (console debugging): full control, so it can create more instances.</item>
/// <item>Authenticated Users: read/write to connect (<see cref="ClientAccess"/>), but <b>not</b> FILE_CREATE_PIPE_INSTANCE,
/// so no other account can add a server instance and receive clients' requests.</item>
/// </list>
/// The DACL is protected. No ACE for ALL APPLICATION PACKAGES, so AppContainer processes can't connect; the implicit Medium
/// no-write-up label keeps Low-integrity processes out.
/// </summary>
public static class EnginePipeSecurity
{
    /// <summary>FILE_ALL_ACCESS.</summary>
    public const int FullControl = 0x001F01FF;

    /// <summary>FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE (0x4).</summary>
    public const int ClientAccess = (0x00120089 | 0x00120116) & ~0x4;

    /// <summary>The access a client opens the pipe with (what <see cref="Core.Pipe.EnginePipeClient"/> requests).</summary>
    public const int ClientOpenAccess = 0x0001 | 0x0002 | 0x0080 | 0x0100 | 0x00020000 | 0x00100000;

    public static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    public static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);

    /// <param name="serverAccount">The engine's account; null or SYSTEM adds no extra entry (tests pass null to prove a
    /// non-SYSTEM account can't create instances).</param>
    public static RawSecurityDescriptor Create(SecurityIdentifier? serverAccount)
    {
        var acl = new RawAcl(GenericAcl.AclRevision, 3);
        acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, FullControl, LocalSystem, false, null));
        if (serverAccount is not null && serverAccount != LocalSystem)
        {
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, FullControl, serverAccount, false, null));
        }

        acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, ClientAccess, AuthenticatedUsers, false, null));
        return new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected, null, null, null, acl);
    }

    public static byte[] ToBytes(RawSecurityDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>The engine's own account (SYSTEM as a service).</summary>
    public static SecurityIdentifier CurrentAccount()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User!;
    }
}
