using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Engine.Sandbox.Native;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// The DACL of the worker's process and initial thread objects (review H1). Without it, CreateProcess uses the token's
/// default DACL, which for an AppContainer process grants the container SID access to its own process: any process
/// running with the same AppContainer SID could then open the worker (memory, handles: the brokered file handles).
/// </summary>
/// <remarks>
/// Protected DACL: SYSTEM and Administrators full access, OWNER RIGHTS only READ_CONTROL (the owner loses the implicit
/// WRITE_DAC, so the creating account can't widen it later either). No user, logon, Everyone, Authenticated Users,
/// ALL APPLICATION PACKAGES or AppContainer SID. The broker keeps working through the full-access handles CreateProcess
/// returns; the worker uses its own pseudo-handles, which no DACL restricts.
/// </remarks>
internal static class WorkerObjectSecurity
{
    private const int AllAccess = 0x001FFFFF; // PROCESS_ALL_ACCESS / THREAD_ALL_ACCESS
    private const int ReadControl = 0x00020000;

    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    /// <summary>The DACL in binary form.</summary>
    public static byte[] DaclBytes()
    {
        var acl = new RawAcl(GenericAcl.AclRevision, 3);
        acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, AllAccess, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), false, null));
        acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, AllAccess, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), false, null));
        acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, ReadControl, OwnerRights, false, null));
        var bytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>A self-relative descriptor with only that protected DACL (for SECURITY_ATTRIBUTES).</summary>
    public static byte[] DescriptorBytes()
    {
        var acl = new RawAcl(DaclBytes(), 0);
        var sd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected, null, null, null, acl);
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>Sets the protected DACL on a process or thread handle (the broker's full-access handle).</summary>
    /// <exception cref="SandboxUnavailableException">SetSecurityInfo failed.</exception>
    public static unsafe void Apply(SafeHandle handle, string what)
    {
        fixed (byte* dacl = DaclBytes())
        {
            int error = SandboxNative.SetSecurityInfo(handle, SandboxNative.SeKernelObject,
                SandboxNative.DaclSecurityInformation | SandboxNative.ProtectedDaclSecurityInformation, IntPtr.Zero, IntPtr.Zero, (IntPtr)dacl, IntPtr.Zero);
            if (error != 0)
            {
                throw new SandboxUnavailableException($"Could not set the {what} DACL of the scan worker: {new Win32Exception(error).Message}");
            }
        }
    }

    /// <summary>The object's current DACL (tests and the start check).</summary>
    public static RawSecurityDescriptor Read(SafeHandle handle)
    {
        int error = SandboxNative.GetSecurityInfo(handle, SandboxNative.SeKernelObject, SandboxNative.DaclSecurityInformation,
            IntPtr.Zero, IntPtr.Zero, out _, IntPtr.Zero, out IntPtr sd);
        if (error != 0)
        {
            throw new Win32Exception(error, "GetSecurityInfo on the scan worker");
        }

        try
        {
            var bytes = new byte[SandboxNative.GetSecurityDescriptorLength(sd)];
            Marshal.Copy(sd, bytes, 0, bytes.Length);
            return new RawSecurityDescriptor(bytes, 0);
        }
        finally
        {
            SandboxNative.LocalFree(sd);
        }
    }

    /// <summary>True if every allow entry is SYSTEM, Administrators or OWNER RIGHTS (READ_CONTROL only), and the DACL is protected.</summary>
    public static bool IsLockedDown(RawSecurityDescriptor sd)
    {
        if (sd.DiscretionaryAcl is null || (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
        {
            return false;
        }

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        foreach (var ace in sd.DiscretionaryAcl)
        {
            if (ace is not CommonAce common || common.AceQualifier != AceQualifier.AccessAllowed)
            {
                continue; // deny entries never widen access
            }

            bool allowed = common.SecurityIdentifier == system || common.SecurityIdentifier == admins
                || (common.SecurityIdentifier == OwnerRights && (common.AccessMask & ~ReadControl) == 0);
            if (!allowed)
            {
                return false;
            }
        }

        return true;
    }
}
