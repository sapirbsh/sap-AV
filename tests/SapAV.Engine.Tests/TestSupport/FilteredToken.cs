using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// A "standard user" copy of the test process token: BUILTIN\Administrators made deny-only and every privilege except
/// SeChangeNotifyPrivilege removed (CreateRestrictedToken with DISABLE_MAX_PRIVILEGE), the same as a UAC-filtered admin
/// or a normal user. Works whether or not the test runs elevated, and needs no rights.
/// </summary>
internal static class FilteredToken
{
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenImpersonate = 0x0004;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint DisableMaxPrivilege = 0x1;
    private const int SecurityImpersonation = 2;
    private const int TokenTypeImpersonation = 2;

    /// <summary>An impersonation token (SecurityImpersonation) without administrator rights; usable for AccessCheck and impersonation.</summary>
    public static SafeAccessTokenHandle CreateNonAdmin()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenDuplicate | TokenQuery | TokenAssignPrimary, out var process))
        {
            throw new Win32Exception();
        }

        using (process)
        {
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var sidBytes = new byte[administrators.BinaryLength];
            administrators.GetBinaryForm(sidBytes, 0);
            var sid = GCHandle.Alloc(sidBytes, GCHandleType.Pinned);
            try
            {
                SidAndAttributes[] disable = [new SidAndAttributes { Sid = sid.AddrOfPinnedObject(), Attributes = 0 }];
                if (!CreateRestrictedToken(process, DisableMaxPrivilege, 1, disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out var restricted))
                {
                    throw new Win32Exception();
                }

                using (restricted)
                {
                    if (!DuplicateTokenEx(restricted, TokenQuery | TokenImpersonate | TokenDuplicate, IntPtr.Zero,
                            SecurityImpersonation, TokenTypeImpersonation, out var impersonation))
                    {
                        throw new Win32Exception();
                    }

                    return impersonation;
                }
            }
            finally
            {
                sid.Free();
            }
        }
    }

    /// <summary>The rights <paramref name="token"/> gets from <paramref name="descriptor"/> when asking for <paramref name="desired"/> (0 = denied).</summary>
    public static int GrantedAccess(SafeAccessTokenHandle token, RawSecurityDescriptor descriptor, int desired)
    {
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        var mapping = new GenericMapping { Read = 0x1, Write = 0x2, Execute = 0, All = 0x7 };
        var privileges = new byte[256];
        int privilegesLength = privileges.Length;
        if (!AccessCheck(bytes, token, desired, ref mapping, privileges, ref privilegesLength, out int granted, out bool status))
        {
            throw new Win32Exception();
        }

        return status ? granted : 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        public uint Read;
        public uint Write;
        public uint Execute;
        public uint All;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(
        SafeAccessTokenHandle existing, uint flags, uint disableSidCount, SidAndAttributes[] sidsToDisable,
        uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictedSidCount, IntPtr sidsToRestrict,
        out SafeAccessTokenHandle newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        SafeAccessTokenHandle existing, uint access, IntPtr attributes, int impersonationLevel, int tokenType,
        out SafeAccessTokenHandle newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(
        byte[] securityDescriptor, SafeAccessTokenHandle clientToken, int desiredAccess, ref GenericMapping mapping,
        byte[] privilegeSet, ref int privilegeSetLength, out int grantedAccess,
        [MarshalAs(UnmanagedType.Bool)] out bool accessStatus);
}
