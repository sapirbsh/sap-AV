using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Quarantine.Native;

/// <summary>
/// Section B M3: runs one call with <c>SeRestorePrivilege</c> enabled on the <b>calling thread only</b>. The engine
/// (SYSTEM) needs it to make a restored file owned by the user who asked for it. It is never enabled on the process token:
/// with SeRestorePrivilege enabled, any open with FILE_FLAG_BACKUP_SEMANTICS for write access bypasses the DACL, and the
/// engine's other threads open files with backup semantics all the time.
/// </summary>
/// <remarks>
/// <c>ImpersonateSelf</c> gives this thread its own copy of the process token; the privilege is enabled on that copy for
/// the call and disabled again, then <c>RevertToSelf</c> drops the copy. If reverting fails, the process is terminated
/// (<see cref="Environment.FailFast(string)"/>): a pooled thread must never keep running on a token with the privilege on.
/// </remarks>
internal static class RestorePrivilege
{
    private const int SecurityImpersonation = 2;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x2;
    private const int ErrorNotAllAssigned = 1300;

    /// <summary>
    /// Runs <paramref name="action"/> (which returns a Win32 error, 0 = success) with SeRestorePrivilege enabled on this
    /// thread. Returns the action's result, or the Win32 error that kept the privilege from being enabled (e.g. 1300,
    /// ERROR_NOT_ALL_ASSIGNED, when the account doesn't hold it); the action doesn't run then.
    /// </summary>
    public static int Run(Func<int> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (!ImpersonateSelf(SecurityImpersonation))
        {
            return Marshal.GetLastPInvokeError();
        }

        try
        {
            if (!OpenThreadToken(GetCurrentThread(), TokenAdjustPrivileges | TokenQuery, openAsSelf: true, out var token))
            {
                return Marshal.GetLastPInvokeError();
            }

            using (token)
            {
                if (!LookupPrivilegeValueW(null, "SeRestorePrivilege", out long luid))
                {
                    return Marshal.GetLastPInvokeError();
                }

                int enabled = Adjust(token, luid, SePrivilegeEnabled);
                if (enabled != 0)
                {
                    return enabled;
                }

                try
                {
                    return action();
                }
                finally
                {
                    _ = Adjust(token, luid, 0);
                }
            }
        }
        finally
        {
            if (!RevertToSelf())
            {
                Environment.FailFast("sap-AV: could not drop the thread token after using SeRestorePrivilege.");
            }
        }
    }

    /// <summary>True if the calling thread is impersonating (has its own token). For tests: after <see cref="Run"/> it must not be.</summary>
    internal static bool ThreadHasToken()
    {
        if (OpenThreadToken(GetCurrentThread(), TokenQuery, openAsSelf: true, out var token))
        {
            token.Dispose();
            return true;
        }

        token.Dispose();
        return false;
    }

    private static unsafe int Adjust(SafeAccessTokenHandle token, long luid, uint attributes)
    {
        var privileges = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = attributes };
        if (!AdjustTokenPrivileges(token, false, &privileges, (uint)sizeof(TokenPrivileges), IntPtr.Zero, IntPtr.Zero))
        {
            return Marshal.GetLastPInvokeError();
        }

        int error = Marshal.GetLastPInvokeError(); // success can still mean "not all assigned"
        return error == ErrorNotAllAssigned ? ErrorNotAllAssigned : 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateSelf(int impersonationLevel);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(IntPtr thread, uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool AdjustTokenPrivileges(
        SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, TokenPrivileges* newState, uint bufferLength,
        IntPtr previousState, IntPtr returnLength);
}
