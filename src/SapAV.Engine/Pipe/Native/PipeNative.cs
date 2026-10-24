using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Pipe.Native;

/// <summary>Win32 calls for the engine pipe (B4): pipe creation, client identity, and access checks with a client token.</summary>
internal static unsafe class PipeNative
{
    public const uint PipeAccessDuplex = 0x00000003;
    public const uint FileFlagFirstPipeInstance = 0x00080000;
    public const uint FileFlagOverlapped = 0x40000000;
    public const uint PipeTypeByte = 0x0;
    public const uint PipeReadModeByte = 0x0;
    public const uint PipeWait = 0x0;
    public const uint PipeRejectRemoteClients = 0x00000008;

    public const uint FileReadData = 0x0001;          // FILE_LIST_DIRECTORY on folders
    public const uint FileAddFile = 0x0002;           // on folders
    public const uint FileDeleteChild = 0x0040;       // on folders
    public const uint Delete = 0x00010000;
    public const uint ReadControl = 0x00020000;
    public const uint FileCreatePipeInstance = 0x0004;

    public const int ErrorAccessDenied = 5;
    public const int ErrorPipeBusy = 231;
    public const int ErrorCantOpenAnonymous = 1347;
    public const int ErrorFileNotFound = 2;
    public const int ErrorPathNotFound = 3;

    public const int DriveRemote = 4;

    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenImpersonate = 0x0004;
    private const int SecurityIdentification = 1;
    private const int TokenImpersonationType = 2;

    private const int TokenUserClass = 1;
    private const int TokenImpersonationLevelClass = 9;
    private const int TokenSessionIdClass = 12;
    private const int TokenElevationClass = 20;
    private const int TokenIntegrityLevelClass = 25;

    private const int SeFileObject = 1;
    private const int SeKernelObject = 6;
    private const uint OwnerSecurityInformation = 0x1;
    private const uint GroupSecurityInformation = 0x2;
    private const uint DaclSecurityInformation = 0x4;
    private const uint LabelSecurityInformation = 0x10;

    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileShareAll = 0x7;

    /// <summary>The file object generic mapping (FILE_GENERIC_READ / WRITE / EXECUTE / FILE_ALL_ACCESS).</summary>
    private static GenericMapping FileMapping => new() { Read = 0x00120089, Write = 0x00120116, Execute = 0x001200A0, All = 0x001F01FF };

    /// <summary>Creates one pipe instance with an explicit security descriptor (overlapped, byte mode). Invalid handle on failure.</summary>
    public static SafePipeHandle CreatePipe(string fullName, uint openMode, uint pipeMode, int maxInstances, int bufferSize, byte[] securityDescriptor, out int error)
    {
        fixed (byte* sd = securityDescriptor)
        {
            var attributes = new SecurityAttributes { Length = sizeof(SecurityAttributes), SecurityDescriptor = (IntPtr)sd, InheritHandle = 0 };
            var handle = CreateNamedPipeW(fullName, openMode, pipeMode, (uint)maxInstances, (uint)bufferSize, (uint)bufferSize, 0, &attributes);
            error = handle.IsInvalid ? Marshal.GetLastPInvokeError() : 0;
            return handle;
        }
    }

    public static bool TryGetClientProcessId(SafePipeHandle pipe, out int processId)
    {
        bool ok = GetNamedPipeClientProcessId(pipe, out uint pid);
        processId = ok ? (int)pid : 0;
        return ok;
    }

    /// <summary>
    /// The client's token, captured by impersonating the client on <b>this thread only</b> and reverting in
    /// <c>finally</c>. Nothing else runs while impersonating. If reverting fails the process is ended: a thread left
    /// running as the client must never run engine code.
    /// </summary>
    /// <returns>The token (identification level or higher), or null with the Win32 error.</returns>
    public static SafeAccessTokenHandle? CaptureClientToken(SafePipeHandle pipe, out int error)
    {
        if (!ImpersonateNamedPipeClient(pipe))
        {
            error = Marshal.GetLastPInvokeError();
            return null;
        }

        SafeAccessTokenHandle? token = null;
        try
        {
            if (!OpenThreadToken(GetCurrentThread(), TokenQuery | TokenDuplicate, openAsSelf: true, out token))
            {
                error = Marshal.GetLastPInvokeError();
                token.Dispose();
                token = null;
            }
            else
            {
                error = 0;
            }
        }
        finally
        {
            if (!RevertToSelf())
            {
                Environment.FailFast("sap-AV engine: RevertToSelf failed after impersonating a pipe client.");
            }
        }

        return token;
    }

    /// <summary>An identification-level copy of the current process token (console runs and tests).</summary>
    public static SafeAccessTokenHandle DuplicateProcessTokenForIdentification()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery | TokenDuplicate, out var processToken))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
        }

        using (processToken)
        {
            return DuplicateIdentification(processToken);
        }
    }

    /// <summary>A copy of an (impersonation or primary) token at identification level, for AccessCheck.</summary>
    public static SafeAccessTokenHandle DuplicateIdentification(SafeAccessTokenHandle token)
    {
        if (!DuplicateTokenEx(token, TokenQuery | TokenDuplicate | TokenImpersonate, IntPtr.Zero, SecurityIdentification, TokenImpersonationType,
            out var duplicate))
        {
            int error = Marshal.GetLastPInvokeError();
            duplicate.Dispose();
            throw new System.ComponentModel.Win32Exception(error);
        }

        return duplicate;
    }

    public static byte[]? TokenUserSid(SafeAccessTokenHandle token)
    {
        var buffer = QueryToken(token, TokenUserClass);
        if (buffer is null)
        {
            return null;
        }

        fixed (byte* p = buffer)
        {
            IntPtr sid = *(IntPtr*)p; // TOKEN_USER.User.Sid
            int length = GetLengthSid(sid);
            var bytes = new byte[length];
            Marshal.Copy(sid, bytes, 0, length);
            return bytes;
        }
    }

    public static int? TokenSessionId(SafeAccessTokenHandle token) => QueryInt(token, TokenSessionIdClass);

    public static bool? TokenIsElevated(SafeAccessTokenHandle token) => QueryInt(token, TokenElevationClass) is { } v ? v != 0 : null;

    /// <summary>SECURITY_IMPERSONATION_LEVEL of an impersonation token (0 anonymous, 1 identification, 2 impersonation, 3 delegation).</summary>
    public static int? TokenImpersonationLevel(SafeAccessTokenHandle token) => QueryInt(token, TokenImpersonationLevelClass);

    /// <summary>The mandatory integrity level RID (e.g. 0x2000 Medium, 0x3000 High, 0x4000 System), or null.</summary>
    public static int? TokenIntegrityRid(SafeAccessTokenHandle token)
    {
        var buffer = QueryToken(token, TokenIntegrityLevelClass);
        if (buffer is null)
        {
            return null;
        }

        fixed (byte* p = buffer)
        {
            IntPtr sid = *(IntPtr*)p; // TOKEN_MANDATORY_LABEL.Label.Sid
            byte count = *GetSidSubAuthorityCount(sid);
            return count == 0 ? null : (int)*GetSidSubAuthority(sid, (uint)(count - 1));
        }
    }

    /// <summary>CheckTokenMembership: the SID is an enabled group of the (impersonation) token.</summary>
    public static bool IsMember(SafeAccessTokenHandle token, byte[] sid)
    {
        fixed (byte* s = sid)
        {
            return CheckTokenMembership(token, (IntPtr)s, out int member) && member != 0;
        }
    }

    /// <summary>
    /// AccessCheck of <paramref name="token"/> against <paramref name="securityDescriptor"/> (self-relative, with owner,
    /// group and DACL) for <paramref name="desiredAccess"/> (specific file rights). False on any error (fails closed).
    /// Privileges are not used (AccessCheck never applies SeBackupPrivilege).
    /// </summary>
    public static bool IsGranted(SafeAccessTokenHandle token, byte[] securityDescriptor, uint desiredAccess)
    {
        var mapping = FileMapping;
        uint access = desiredAccess;
        MapGenericMask(ref access, ref mapping);
        var privileges = stackalloc byte[256];
        uint privilegesLength = 256;
        fixed (byte* sd = securityDescriptor)
        {
            if (!AccessCheck((IntPtr)sd, token, access, ref mapping, privileges, ref privilegesLength, out uint granted, out int status))
            {
                return false;
            }

            return status != 0 && (granted & access) == access;
        }
    }

    /// <summary>
    /// Opens <paramref name="path"/> itself (no reparse point followed) for READ_CONTROL only, as the engine, and returns its
    /// owner, group, DACL and label as a self-relative descriptor, and the open handle (the caller disposes it); null with
    /// the Win32 error when it can't be opened or read.
    /// </summary>
    public static byte[]? TryReadSecurity(string path, out SafeFileHandle? handle, out int error)
    {
        handle = CreateFileW(path, ReadControl, FileShareAll, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            handle = null;
            return null;
        }

        var bytes = TryReadSecurity(handle, SeFileObject, OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation | LabelSecurityInformation, out error);
        if (bytes is null)
        {
            handle.Dispose();
            handle = null;
        }

        return bytes;
    }

    /// <summary>The security descriptor of an open file handle (needs READ_CONTROL on it), or null.</summary>
    public static byte[]? TryReadFileSecurity(SafeHandle handle) =>
        TryReadSecurity(handle, SeFileObject, OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation | LabelSecurityInformation, out _);

    /// <summary>The owner + DACL of a kernel object handle (e.g. a pipe, read back in tests), or null.</summary>
    public static RawSecurityDescriptor? TryReadKernelObjectSecurity(SafeHandle handle)
    {
        var bytes = TryReadSecurity(handle, SeKernelObject, OwnerSecurityInformation | DaclSecurityInformation, out _);
        return bytes is null ? null : new RawSecurityDescriptor(bytes, 0);
    }

    /// <summary>GetDriveTypeW of the root (e.g. <c>C:\</c>) in the engine's own device namespace.</summary>
    public static int DriveType(string root) => GetDriveTypeW(root);

    private static byte[]? TryReadSecurity(SafeHandle handle, int objectType, uint information, out int error)
    {
        error = GetSecurityInfo(handle, objectType, information, out _, out _, out _, out _, out IntPtr descriptor);
        if (error != 0)
        {
            return null;
        }

        try
        {
            int length = (int)GetSecurityDescriptorLength(descriptor);
            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, length);
            return bytes;
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    private static byte[]? QueryToken(SafeAccessTokenHandle token, int informationClass)
    {
        GetTokenInformation(token, informationClass, null, 0, out uint needed);
        if (needed == 0 || needed > 64 * 1024)
        {
            return null;
        }

        var buffer = new byte[needed];
        fixed (byte* p = buffer)
        {
            return GetTokenInformation(token, informationClass, p, needed, out _) ? buffer : null;
        }
    }

    private static int? QueryInt(SafeAccessTokenHandle token, int informationClass)
    {
        int value;
        return GetTokenInformation(token, informationClass, &value, sizeof(int), out _) ? value : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        public uint Read;
        public uint Write;
        public uint Execute;
        public uint All;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafePipeHandle CreateNamedPipeW(
        string name, uint openMode, uint pipeMode, uint maxInstances, uint outBufferSize, uint inBufferSize, uint defaultTimeout,
        SecurityAttributes* securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateNamedPipeClient(SafePipeHandle pipe);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(IntPtr thread, uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        SafeAccessTokenHandle existing, uint desiredAccess, IntPtr attributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle duplicate);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, void* information, uint length, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckTokenMembership(SafeAccessTokenHandle token, IntPtr sid, out int isMember);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern byte* GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint* GetSidSubAuthority(IntPtr sid, uint index);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern void MapGenericMask(ref uint accessMask, ref GenericMapping mapping);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(
        IntPtr securityDescriptor, SafeAccessTokenHandle clientToken, uint desiredAccess, ref GenericMapping mapping, byte* privilegeSet,
        ref uint privilegeSetLength, out uint grantedAccess, out int accessStatus);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr template);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int GetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetDriveTypeW(string root);
}
