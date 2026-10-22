using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Quarantine.Native;

/// <summary>
/// Win32 / NT calls used by the quarantine: handle-relative opens (<c>NtCreateFile</c> with <c>RootDirectory</c>),
/// rename and delete by handle, basic info, final paths, security descriptors and machine-scope DPAPI.
/// </summary>
/// <remarks>Every path-free operation here works on a handle the caller already validated.</remarks>
internal static unsafe class QuarantineNative
{
    // Access rights.
    public const uint Delete = 0x00010000;
    public const uint ReadControl = 0x00020000;
    public const uint WriteDac = 0x00040000;
    public const uint WriteOwner = 0x00080000;
    public const uint Synchronize = 0x00100000;
    public const uint GenericRead = 0x80000000;
    public const uint GenericWrite = 0x40000000;
    public const uint FileReadAttributes = 0x0080;
    public const uint FileWriteAttributes = 0x0100;
    public const uint FileListDirectory = 0x0001;
    public const uint FileTraverse = 0x0020;
    public const uint FileExecute = 0x0020;

    public const uint ShareRead = 1;
    public const uint ShareWrite = 2;
    public const uint ShareDelete = 4;

    // NtCreateFile dispositions / options / object attributes.
    public const uint FileOpen = 1;
    public const uint FileCreate = 2;
    public const uint FileDirectoryFile = 0x00000001;
    public const uint FileSynchronousIoNonAlert = 0x00000020;
    public const uint FileNonDirectoryFile = 0x00000040;
    public const uint FileOpenReparsePoint = 0x00200000;
    public const uint ObjCaseInsensitive = 0x00000040;
    public const uint ObjDontReparse = 0x00001000;

    // CreateFileW.
    private const uint OpenExisting = 3;
    public const uint FlagBackupSemantics = 0x02000000;
    public const uint FlagOpenReparsePoint = 0x00200000;

    // Win32 errors.
    public const int ErrorFileNotFound = 2;
    public const int ErrorPathNotFound = 3;
    public const int ErrorAccessDenied = 5;
    public const int ErrorNotSameDevice = 17;
    public const int ErrorSharingViolation = 32;
    public const int ErrorLockViolation = 33;
    public const int ErrorFileExists = 80;
    public const int ErrorInvalidParameter = 87;
    public const int ErrorAlreadyExists = 183;
    public const int ErrorDirectory = 267;
    public const int ErrorInvalidOwner = 1307;
    public const int ErrorReparsePointEncountered = 4395;

    public const uint FileAttributeReparsePoint = 0x400;
    public const uint FileAttributeDirectory = 0x10;

    /// <summary>
    /// Opens or creates <paramref name="name"/> relative to the open directory (or file, for a stream name)
    /// <paramref name="root"/>, never resolving a path from the root of the namespace. Returns null and the Win32
    /// error on failure.
    /// </summary>
    public static SafeFileHandle? OpenRelative(
        SafeHandle root, string name, uint access, uint share, uint disposition, uint options, out int win32Error,
        uint objectAttributes = ObjCaseInsensitive, uint fileAttributes = 0)
    {
        bool added = false;
        root.DangerousAddRef(ref added);
        try
        {
            fixed (char* buffer = name)
            {
                var unicode = new UnicodeString
                {
                    Length = checked((ushort)(name.Length * 2)),
                    MaximumLength = checked((ushort)(name.Length * 2)),
                    Buffer = buffer,
                };
                var sqos = new SecurityQualityOfService { Length = (uint)sizeof(SecurityQualityOfService), ImpersonationLevel = 0 };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = root.DangerousGetHandle(),
                    ObjectName = &unicode,
                    Attributes = objectAttributes,
                    SecurityQualityOfService = &sqos,
                };

                int status = NtCreateFile(out IntPtr handle, access | Synchronize, &attributes, out _, IntPtr.Zero,
                    fileAttributes, share, disposition, options | FileSynchronousIoNonAlert, IntPtr.Zero, 0);
                if (status < 0)
                {
                    win32Error = (int)RtlNtStatusToDosError(status);
                    return null;
                }

                win32Error = 0;
                return new SafeFileHandle(handle, ownsHandle: true);
            }
        }
        finally
        {
            if (added)
            {
                root.DangerousRelease();
            }
        }
    }

    /// <summary>The access mask granted to <paramref name="handle"/> (<c>NtQueryObject(ObjectBasicInformation)</c>).</summary>
    public static bool TryGetGrantedAccess(SafeHandle handle, out uint grantedAccess)
    {
        byte* info = stackalloc byte[56]; // OBJECT_BASIC_INFORMATION
        bool added = false;
        handle.DangerousAddRef(ref added);
        try
        {
            int status = NtQueryObject(handle.DangerousGetHandle(), 0 /* ObjectBasicInformation */, info, 56, out _);
            grantedAccess = status >= 0 ? *(uint*)(info + 4) : 0;
            return status >= 0;
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    /// <summary>Opens a directory by full path without following a final reparse point (backup semantics).</summary>
    public static SafeFileHandle OpenDirectoryNoReparse(string path, uint access, uint share, out int win32Error)
    {
        var handle = CreateFileW(path, access, share, IntPtr.Zero, OpenExisting, FlagBackupSemantics | FlagOpenReparsePoint, IntPtr.Zero);
        win32Error = handle.IsInvalid ? Marshal.GetLastPInvokeError() : 0;
        return handle;
    }

    /// <summary>Creates a directory with the given self-relative security descriptor (atomic: no window with another ACL).</summary>
    public static bool CreateDirectoryWithSecurity(string path, byte[] securityDescriptor, out int win32Error)
    {
        fixed (byte* sd = securityDescriptor)
        {
            var sa = new SecurityAttributes { Length = (uint)sizeof(SecurityAttributes), SecurityDescriptor = (IntPtr)sd, InheritHandle = 0 };
            bool ok = CreateDirectoryW(path, &sa);
            win32Error = ok ? 0 : Marshal.GetLastPInvokeError();
            return ok;
        }
    }

    /// <summary><c>FileAttributeTagInfo</c>: attributes and reparse tag of the opened object itself.</summary>
    public static bool TryGetAttributeTag(SafeHandle handle, out uint attributes, out uint reparseTag)
    {
        uint* info = stackalloc uint[2];
        if (!GetFileInformationByHandleEx(handle, 9 /* FileAttributeTagInfo */, info, 8))
        {
            attributes = 0;
            reparseTag = 0;
            return false;
        }

        attributes = info[0];
        reparseTag = info[1];
        return true;
    }

    /// <summary><c>GetFileInformationByHandle</c>.</summary>
    /// <exception cref="Win32Exception">The call failed.</exception>
    public static ByHandleFileInformation GetFileInformation(SafeHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var info))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        return info;
    }

    /// <summary>
    /// The final path of an open handle in drive-letter form (<c>C:\dir\name</c>; the <c>\\?\</c> prefix removed).
    /// Null if it can't be determined or isn't on a drive letter (UNC, volume GUID only).
    /// </summary>
    public static string? GetFinalDosPath(SafeHandle handle)
    {
        const int Capacity = 32_768;
        var buffer = new char[Capacity];
        uint length;
        fixed (char* p = buffer)
        {
            length = GetFinalPathNameByHandleW(handle, p, Capacity, 0 /* FILE_NAME_NORMALIZED | VOLUME_NAME_DOS */);
        }

        if (length == 0 || length >= Capacity)
        {
            return null;
        }

        var path = new string(buffer, 0, (int)length);
        const string Prefix = @"\\?\";
        if (!path.StartsWith(Prefix, StringComparison.Ordinal) || path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        path = path[Prefix.Length..];
        return path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' ? path : null;
    }

    /// <summary>
    /// Renames the open file to <paramref name="newName"/> inside the directory <paramref name="targetDirectory"/>
    /// (<c>FileRenameInformation</c> with <c>RootDirectory</c>), never replacing an existing name.
    /// </summary>
    public static bool TryRenameRelative(SafeHandle file, SafeHandle targetDirectory, string newName, out int win32Error)
    {
        int nameBytes = newName.Length * 2;
        int size = 20 + nameBytes + 2;
        byte* buffer = stackalloc byte[size];
        new Span<byte>(buffer, size).Clear();
        bool addedDir = false, addedFile = false;
        targetDirectory.DangerousAddRef(ref addedDir);
        file.DangerousAddRef(ref addedFile);
        try
        {
            *buffer = 0; // ReplaceIfExists = FALSE
            *(IntPtr*)(buffer + 8) = targetDirectory.DangerousGetHandle();
            *(uint*)(buffer + 16) = (uint)nameBytes;
            fixed (char* name = newName)
            {
                Buffer.MemoryCopy(name, buffer + 20, nameBytes, nameBytes);
            }

            int status = NtSetInformationFile(file.DangerousGetHandle(), out _, buffer, (uint)(20 + nameBytes), 10 /* FileRenameInformation */);
            win32Error = status < 0 ? (int)RtlNtStatusToDosError(status) : 0;
            return status >= 0;
        }
        finally
        {
            if (addedFile)
            {
                file.DangerousRelease();
            }

            if (addedDir)
            {
                targetDirectory.DangerousRelease();
            }
        }
    }

    /// <summary>
    /// Marks the open file for deletion through this handle (needs DELETE access). Uses
    /// <c>FileDispositionInfoEx</c> (POSIX semantics + ignore read-only) and falls back to <c>FileDispositionInfo</c>.
    /// </summary>
    public static bool TryDeleteByHandle(SafeHandle file, out int win32Error)
    {
        uint flags = 0x1 /* DELETE */ | 0x2 /* POSIX_SEMANTICS */ | 0x10 /* IGNORE_READONLY_ATTRIBUTE */;
        if (SetFileInformationByHandle(file, 21 /* FileDispositionInfoEx */, &flags, 4))
        {
            win32Error = 0;
            return true;
        }

        win32Error = Marshal.GetLastPInvokeError();
        if (win32Error is not (ErrorInvalidParameter or 50 /* ERROR_NOT_SUPPORTED */))
        {
            return false;
        }

        byte delete = 1;
        if (SetFileInformationByHandle(file, 4 /* FileDispositionInfo */, &delete, 1))
        {
            win32Error = 0;
            return true;
        }

        win32Error = Marshal.GetLastPInvokeError();
        return false;
    }

    /// <summary>Sets times and attributes by handle (<c>FileBasicInfo</c>; a zero time means "leave unchanged").</summary>
    /// <exception cref="Win32Exception">The call failed.</exception>
    public static void SetBasicInfo(SafeHandle file, long creation, long lastAccess, long lastWrite, uint attributes)
    {
        var info = new FileBasicInfo
        {
            CreationTime = creation,
            LastAccessTime = lastAccess,
            LastWriteTime = lastWrite,
            ChangeTime = 0,
            FileAttributes = attributes,
        };
        if (!SetFileInformationByHandle(file, 0 /* FileBasicInfo */, &info, (uint)sizeof(FileBasicInfo)))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
    }

    /// <exception cref="Win32Exception">The call failed.</exception>
    public static void Flush(SafeHandle file)
    {
        if (!FlushFileBuffers(file))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
    }

    /// <summary>The handle's security descriptor (self-relative), or null with the error.</summary>
    public static byte[]? TryGetSecurity(SafeHandle handle, uint securityInformation, out int win32Error)
    {
        int result = GetSecurityInfo(handle, 1 /* SE_FILE_OBJECT */, securityInformation, out _, out _, out _, out _, out IntPtr sd);
        if (result != 0)
        {
            win32Error = result;
            return null;
        }

        try
        {
            uint length = GetSecurityDescriptorLength(sd);
            var bytes = new byte[length];
            Marshal.Copy(sd, bytes, 0, (int)length);
            win32Error = 0;
            return bytes;
        }
        finally
        {
            LocalFree(sd);
        }
    }

    public const uint OwnerSecurityInformation = 0x1;
    public const uint GroupSecurityInformation = 0x2;
    public const uint DaclSecurityInformation = 0x4;
    public const uint ProtectedDaclSecurityInformation = 0x80000000;
    public const uint UnprotectedDaclSecurityInformation = 0x20000000;

    /// <summary>Sets the DACL and/or owner by handle (<c>SetSecurityInfo</c>). Returns the Win32 error (0 = success).</summary>
    public static int SetSecurity(SafeHandle handle, uint securityInformation, byte[]? ownerSid, byte[]? dacl)
    {
        fixed (byte* owner = ownerSid)
        fixed (byte* acl = dacl)
        {
            return SetSecurityInfo(handle, 1 /* SE_FILE_OBJECT */, securityInformation, (IntPtr)owner, IntPtr.Zero, (IntPtr)acl, IntPtr.Zero);
        }
    }

    /// <summary>DPAPI, machine scope, no UI.</summary>
    /// <exception cref="Win32Exception">The call failed.</exception>
    public static byte[] ProtectMachine(byte[] data, byte[] entropy) => Dpapi(data, entropy, protect: true);

    /// <inheritdoc cref="ProtectMachine"/>
    public static byte[] UnprotectMachine(byte[] data, byte[] entropy) => Dpapi(data, entropy, protect: false);

    private static byte[] Dpapi(byte[] data, byte[] entropy, bool protect)
    {
        const uint Flags = 0x1 /* UI_FORBIDDEN */ | 0x4 /* LOCAL_MACHINE */;
        fixed (byte* d = data)
        fixed (byte* e = entropy)
        {
            var input = new DataBlob { Size = (uint)data.Length, Data = (IntPtr)d };
            var extra = new DataBlob { Size = (uint)entropy.Length, Data = (IntPtr)e };
            DataBlob output = default;
            bool ok = protect
                ? CryptProtectData(&input, null, &extra, IntPtr.Zero, IntPtr.Zero, Flags, &output)
                : CryptUnprotectData(&input, IntPtr.Zero, &extra, IntPtr.Zero, IntPtr.Zero, Flags, &output);
            if (!ok)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            try
            {
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, result.Length);
                return result;
            }
            finally
            {
                if (output.Data != IntPtr.Zero)
                {
                    new Span<byte>((void*)output.Data, (int)output.Size).Clear();
                    LocalFree(output.Data);
                }
            }
        }
    }

    /// <summary>BY_HANDLE_FILE_INFORMATION (FILETIMEs are 4-byte aligned, hence Pack = 4).</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public char* Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityQualityOfService
    {
        public uint Length;
        public int ImpersonationLevel;
        public byte ContextTrackingMode;
        public byte EffectiveOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public UnicodeString* ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public SecurityQualityOfService* SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(
        out IntPtr fileHandle, uint desiredAccess, ObjectAttributes* objectAttributes, out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions,
        IntPtr eaBuffer, uint eaLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(IntPtr fileHandle, out IoStatusBlock ioStatusBlock, void* information, uint length, int fileInformationClass);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtQueryObject(IntPtr handle, int objectInformationClass, void* information, uint length, out uint returnLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, SecurityAttributes* securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeHandle hFile, out ByHandleFileInformation info);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeHandle hFile, int fileInformationClass, void* info, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeHandle hFile, int fileInformationClass, void* info, uint bufferSize);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeHandle hFile, char* path, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeHandle hFile);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int GetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int SetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        DataBlob* dataIn, char* description, DataBlob* entropy, IntPtr reserved, IntPtr prompt, uint flags, DataBlob* dataOut);

    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        DataBlob* dataIn, IntPtr description, DataBlob* entropy, IntPtr reserved, IntPtr prompt, uint flags, DataBlob* dataOut);
}
