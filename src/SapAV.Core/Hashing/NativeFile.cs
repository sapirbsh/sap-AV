using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Hashing;

/// <summary>
/// Win32 file opening for the hasher, so the open flags are explicit instead of depending on how
/// <see cref="FileStream"/> happens to call <c>CreateFileW</c>.
/// </summary>
internal static class NativeFile
{
    private const uint GenericRead = 0x80000000;

    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;

    private const uint OpenExisting = 3;

    private const uint FileFlagOverlapped = 0x40000000;        // async reads through FileStream(isAsync: true)
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagBackupSemantics = 0x02000000;   // lets directories open, so they're reported as Directory
    private const uint FileFlagOpenNoRecall = 0x00100000;      // never recall a cloud placeholder / offline file

    // SQOS for the client end of a named pipe reached through any link or junction: the server only gets
    // an anonymous-level token and can't impersonate us. Note: SECURITY_SQOS_PRESENT has the same value as
    // FILE_FLAG_OPEN_NO_RECALL (both 0x00100000 in WinBase.h), and SECURITY_ANONYMOUS is 0; both are
    // listed so the intent is explicit.
    private const uint SecuritySqosPresent = 0x00100000;
    private const uint SecurityAnonymous = 0x00000000;

    /// <summary>The flags <see cref="OpenForHashing"/> passes to <c>CreateFileW</c>.</summary>
    internal const uint HashingFlags =
        FileFlagOverlapped | FileFlagSequentialScan | FileFlagBackupSemantics | FileFlagOpenNoRecall
        | SecuritySqosPresent | SecurityAnonymous;

    /// <summary>
    /// The flags <see cref="OpenForSignatureCheck"/> passes to <c>CreateFileW</c>: exactly
    /// <see cref="HashingFlags"/> without <c>FILE_FLAG_OVERLAPPED</c>. WinVerifyTrust's SIPs and
    /// <c>CryptCATAdminCalcHashFromFileHandle2</c> read the handle with synchronous <c>ReadFile</c> calls
    /// (no OVERLAPPED), which is not valid on an overlapped handle. Every security-relevant flag (backup
    /// semantics, no recall, anonymous SQOS) is kept.
    /// </summary>
    internal const uint SignatureCheckFlags = HashingFlags & ~FileFlagOverlapped;

    internal const uint FileTypeDisk = 0x0001;

    /// <summary>
    /// Opens <paramref name="fullPath"/> for reading with shared Read/Write/Delete and <see cref="HashingFlags"/>.
    /// On failure returns an invalid handle (already disposed) and the Win32 error code.
    /// </summary>
    internal static SafeFileHandle OpenForHashing(string fullPath, out int win32Error) =>
        Open(fullPath, HashingFlags, out win32Error);

    /// <summary>
    /// Same as <see cref="OpenForHashing"/> but with <see cref="SignatureCheckFlags"/> (a synchronous handle),
    /// for the Authenticode checker.
    /// </summary>
    internal static SafeFileHandle OpenForSignatureCheck(string fullPath, out int win32Error) =>
        Open(fullPath, SignatureCheckFlags, out win32Error);

    /// <summary>
    /// Same flags as <see cref="OpenForSignatureCheck"/> (a synchronous handle with every security-relevant
    /// flag), for the YARA scanner: it memory-maps the file from this handle, so YARA-X never opens the path itself.
    /// </summary>
    internal static SafeFileHandle OpenForMemoryMap(string fullPath, out int win32Error) =>
        Open(fullPath, SignatureCheckFlags, out win32Error);

    /// <summary>
    /// Opens with <see cref="SignatureCheckFlags"/> (synchronous, all security flags) for the single-handle scan
    /// pipeline. With <paramref name="denyWriters"/> the share mode is Read | Delete, so no other program can open
    /// the file for writing while it is scanned (and an existing writer makes the open fail with a sharing
    /// violation); otherwise Read | Write | Delete, like the hasher. <paramref name="additionalAccess"/> is OR-ed into
    /// GENERIC_READ (the quarantine asks for DELETE so it can move the file by handle); 0 for every scanner.
    /// </summary>
    internal static SafeFileHandle OpenForScan(string fullPath, bool denyWriters, out int win32Error, uint additionalAccess = 0) =>
        Open(fullPath, SignatureCheckFlags, out win32Error,
            denyWriters ? FileShareRead | FileShareDelete : FileShareRead | FileShareWrite | FileShareDelete,
            GenericRead | additionalAccess);

    private static SafeFileHandle Open(
        string fullPath, uint flags, out int win32Error, uint share = FileShareRead | FileShareWrite | FileShareDelete,
        uint access = GenericRead)
    {
        var handle = CreateFileW(
            fullPath,
            access,
            share,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);

        win32Error = handle.IsInvalid ? Marshal.GetLastPInvokeError() : 0;
        if (handle.IsInvalid)
        {
            handle.Dispose();
        }

        return handle;
    }

    /// <summary>
    /// True only if the open file is on a local volume of drive type DRIVE_FIXED: the remote-protocol query
    /// (<c>GetFileInformationByHandleEx(FileRemoteProtocolInfo)</c>) must fail, which it does for local files,
    /// and the volume's root (from <c>GetFinalPathNameByHandleW(VOLUME_NAME_GUID)</c>) must report DRIVE_FIXED.
    /// Removable media, network shares, RAM disks, CD-ROMs and anything that can't be determined return false.
    /// </summary>
    internal static unsafe bool IsOnLocalFixedVolume(SafeFileHandle handle)
    {
        byte* remoteInfo = stackalloc byte[512];
        if (GetFileInformationByHandleEx(handle, 13 /* FileRemoteProtocolInfo */, remoteInfo, 512))
        {
            return false; // the file system reported a remote protocol (SMB, ...)
        }

        char* path = stackalloc char[1024];
        uint length = GetFinalPathNameByHandleW(handle, path, 1024, 1 /* VOLUME_NAME_GUID */);
        if (length == 0 || length >= 1024)
        {
            return false;
        }

        var full = new ReadOnlySpan<char>(path, (int)length);
        const string Prefix = @"\\?\Volume{";
        if (!full.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int rootEnd = full.IndexOf('}');
        if (rootEnd < 0 || rootEnd + 1 >= full.Length || full[rootEnd + 1] != '\\')
        {
            return false;
        }

        string root = new string(full[..(rootEnd + 2)]); // "\\?\Volume{guid}\"
        return GetDriveTypeW(root) == 3 /* DRIVE_FIXED */;
    }

    /// <summary><c>GetFileInformationByHandleEx(FileIdInfo)</c>: 64-bit volume serial and 128-bit file ID (lowercase hex).</summary>
    internal static unsafe bool TryGetFileId(SafeFileHandle handle, out ulong volumeSerial, out string fileId)
    {
        byte* info = stackalloc byte[24];
        if (!GetFileInformationByHandleEx(handle, 18 /* FileIdInfo */, info, 24))
        {
            volumeSerial = 0;
            fileId = string.Empty;
            return false;
        }

        volumeSerial = *(ulong*)info;
        fileId = Convert.ToHexStringLower(new ReadOnlySpan<byte>(info + 8, 16));
        return true;
    }

    /// <summary>The handle's final path as <c>C:\...</c> (the <c>\\?\</c> prefix removed); null for UNC or no drive letter.</summary>
    internal static unsafe string? TryGetFinalDosPath(SafeFileHandle handle)
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
        if (!path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        path = path[4..];
        return path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' ? path : null;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern unsafe uint GetFinalPathNameByHandleW(SafeFileHandle hFile, char* path, uint length, uint flags);

    [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetDriveTypeW(string rootPathName);

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool GetFileInformationByHandleEx(SafeFileHandle hFile, int fileInformationClass, void* info, uint bufferSize);

    /// <summary>
    /// The file's current update sequence number (<c>FSCTL_READ_FILE_USN_DATA</c>). The USN changes whenever the
    /// change journal records a change to the file (data, size, timestamps, attributes, rename). False when the
    /// volume has no active change journal (the call fails or reports USN 0).
    /// </summary>
    internal static unsafe bool TryGetUsn(SafeFileHandle handle, out long usn)
    {
        usn = 0;
        ushort* input = stackalloc ushort[2];
        input[0] = 2; // MinMajorVersion
        input[1] = 3; // MaxMajorVersion
        byte* output = stackalloc byte[1024];
        if (!DeviceIoControl(handle, 0x000900EB /* FSCTL_READ_FILE_USN_DATA */, input, 4, output, 1024, out uint returned, IntPtr.Zero)
            || returned < 8)
        {
            return false;
        }

        ushort major = *(ushort*)(output + 4);
        int offset = major switch { 2 => 24, 3 => 40, _ => -1 };
        if (offset < 0 || returned < offset + 8)
        {
            return false;
        }

        usn = *(long*)(output + offset);
        return usn != 0;
    }

    /// <summary>
    /// Opens the alternate data stream <paramref name="streamName"/> (e.g. <c>:Zone.Identifier</c>) <b>relative to the
    /// open file handle</b> (<c>NtCreateFile</c> with <c>RootDirectory</c> = the file), so the path is never resolved
    /// again: read-only, shared, no recall, non-directory, anonymous SQOS. On failure returns null and the Win32 error.
    /// </summary>
    internal static unsafe SafeFileHandle? OpenStreamRelative(SafeFileHandle file, string streamName, out int win32Error)
    {
        bool added = false;
        file.DangerousAddRef(ref added);
        try
        {
            fixed (char* name = streamName)
            {
                var unicode = new UnicodeString
                {
                    Length = (ushort)(streamName.Length * 2),
                    MaximumLength = (ushort)(streamName.Length * 2),
                    Buffer = name,
                };
                var sqos = new SecurityQualityOfService { Length = (uint)sizeof(SecurityQualityOfService), ImpersonationLevel = 0 /* Anonymous */ };
                var attributes = new ObjectAttributes
                {
                    Length = (uint)sizeof(ObjectAttributes),
                    RootDirectory = file.DangerousGetHandle(),
                    ObjectName = &unicode,
                    Attributes = 0x40, // OBJ_CASE_INSENSITIVE
                    SecurityQualityOfService = &sqos,
                };

                int status = NtCreateFile(
                    out IntPtr stream,
                    0x00120089, // FILE_GENERIC_READ
                    &attributes,
                    out _,
                    IntPtr.Zero,
                    0,
                    FileShareRead | FileShareWrite | FileShareDelete,
                    1,          // FILE_OPEN
                    0x00000040 | 0x00000020 | 0x00400000, // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_NO_RECALL
                    IntPtr.Zero,
                    0);

                if (status < 0)
                {
                    win32Error = (int)RtlNtStatusToDosError(status);
                    return null;
                }

                win32Error = 0;
                return new SafeFileHandle(stream, ownsHandle: true);
            }
        }
        finally
        {
            if (added)
            {
                file.DangerousRelease();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct UnicodeString
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
    private unsafe struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public UnicodeString* ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public SecurityQualityOfService* SecurityQualityOfService;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern unsafe int NtCreateFile(
        out IntPtr fileHandle, uint desiredAccess, ObjectAttributes* objectAttributes, out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions,
        IntPtr eaBuffer, uint eaLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern uint RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool DeviceIoControl(
        SafeFileHandle device, uint ioControlCode, void* inBuffer, uint inBufferSize, void* outBuffer, uint outBufferSize,
        out uint bytesReturned, IntPtr overlapped);

    /// <summary><c>GetFileType</c>: 1 = disk, 2 = character device, 3 = pipe, 0 = unknown/error.</summary>
    internal static uint GetFileType(SafeFileHandle handle) => GetFileTypeNative(handle);

    /// <summary>Moves a synchronous handle's file pointer back to the start (<c>SetFilePointerEx</c>).</summary>
    internal static bool Rewind(SafeFileHandle handle) => SetFilePointerEx(handle, 0, IntPtr.Zero, 0 /* FILE_BEGIN */);

    [DllImport("kernel32.dll", EntryPoint = "SetFilePointerEx", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(SafeFileHandle hFile, long liDistanceToMove, IntPtr lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFileType", SetLastError = true, ExactSpelling = true)]
    private static extern uint GetFileTypeNative(SafeFileHandle hFile);
}
