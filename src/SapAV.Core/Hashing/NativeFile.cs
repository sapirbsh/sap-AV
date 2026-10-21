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

    private static SafeFileHandle Open(string fullPath, uint flags, out int win32Error)
    {
        var handle = CreateFileW(
            fullPath,
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
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
    /// The file's identity from the handle (<c>GetFileInformationByHandleEx(FileIdInfo)</c>: volume serial number
    /// and 128-bit file ID, valid on NTFS and ReFS). Two handles with the same identity refer to the same file;
    /// alternate data streams share their file's identity. False if the file system doesn't report one.
    /// </summary>
    internal static unsafe bool TryGetFileId(SafeFileHandle handle, out (ulong Volume, UInt128 FileId) id)
    {
        FileIdInfo info;
        if (!GetFileInformationByHandleEx(handle, 18 /* FileIdInfo */, &info, (uint)sizeof(FileIdInfo)))
        {
            id = default;
            return false;
        }

        id = (info.VolumeSerialNumber, new UInt128(info.FileIdHigh, info.FileIdLow));
        return true;
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

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern unsafe uint GetFinalPathNameByHandleW(SafeFileHandle hFile, char* path, uint length, uint flags);

    [DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetDriveTypeW(string rootPathName);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;  // FILE_ID_128 bytes 0-7 (little-endian)
        public ulong FileIdHigh; // bytes 8-15
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool GetFileInformationByHandleEx(SafeFileHandle hFile, int fileInformationClass, void* info, uint bufferSize);

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
