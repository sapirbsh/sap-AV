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

    internal const uint FileTypeDisk = 0x0001;

    /// <summary>
    /// Opens <paramref name="fullPath"/> for reading with shared Read/Write/Delete and <see cref="HashingFlags"/>.
    /// On failure returns an invalid handle (already disposed) and the Win32 error code.
    /// </summary>
    internal static SafeFileHandle OpenForHashing(string fullPath, out int win32Error)
    {
        var handle = CreateFileW(
            fullPath,
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            HashingFlags,
            IntPtr.Zero);

        win32Error = handle.IsInvalid ? Marshal.GetLastPInvokeError() : 0;
        if (handle.IsInvalid)
        {
            handle.Dispose();
        }

        return handle;
    }

    /// <summary><c>GetFileType</c>: 1 = disk, 2 = character device, 3 = pipe, 0 = unknown/error.</summary>
    internal static uint GetFileType(SafeFileHandle handle) => GetFileTypeNative(handle);

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
