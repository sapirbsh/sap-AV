using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Scanning.Native;

/// <summary>Win32 calls for scan jobs (B3): background thread mode, reopening the scan handle, owner and reparse-tag queries.</summary>
internal static unsafe class ScanNative
{
    public const uint GenericRead = 0x80000000;
    public const uint Delete = 0x00010000;
    public const uint WriteDac = 0x00040000;
    public const uint FileReadAttributes = 0x0080;
    public const uint FileShareRead = 0x1;
    public const uint FileShareWrite = 0x2;
    public const uint FileShareDelete = 0x4;
    public const int ErrorSharingViolation = 32;
    public const int ErrorAccessDenied = 5;

    private const int ThreadModeBackgroundBegin = 0x00010000;
    private const int ThreadModeBackgroundEnd = 0x00020000;
    private const int SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x1;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;

    /// <summary>
    /// Puts the calling thread in background mode (low CPU, I/O and memory priority). Per thread, never per process: the
    /// engine's pipe and alert threads keep normal priority. Returns false if Windows refused (the thread then runs normally).
    /// </summary>
    public static bool BeginBackgroundMode() => SetThreadPriority(GetCurrentThread(), ThreadModeBackgroundBegin);

    /// <summary>Ends <see cref="BeginBackgroundMode"/> for the calling thread.</summary>
    public static void EndBackgroundMode() => _ = SetThreadPriority(GetCurrentThread(), ThreadModeBackgroundEnd);

    /// <summary>
    /// Opens the <b>same file object</b> as <paramref name="handle"/> again with other access (no path lookup, so no
    /// redirect is possible). Synchronous. On failure returns null and the Win32 error.
    /// </summary>
    public static SafeFileHandle? ReOpen(SafeFileHandle handle, uint access, uint share, out int error)
    {
        var reopened = ReOpenFile(handle, access, share, 0);
        if (reopened.IsInvalid)
        {
            error = Marshal.GetLastPInvokeError();
            reopened.Dispose();
            return null;
        }

        error = 0;
        return reopened;
    }

    /// <summary>The owner SID of the open file (needs READ_CONTROL, which GENERIC_READ includes), or null if it can't be read.</summary>
    public static SecurityIdentifier? TryGetOwner(SafeFileHandle handle)
    {
        int status = GetSecurityInfo(handle, SeFileObject, OwnerSecurityInformation, out IntPtr owner, out _, out _, out _, out IntPtr descriptor);
        if (status != 0)
        {
            return null;
        }

        try
        {
            return owner == IntPtr.Zero ? null : new SecurityIdentifier(owner);
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    /// <summary>
    /// The reparse tag of <paramref name="path"/> itself (the link is not followed), or null if it can't be read. Opens
    /// with FILE_READ_ATTRIBUTES only, so nothing is recalled from the cloud.
    /// </summary>
    public static uint? TryGetReparseTag(string path)
    {
        using var handle = CreateFileW(path, FileReadAttributes, FileShareRead | FileShareWrite | FileShareDelete, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            return null;
        }

        FileAttributeTagInfo info;
        return GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, &info, (uint)sizeof(FileAttributeTagInfo))
            ? info.ReparseTag
            : null;
    }

    /// <summary>
    /// IsReparseTagNameSurrogate: the tag redirects to another name (symlink, junction / mount point, AF_UNIX, ...).
    /// Cloud-file and dedup tags are not surrogates: the data is still "this" file.
    /// </summary>
    public static bool IsNameSurrogate(uint tag) => (tag & 0x20000000) != 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadPriority(IntPtr thread, int priority);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle ReOpenFile(SafeFileHandle original, uint desiredAccess, uint shareMode, uint flagsAndAttributes);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass, void* info, uint bufferSize);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int GetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
