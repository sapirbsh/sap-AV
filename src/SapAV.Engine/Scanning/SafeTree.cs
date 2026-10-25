using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Engine.Scanning.Native;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning;

/// <summary>Why <see cref="SafeTree.Open"/> failed.</summary>
internal enum SafeTreeFailure
{
    None,

    /// <summary>Not an exact drive-letter path, or a network / unavailable drive.</summary>
    Unsupported,

    NotFound,

    /// <summary>A component (ancestor or the target) is a name surrogate (junction, symlink, mount point), or a reparse was refused.</summary>
    Redirected,

    AccessDenied,

    /// <summary>Sharing violation.</summary>
    Locked,

    Error,

    /// <summary>
    /// A2 W-A: a UNC path or network drive, or the opened object reports itself remote (<see cref="RemoteFileProbe"/>),
    /// and the caller didn't allow remote objects.
    /// </summary>
    Remote,
}

/// <summary>One entry of a folder listing (from the folder's own handle).</summary>
/// <param name="ReparseTag">The tag when <see cref="Attributes"/> has ReparsePoint (from the listing, no extra open).</param>
internal readonly record struct SafeTreeEntry(string Name, FileAttributes Attributes, uint ReparseTag, long Length)
{
    public bool IsDirectory => Attributes.HasFlag(FileAttributes.Directory);

    public bool IsNameSurrogate => Attributes.HasFlag(FileAttributes.ReparsePoint) && ScanNative.IsNameSurrogate(ReparseTag);
}

/// <summary>
/// Opening and listing folders <b>bound to handles</b> (review B4 H3 / M2, ROADMAP B3 M1). Paths are never resolved by a
/// following open: the volume root is opened with FILE_FLAG_OPEN_REPARSE_POINT, every further component relative to its
/// parent's handle with <c>NtCreateFile(FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE)</c>, and a component that is a name
/// surrogate (junction, symlink, mount point) is refused. Other reparse points (OneDrive / cloud folders) are regular
/// content, as before. A folder is listed from the same handle that was access-checked
/// (<c>GetFileInformationByHandleEx(FileFullDirectoryInfo)</c>), so swapping it for a junction after the check changes nothing.
/// </summary>
internal static unsafe class SafeTree
{
    /// <summary>Access for a folder that is checked and listed.</summary>
    public const uint DirectoryAccess = N.FileListDirectory | N.ReadControl | N.FileReadAttributes | N.FileTraverse;

    /// <summary>Access for an object that is only inspected (security descriptor, attributes, identity).</summary>
    public const uint InspectAccess = N.ReadControl | N.FileReadAttributes;

    public const uint ShareAll = N.ShareRead | N.ShareWrite | N.ShareDelete;

    /// <summary>FILE_OPEN_NO_RECALL: never recall an offline / cloud file's data.</summary>
    public const uint OpenNoRecall = 0x00400000;

    private const uint AncestorAccess = N.FileTraverse | N.FileReadAttributes;
    private const int ErrorDirectory = 267;
    private const int ErrorReparsePointEncountered = 4395;
    private const int ErrorNoMoreFiles = 18;
    private const int FileFullDirectoryInfoClass = 14;
    private const int FileFullDirectoryRestartInfoClass = 15;

    /// <summary>
    /// Opens <paramref name="path"/> (fully qualified drive path, plain or <c>\\?\</c>; names kept exactly) with
    /// <paramref name="access"/> on the target. Ancestors are opened for traverse only. Null with the failure otherwise.
    /// </summary>
    /// <param name="allowRemote">
    /// A2 W-A: also open UNC paths (<c>\\server\share\…</c>) and network drives, and accept a target that reports itself
    /// remote. Only for jobs an administrator explicitly allowed to scan remote files; everything else (the default) gets
    /// <see cref="SafeTreeFailure.Remote"/> before anything is opened (UNC, network drive letter), or right after the open
    /// for a target that turns out to be remote. That after-open check can't undo SMB authentication; refusing UNC paths and
    /// network drives up front, and never following a reparse point, is what keeps SYSTEM from contacting a server.
    /// </param>
    public static SafeFileHandle? Open(
        string path, uint access, uint share, uint options, out SafeTreeFailure failure, out int win32Error, bool allowRemote = false)
    {
        win32Error = 0;
        if (!TrySplitRoot(path, allowRemote, out string root, out string[] parts, out failure))
        {
            return null;
        }

        var current = N.OpenDirectoryNoReparse(root, parts.Length == 0 ? access : AncestorAccess, ShareAll, out win32Error);
        if (current.IsInvalid)
        {
            current.Dispose();
            failure = Map(win32Error);
            return null;
        }

        for (int i = 0; i < parts.Length; i++)
        {
            bool last = i == parts.Length - 1;
            var next = OpenChild(current, parts[i], last ? access : AncestorAccess, last ? share : ShareAll,
                last ? options : N.FileDirectoryFile, out failure, out win32Error);
            current.Dispose();
            if (next is null)
            {
                return null;
            }

            current = next;
        }

        if (!allowRemote && RemoteFileProbe.Instance.Classify(current) != FileLocation.Local)
        {
            current.Dispose();
            failure = SafeTreeFailure.Remote;
            return null;
        }

        failure = SafeTreeFailure.None;
        return current;
    }

    /// <summary>
    /// The root to open first (<c>\\?\C:\</c>, or <c>\\?\UNC\server\share\</c> when <paramref name="allowRemote"/>) and the
    /// components below it. False for anything else, a missing drive, or a remote one that isn't allowed.
    /// </summary>
    private static bool TrySplitRoot(string path, bool allowRemote, out string root, out string[] parts, out SafeTreeFailure failure)
    {
        root = string.Empty;
        parts = [];
        if (ExactPath.ToExtended(path) is not { } exact || !exact.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            failure = SafeTreeFailure.Unsupported;
            return false;
        }

        if (exact.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            var pieces = exact[8..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (!allowRemote || pieces.Length < 2)
            {
                failure = allowRemote ? SafeTreeFailure.Unsupported : SafeTreeFailure.Remote;
                return false;
            }

            root = $@"\\?\UNC\{pieces[0]}\{pieces[1]}\";
            parts = pieces[2..];
            failure = SafeTreeFailure.None;
            return true;
        }

        if (exact.Length < 7 || exact[5] != ':')
        {
            failure = SafeTreeFailure.Unsupported;
            return false;
        }

        root = exact[..7]; // \\?\C:\
        parts = exact[7..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        int type = Pipe.Native.PipeNative.DriveType(root[4..]);
        failure = type is 0 or 1 ? SafeTreeFailure.NotFound
            : type == Pipe.Native.PipeNative.DriveRemote && !allowRemote ? SafeTreeFailure.Remote
            : SafeTreeFailure.None;
        return failure == SafeTreeFailure.None;
    }

    /// <summary>
    /// Opens <paramref name="name"/> relative to <paramref name="parent"/> without reparsing; a name surrogate is refused
    /// (Redirected). <paramref name="options"/> may add FILE_DIRECTORY_FILE / FILE_NON_DIRECTORY_FILE / no-recall.
    /// </summary>
    public static SafeFileHandle? OpenChild(
        SafeFileHandle parent, string name, uint access, uint share, uint options, out SafeTreeFailure failure, out int win32Error)
    {
        var handle = N.OpenRelative(parent, name, access, share, N.FileOpen, options | N.FileOpenReparsePoint, out win32Error,
            N.ObjCaseInsensitive | N.ObjDontReparse);
        if (handle is null)
        {
            failure = Map(win32Error);
            return null;
        }

        if (!N.TryGetAttributeTag(handle, out uint attributes, out uint tag))
        {
            handle.Dispose();
            failure = SafeTreeFailure.Error;
            return null;
        }

        if ((attributes & N.FileAttributeReparsePoint) != 0 && ScanNative.IsNameSurrogate(tag))
        {
            handle.Dispose();
            failure = SafeTreeFailure.Redirected;
            return null;
        }

        failure = SafeTreeFailure.None;
        return handle;
    }

    /// <summary>True if the handle is a directory (from its attributes).</summary>
    public static bool IsDirectory(SafeFileHandle handle) =>
        N.TryGetAttributeTag(handle, out uint attributes, out _) && (attributes & N.FileAttributeDirectory) != 0;

    /// <summary>Lists a folder from its handle (opened with FILE_LIST_DIRECTORY, synchronous). "." and ".." are skipped.</summary>
    /// <exception cref="IOException">The listing failed.</exception>
    public static List<SafeTreeEntry> List(SafeFileHandle directory)
    {
        var entries = new List<SafeTreeEntry>();
        const int size = 64 * 1024;
        byte* buffer = (byte*)NativeMemory.Alloc(size);
        try
        {
            int infoClass = FileFullDirectoryRestartInfoClass;
            while (true)
            {
                if (!GetFileInformationByHandleEx(directory, infoClass, buffer, size))
                {
                    int error = Marshal.GetLastPInvokeError();
                    if (error == ErrorNoMoreFiles)
                    {
                        return entries;
                    }

                    throw new IOException("A folder could not be listed.", new Win32Exception(error));
                }

                infoClass = FileFullDirectoryInfoClass;
                Parse(buffer, size, entries);
            }
        }
        finally
        {
            NativeMemory.Free(buffer);
        }
    }

    /// <summary>The child path of an exact folder path (<c>\\?\C:\</c> + name, or <c>…\folder</c> + <c>\name</c>).</summary>
    public static string Child(string directory, string name) =>
        directory.EndsWith('\\') ? directory + name : directory + "\\" + name;

    private static void Parse(byte* buffer, int size, List<SafeTreeEntry> entries)
    {
        // FILE_FULL_DIR_INFO: NextEntryOffset 0, FileIndex 4, times 8-39, EndOfFile 40, AllocationSize 48, FileAttributes 56,
        // FileNameLength 60, EaSize 64 (the reparse tag when FILE_ATTRIBUTE_REPARSE_POINT is set), FileName 68.
        int offset = 0;
        while (offset + 68 <= size)
        {
            byte* entry = buffer + offset;
            uint next = *(uint*)entry;
            long length = *(long*)(entry + 40);
            uint attributes = *(uint*)(entry + 56);
            int nameBytes = (int)*(uint*)(entry + 60);
            uint tag = *(uint*)(entry + 64);
            if (nameBytes > 0 && offset + 68 + nameBytes <= size)
            {
                string name = new((char*)(entry + 68), 0, nameBytes / 2);
                if (name is not ("." or ".."))
                {
                    bool reparse = (attributes & N.FileAttributeReparsePoint) != 0;
                    entries.Add(new SafeTreeEntry(name, (FileAttributes)attributes, reparse ? tag : 0, length));
                }
            }

            if (next == 0)
            {
                return;
            }

            offset += (int)next;
        }
    }

    private static SafeTreeFailure Map(int error) => error switch
    {
        N.ErrorFileNotFound or N.ErrorPathNotFound or ErrorDirectory => SafeTreeFailure.NotFound,
        N.ErrorAccessDenied => SafeTreeFailure.AccessDenied,
        N.ErrorSharingViolation => SafeTreeFailure.Locked,
        ErrorReparsePointEncountered => SafeTreeFailure.Redirected,
        _ => SafeTreeFailure.Error,
    };

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass, void* info, uint bufferSize);
}
