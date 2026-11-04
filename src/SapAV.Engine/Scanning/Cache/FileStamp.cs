using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Scanning;

namespace SapAV.Engine.Scanning.Cache;

/// <summary>
/// What the scan cache (C5) compares, read from the <b>scan's own handle</b> after the hardened open (ROADMAP A2 W1),
/// never from a path stat: the file object (volume serial + 128-bit file ID), its size, last-write and change time, and
/// the change-journal USN. The USN is what makes this safe (section C review H5): the times alone are not. A same-size write
/// followed by <c>SetFileInformationByHandle(FileBasicInfo)</c> puts back both last-write and change time with no privilege,
/// and a mapped write can change neither. So without a journal there is no stamp, on any volume but NTFS or ReFS.
/// </summary>
/// <param name="ChangeTime">FILETIME of the last metadata or data change. Compared, but settable by whoever can write the file.</param>
/// <param name="Usn">The file's USN. Null never comes from <see cref="Capture"/> and is never cached (<see cref="ScanCache"/> refuses it).</param>
internal readonly record struct FileStamp(ulong Volume, UInt128 FileId, long Size, long LastWriteTime, long ChangeTime, long? Usn)
{
    /// <summary>The stamp of an open file; null if the file system can't report one of the values, has no active change journal, or isn't NTFS or ReFS.</summary>
    public static FileStamp? Capture(SafeFileHandle handle, FileIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(identity);
        if (!IsJournalingFileSystem(NativeFile.FileSystemName(handle)) || !NativeFile.TryGetUsn(handle, out long usn)
            || !TryGetTimes(handle, out long lastWrite, out long change) || !TryGetSize(handle, out long size))
        {
            return null;
        }

        var key = IdentityKey.Of(identity);
        return new FileStamp(key.Volume, key.FileId, size, lastWrite, change, usn);
    }

    /// <summary>
    /// D4 review H2: the same values for change detection only (never for the scan cache): the USN is null when the volume has
    /// no journal, so without one only the times and size (which a writer can put back) tell a change. Null when the file
    /// system reports no file ID, times or size.
    /// </summary>
    public static FileStamp? CaptureForChangeDetection(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!NativeFile.TryGetFileId(handle, out ulong volume, out string id) || !TryGetTimes(handle, out long lastWrite, out long change) || !TryGetSize(handle, out long size))
        {
            return null;
        }

        long? usn = NativeFile.TryGetUsn(handle, out long value) ? value : null;
        var key = IdentityKey.Of(new FileIdentity(volume, id, null));
        return new FileStamp(key.Volume, key.FileId, size, lastWrite, change, usn);
    }

    /// <summary>Only NTFS and ReFS have the change journal the stamp relies on.</summary>
    internal static bool IsJournalingFileSystem(string? name) => name is "NTFS" or "ReFS";

    /// <summary>The 16-byte file ID in the order the cache stores it.</summary>
    public byte[] FileIdBytes()
    {
        var bytes = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt128BigEndian(bytes, FileId);
        return bytes;
    }

    private static unsafe bool TryGetTimes(SafeFileHandle handle, out long lastWrite, out long change)
    {
        // FILE_BASIC_INFO: CreationTime 0, LastAccessTime 8, LastWriteTime 16, ChangeTime 24, FileAttributes 32 (40 bytes).
        byte* info = stackalloc byte[40];
        if (!GetFileInformationByHandleEx(handle, 0 /* FileBasicInfo */, info, 40))
        {
            lastWrite = change = 0;
            return false;
        }

        lastWrite = *(long*)(info + 16);
        change = *(long*)(info + 24);
        return true;
    }

    private static unsafe bool TryGetSize(SafeFileHandle handle, out long size)
    {
        // FILE_STANDARD_INFO: AllocationSize 0, EndOfFile 8, NumberOfLinks 16, DeletePending 20, Directory 21 (24 bytes).
        byte* info = stackalloc byte[24];
        if (!GetFileInformationByHandleEx(handle, 1 /* FileStandardInfo */, info, 24))
        {
            size = 0;
            return false;
        }

        size = *(long*)(info + 8);
        return size >= 0;
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass, void* info, uint bufferSize);
}
