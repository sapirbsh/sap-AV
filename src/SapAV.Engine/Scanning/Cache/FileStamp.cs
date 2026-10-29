using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Scanning;

namespace SapAV.Engine.Scanning.Cache;

/// <summary>
/// What the scan cache (C5) compares, read from the <b>scan's own handle</b> after the hardened open (ROADMAP A2 W1),
/// never from a path stat: the file object (volume serial + 128-bit file ID), its size, last-write and change time, and
/// the change-journal USN when the volume has one. Any write, truncation, timestamp reset (SetFileTime moves the change
/// time), attribute change, rename or stream change moves at least one of these.
/// </summary>
/// <param name="ChangeTime">FILETIME of the last metadata or data change (not settable through the Win32 API).</param>
/// <param name="Usn">The file's USN, or null when the volume has no change journal.</param>
internal readonly record struct FileStamp(ulong Volume, UInt128 FileId, long Size, long LastWriteTime, long ChangeTime, long? Usn)
{
    /// <summary>The stamp of an open file, or null if the file system can't report one of the values.</summary>
    public static FileStamp? Capture(SafeFileHandle handle, FileIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(identity);
        if (!TryGetTimes(handle, out long lastWrite, out long change) || !TryGetSize(handle, out long size))
        {
            return null;
        }

        var key = IdentityKey.Of(identity);
        return new FileStamp(key.Volume, key.FileId, size, lastWrite, change, NativeFile.TryGetUsn(handle, out long usn) ? usn : null);
    }

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
