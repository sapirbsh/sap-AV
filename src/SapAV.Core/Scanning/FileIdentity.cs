using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;

namespace SapAV.Core.Scanning;

/// <summary>
/// Which file object a scan judged, captured from the scan's own handle: the volume serial number and 128-bit file ID
/// (<c>FILE_ID_INFO</c>) plus the handle's final path. Anything that later acts on the scan (quarantine, B2) must act
/// on this exact object, never on whatever the path happens to resolve to by then.
/// </summary>
/// <param name="VolumeSerialNumber">64-bit volume serial from <c>FILE_ID_INFO</c>.</param>
/// <param name="FileId">The 128-bit file ID as 32 lowercase hex characters.</param>
/// <param name="FinalPath">The handle's final path in drive-letter form (<c>C:\...</c>), or null if it has none (UNC, no letter).</param>
public sealed record FileIdentity(ulong VolumeSerialNumber, string FileId, string? FinalPath)
{
    /// <summary>The identity of the open file, or null if the file system can't report a file ID.</summary>
    public static FileIdentity? TryCapture(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        return NativeFile.TryGetFileId(handle, out ulong serial, out string fileId)
            ? new FileIdentity(serial, fileId, NativeFile.TryGetFinalDosPath(handle))
            : null;
    }

    /// <summary>Same volume and file ID (the path is compared separately).</summary>
    public bool IsSameObject(FileIdentity? other) =>
        other is not null && other.VolumeSerialNumber == VolumeSerialNumber && string.Equals(other.FileId, FileId, StringComparison.Ordinal);
}
