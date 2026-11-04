using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.RealTime;

/// <summary>
/// Opens a folder to watch (D1 real-time files, D4 persistence folders): a drive-letter path on a local fixed drive, reached
/// through <see cref="SafeTree"/> (component by component, no link on the way or at the end), a directory, local by the
/// remote-file check on its handle, with a file ID (so a later swap of the folder object is noticed).
/// </summary>
internal static class WatchedRootOpener
{
    internal readonly record struct Opened(SafeFileHandle Handle, ulong Volume, string FileId);

    /// <param name="exact">The <c>\\?\</c> form of the folder.</param>
    public static bool IsOnFixedDrive(string exact, Func<string, int> driveType) =>
        exact.Length >= 7 && exact[5] == ':' && driveType(exact.Substring(4, 3)) == FullScanVolumes.DriveFixed;

    /// <param name="exact">The <c>\\?\</c> form of the folder.</param>
    /// <param name="problem">Why it can't be watched (engine text), when null is returned.</param>
    public static Opened? Open(string exact, Func<string, int> driveType, IRemoteFileProbe remote, out string? problem)
    {
        if (!IsOnFixedDrive(exact, driveType))
        {
            problem = "it isn't on a local fixed drive";
            return null;
        }

        var handle = SafeTree.Open(exact, SafeTree.DirectoryAccess, SafeTree.ShareAll, N.FileDirectoryFile, out var failure, out int error);
        if (handle is null)
        {
            problem = failure switch
            {
                SafeTreeFailure.Redirected => "it, or a folder on its path, is a junction or symbolic link; links are never followed",
                SafeTreeFailure.NotFound => "it doesn't exist",
                SafeTreeFailure.Remote => "it is on a remote file system",
                SafeTreeFailure.AccessDenied => "access is denied",
                _ => $"it could not be opened safely ({failure}, Win32 error {error})",
            };
            return null;
        }

        problem = !SafeTree.IsDirectory(handle) ? "it isn't a folder"
            : remote.Classify(handle) != FileLocation.Local ? "it is on a remote file system"
            : !NativeFile.TryGetFileId(handle, out _, out _) ? "its file system reports no file ID"
            : null;
        if (problem is not null)
        {
            handle.Dispose();
            return null;
        }

        NativeFile.TryGetFileId(handle, out ulong volume, out string fileId);
        return new Opened(handle, volume, fileId);
    }
}
