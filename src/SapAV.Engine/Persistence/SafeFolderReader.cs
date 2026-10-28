using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Folder listing and small-file reads for the Startup folder and scheduled task sources (ROADMAP C2), through
/// <see cref="SafeTree"/>: every component opened relative to its parent, no junction / symlink / mount point followed,
/// no network path, no cloud recall. Files are read only when they are regular disk files under a size cap.
/// </summary>
internal static class SafeFolderReader
{
    /// <summary>Opens a folder for listing; null with the issue reason when it can't (null reason: it doesn't exist).</summary>
    public static SafeFileHandle? OpenFolder(string path, out PersistenceIssueReason? failure)
    {
        var handle = SafeTree.Open(path, SafeTree.DirectoryAccess, SafeTree.ShareAll, N.FileDirectoryFile, out var why, out _);
        failure = handle is not null ? null : why switch
        {
            SafeTreeFailure.NotFound => null,
            SafeTreeFailure.AccessDenied => PersistenceIssueReason.AccessDenied,
            SafeTreeFailure.Redirected => PersistenceIssueReason.LinkNotFollowed,
            SafeTreeFailure.Remote => PersistenceIssueReason.NetworkLocation,
            _ => PersistenceIssueReason.Error,
        };
        return handle;
    }

    /// <summary>Opens a subfolder relative to <paramref name="parent"/> (a link is refused).</summary>
    public static SafeFileHandle? OpenSubfolder(SafeFileHandle parent, string name, out PersistenceIssueReason? failure)
    {
        var handle = SafeTree.OpenChild(parent, name, SafeTree.DirectoryAccess, SafeTree.ShareAll, N.FileDirectoryFile, out var why, out _);
        failure = handle is not null ? null : why switch
        {
            SafeTreeFailure.NotFound => null,
            SafeTreeFailure.AccessDenied => PersistenceIssueReason.AccessDenied,
            SafeTreeFailure.Redirected => PersistenceIssueReason.LinkNotFollowed,
            _ => PersistenceIssueReason.Error,
        };
        return handle;
    }

    /// <summary>
    /// Reads a file listed in <paramref name="folder"/>, at most <paramref name="maxBytes"/>; null with the reason and a
    /// message otherwise (too large, not a regular file, locked, denied).
    /// </summary>
    public static byte[]? ReadFile(SafeFileHandle folder, string name, int maxBytes, out PersistenceIssueReason failure, out string message)
    {
        failure = PersistenceIssueReason.Error;
        using var handle = SafeTree.OpenChild(folder, name, N.GenericRead, SafeTree.ShareAll, N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out var why, out int error);
        if (handle is null)
        {
            failure = why switch
            {
                SafeTreeFailure.AccessDenied => PersistenceIssueReason.AccessDenied,
                SafeTreeFailure.Redirected => PersistenceIssueReason.LinkNotFollowed,
                _ => PersistenceIssueReason.Error,
            };
            message = $"The file can't be opened ({why}, Win32 error {error}).";
            return null;
        }

        if (!SecureFile.Validate(handle, out var invalid, out _))
        {
            message = $"Not a regular local file ({invalid.Reason}).";
            return null;
        }

        long length = RandomAccess.GetLength(handle);
        if (length > maxBytes)
        {
            failure = PersistenceIssueReason.TooLarge;
            message = $"The file is {length} bytes, over the {maxBytes}-byte cap.";
            return null;
        }

        var buffer = new byte[length];
        int read = 0;
        while (read < buffer.Length)
        {
            int n = RandomAccess.Read(handle, buffer.AsSpan(read), read);
            if (n <= 0)
            {
                break;
            }

            read += n;
        }

        message = string.Empty;
        return read == buffer.Length ? buffer : buffer[..read];
    }
}
