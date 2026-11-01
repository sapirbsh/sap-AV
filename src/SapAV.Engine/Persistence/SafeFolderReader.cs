using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Folder listing and small-file opens for the Startup folder and scheduled task sources (ROADMAP C2), through
/// <see cref="SafeTree"/>: every component opened relative to its parent, no junction / symlink / mount point followed,
/// no network path, no cloud recall. The engine never reads these files: it hands the opened handle to the sandboxed
/// worker (<see cref="IPersistenceFileParser"/>, section C review H2).
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
    /// Opens a file listed in <paramref name="folder"/> for parsing in the worker: a regular local file of at most
    /// <paramref name="maxBytes"/>. Null with the reason and a message otherwise (too large, not a regular file, locked,
    /// denied, an I/O error). Never throws for one file's problem (section C review M3).
    /// </summary>
    public static SafeFileHandle? OpenForParsing(SafeFileHandle folder, string name, int maxBytes, out PersistenceIssueReason failure, out string message)
    {
        failure = PersistenceIssueReason.Error;
        var handle = SafeTree.OpenChild(folder, name, N.GenericRead, SafeTree.ShareAll, N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out var why, out int error);
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

        try
        {
            if (!SecureFile.Validate(handle, out var invalid, out _))
            {
                message = $"Not a regular local file ({invalid.Reason}).";
                handle.Dispose();
                return null;
            }

            long length = RandomAccess.GetLength(handle);
            if (length > maxBytes)
            {
                failure = PersistenceIssueReason.TooLarge;
                message = $"The file is {length} bytes, over the {maxBytes}-byte cap.";
                handle.Dispose();
                return null;
            }

            message = string.Empty;
            return handle;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            message = $"The file can't be read ({ex.GetType().Name}).";
            handle.Dispose();
            return null;
        }
    }
}
