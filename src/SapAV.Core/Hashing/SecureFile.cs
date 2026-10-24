using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Hashing;

/// <summary>Why <see cref="SecureFile.OpenRegularFile"/> or <see cref="SecureFile.Validate"/> refused a file.</summary>
/// <param name="Reason">The failure (never None).</param>
/// <param name="Message">Diagnostic text.</param>
/// <param name="Length">The size from the handle, when the file was opened (e.g. Offline).</param>
/// <param name="Attributes">The attributes from the handle, when known (Directory, Offline).</param>
/// <param name="LastWriteTimeUtc">The last-write time from the handle, when known (Offline).</param>
internal readonly record struct SecureOpenFailure(
    HashFailureReason Reason, string Message, long? Length = null, FileAttributes? Attributes = null, DateTime? LastWriteTimeUtc = null);

/// <summary>
/// The one hardened open sequence for every content reader (hasher, Authenticode, YARA, heuristics,
/// Mark-of-the-Web) and for the single-handle scan pipeline (<see cref="Scanning.FileScanner"/>).
/// </summary>
/// <remarks>
/// In order: empty/NUL paths are InvalidPath; device-namespace paths (raw, or after
/// <see cref="Path.GetFullPath(string)"/>, which maps <c>CON</c>, <c>NUL</c>, ... to <c>\\.\...</c>) are
/// NotRegularFile and never opened; one <c>CreateFileW</c> with <see cref="NativeFile.SignatureCheckFlags"/>
/// (synchronous; backup semantics, no cloud recall, anonymous SQOS for pipes reached through links); then
/// <see cref="Validate"/>: <c>GetFileType</c> must be disk, directories are rejected, and offline files / cloud
/// placeholders are rejected unless allowed, all before anything is read.
/// </remarks>
internal static class SecureFile
{
    /// <summary>Opens <paramref name="path"/> if it is a regular local file; otherwise null and the reason.</summary>
    /// <param name="allowOffline">If true, offline files / placeholders are returned too (for metadata-only callers).</param>
    /// <param name="denyWriters">Share Read | Delete only (no writers while open; an existing writer gives Locked).</param>
    /// <param name="additionalAccess">
    /// Access rights added to GENERIC_READ (e.g. DELETE for the quarantine's move by handle). 0 for every content reader.
    /// </param>
    public static SafeFileHandle? OpenRegularFile(
        string path, out SecureOpenFailure failure, out FileAttributes attributes, bool allowOffline = false, bool denyWriters = false,
        uint additionalAccess = 0)
    {
        attributes = default;
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            failure = new(HashFailureReason.InvalidPath, "Path is empty, blank or contains a NUL character.");
            return null;
        }

        if (Sha256Hasher.IsDeviceNamespacePath(path))
        {
            failure = new(HashFailureReason.NotRegularFile, "Device-namespace path (pipe, device or volume), not a regular file.");
            return null;
        }

        string fullPath;
        try
        {
            // B3 review H1: a plain path drops trailing dots/spaces (evil.exe. would open evil.exe next to it). Such names are
            // opened in the exact \\?\ form (\\?\ input is already exact and kept as is); a name that can't be made exact is
            // refused, never approximated.
            if (ExactPath.NeedsExtended(path) && !path.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                fullPath = ExactPath.ToExtended(path) ?? throw new ArgumentException(
                    "The path has a name ending in a dot or space and can't be opened exactly.", nameof(path));
            }
            else
            {
                fullPath = Path.GetFullPath(path);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            failure = new(HashFailureReason.InvalidPath, ex.Message);
            return null;
        }

        if (Sha256Hasher.IsDeviceNamespacePath(fullPath))
        {
            failure = new(HashFailureReason.NotRegularFile, $"Path resolves to a device ({fullPath}), not a regular file.");
            return null;
        }

        var handle = NativeFile.OpenForScan(fullPath, denyWriters, out int error, additionalAccess);
        if (handle.IsInvalid)
        {
            // Review B H2: no follow-up lookup of a link's target to relabel the failure (a file symlink to a directory is
            // reported as the AccessDenied Windows gives); resolving the target by path would follow user-controlled links.
            failure = new(Sha256Hasher.MapWin32Error(error), $"{Marshal.GetPInvokeErrorMessage(error)} (Win32 error {error})");
            return null;
        }

        if (!Validate(handle, out failure, out attributes, allowOffline))
        {
            handle.Dispose();
            return null;
        }

        return handle;
    }

    /// <summary>
    /// Checks an open handle: a disk file (<c>GetFileType</c>), not a directory, and (unless
    /// <paramref name="allowOffline"/>) not offline or a cloud placeholder. Never throws for I/O.
    /// </summary>
    public static bool Validate(SafeFileHandle handle, out SecureOpenFailure failure, out FileAttributes attributes, bool allowOffline = false)
    {
        ArgumentNullException.ThrowIfNull(handle);
        attributes = default;
        if (handle.IsInvalid || handle.IsClosed)
        {
            failure = new(HashFailureReason.InvalidPath, "The file handle is invalid or closed.");
            return false;
        }

        try
        {
            // First thing after opening: only disk files go further.
            uint fileType = NativeFile.GetFileType(handle);
            if (fileType != NativeFile.FileTypeDisk)
            {
                failure = new(HashFailureReason.NotRegularFile,
                    $"Not a regular file (file type {fileType}: device, pipe or other non-disk target).");
                return false;
            }

            attributes = File.GetAttributes(handle);
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                failure = new(HashFailureReason.Directory, "Path is a directory.", Attributes: attributes);
                return false;
            }

            if (!allowOffline && Sha256Hasher.IsOfflineOrPlaceholder(attributes))
            {
                failure = new(HashFailureReason.Offline, "File is offline or a cloud placeholder; not read to avoid a download.",
                    RandomAccess.GetLength(handle), attributes, File.GetLastWriteTimeUtc(handle));
                return false;
            }

            failure = default;
            return true;
        }
        catch (Exception ex) when (Sha256Hasher.TryClassify(ex, out var reason))
        {
            failure = new(reason, ex.Message);
            return false;
        }
    }
}
