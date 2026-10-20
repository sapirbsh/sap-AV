using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Hashing;

/// <summary>Why <see cref="SecureFile.OpenRegularFile"/> did not return a handle.</summary>
internal readonly record struct SecureOpenFailure(HashFailureReason Reason, string Message, long? Length = null);

/// <summary>
/// The hardened open sequence shared by the content readers that come after the hasher (YARA, heuristics,
/// Mark-of-the-Web): the same path checks and flags as <see cref="Sha256Hasher"/> and
/// <see cref="Signatures.AuthenticodeVerifier"/>, returning a synchronous handle to a regular, local file.
/// </summary>
/// <remarks>
/// In order: empty/NUL paths are InvalidPath; device-namespace paths (raw, or after
/// <see cref="Path.GetFullPath(string)"/>, which maps <c>CON</c>, <c>NUL</c>, ... to <c>\\.\...</c>) are
/// NotRegularFile and never opened; one <c>CreateFileW</c> with <see cref="NativeFile.SignatureCheckFlags"/>
/// (shared, backup semantics, no cloud recall, anonymous SQOS); then <c>GetFileType</c> must be disk, and
/// directories and offline files / cloud placeholders are rejected before anything is read.
/// </remarks>
internal static class SecureFile
{
    /// <summary>Opens <paramref name="path"/> if it is a regular local file; otherwise null and the reason.</summary>
    /// <param name="allowOffline">If true, offline files / placeholders are returned too (for metadata-only callers).</param>
    public static SafeFileHandle? OpenRegularFile(
        string path, out SecureOpenFailure failure, out FileAttributes attributes, bool allowOffline = false)
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
            fullPath = Path.GetFullPath(path);
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

        var handle = NativeFile.OpenForMemoryMap(fullPath, out int error);
        if (handle.IsInvalid)
        {
            failure = new(Sha256Hasher.MapWin32Error(error), $"{Marshal.GetPInvokeErrorMessage(error)} (Win32 error {error})");
            return null;
        }

        try
        {
            // First thing after opening: only disk files go further.
            uint fileType = NativeFile.GetFileType(handle);
            if (fileType != NativeFile.FileTypeDisk)
            {
                failure = new(HashFailureReason.NotRegularFile,
                    $"Not a regular file (file type {fileType}: device, pipe or other non-disk target).");
                handle.Dispose();
                return null;
            }

            attributes = File.GetAttributes(handle);
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                failure = new(HashFailureReason.Directory, "Path is a directory.");
                handle.Dispose();
                return null;
            }

            if (!allowOffline && Sha256Hasher.IsOfflineOrPlaceholder(attributes))
            {
                failure = new(HashFailureReason.Offline, "File is offline or a cloud placeholder; not read to avoid a download.",
                    RandomAccess.GetLength(handle));
                handle.Dispose();
                return null;
            }

            failure = default;
            return handle;
        }
        catch (Exception ex) when (Sha256Hasher.TryClassify(ex, out var reason))
        {
            handle.Dispose();
            failure = new(reason, ex.Message);
            return null;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }
}
