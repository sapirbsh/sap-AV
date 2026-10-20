using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SapAV.Core.Hashing;

/// <summary>
/// Streaming SHA-256 hasher with a size limit. Reads through one fixed-size pooled buffer, so memory use
/// does not depend on file size. Thread-safe: one instance can hash many files concurrently.
/// </summary>
/// <remarks>
/// File hashing (<see cref="HashFileAsync"/>), in order:
/// <list type="number">
/// <item>Rejects empty/whitespace paths and paths with an embedded NUL (InvalidPath).</item>
/// <item>Rejects device-namespace paths (<c>\\.\pipe\x</c>, <c>\\.\NUL</c>, raw volumes and disks) on both
/// the raw path and <see cref="Path.GetFullPath(string)"/>, which turns legacy names such as <c>CON</c>,
/// <c>NUL</c>, <c>COM1</c> and <c>LPT1</c> into <c>\\.\...</c>. These are never opened (NotRegularFile).</item>
/// <item>Opens with <c>CreateFileW</c> (see <see cref="NativeFile.HashingFlags"/>): shared Read/Write/Delete,
/// backup semantics (directories open and are reported as Directory), no recall (a cloud placeholder is
/// never downloaded, even through a link), and anonymous impersonation for any pipe reached through a
/// link or junction.</item>
/// <item>Right after opening, before any read or metadata use, requires <c>GetFileType</c> = disk;
/// anything else is closed as NotRegularFile. Then attributes from the handle: Directory, or
/// Offline/placeholder (not read). The FileStream CanSeek check stays as a second backstop.</item>
/// <item>Reads last-write time and size from the same handle (no separate stat).</item>
/// <item>Hashes, reading at most limit + 1 bytes, so a file that grows past the limit is reported as
/// TooLarge instead of being read on.</item>
/// <item>Re-reads last-write time and size from the handle; if either changed, or the bytes read don't
/// match the size, reports ChangedDuringHashing so a half-written file can't be cached as Clean.</item>
/// </list>
/// Content exactly at the limit is hashed; content over it is not.
/// </remarks>
public sealed class Sha256Hasher : IFileHasher
{
    /// <summary>Default size limit: 256 MiB.</summary>
    public const long DefaultMaxSizeBytes = 256L * 1024 * 1024;

    /// <summary>
    /// Default read buffer size: 128 KiB. A power of two, so <see cref="ArrayPool{T}.Shared"/> returns a
    /// buffer of exactly this size. It is above the large-object-heap threshold, but it is pooled and
    /// reused, so it isn't reallocated per file.
    /// </summary>
    public const int DefaultBufferSize = 128 * 1024;

    // Exact HRESULTs (HRESULT_FROM_WIN32) as set on IOException by .NET.
    private const int HResultSharingViolation = unchecked((int)0x80070020); // ERROR_SHARING_VIOLATION
    private const int HResultLockViolation = unchecked((int)0x80070021);    // ERROR_LOCK_VIOLATION
    private const int HResultInvalidName = unchecked((int)0x8007007B);      // ERROR_INVALID_NAME
    private const int HResultVirusInfected = unchecked((int)0x800700E1);    // ERROR_VIRUS_INFECTED
    private const int HResultVirusDeleted = unchecked((int)0x800700E2);     // ERROR_VIRUS_DELETED

    // Cloud-file attributes not named in System.IO.FileAttributes.
    private const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;       // FILE_ATTRIBUTE_RECALL_ON_OPEN
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000; // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

    private readonly int _bufferSize;

    /// <param name="maxSizeBytes">Largest content size that is hashed, in bytes (0 or more).</param>
    /// <param name="bufferSize">Read buffer size in bytes (1 or more).</param>
    public Sha256Hasher(long maxSizeBytes = DefaultMaxSizeBytes, int bufferSize = DefaultBufferSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 1);
        MaxSizeBytes = maxSizeBytes;
        _bufferSize = bufferSize;
    }

    public long MaxSizeBytes { get; }

    /// <summary>
    /// Test seam: awaited before each read with the number of bytes read so far
    /// (lets tests modify a file mid-hash deterministically, or prove that nothing was read).
    /// </summary>
    internal Func<long, Task>? BeforeReadHook { get; init; }

    /// <inheritdoc/>
    public async Task<HashResult> HashFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0'))
        {
            return HashResult.NotHashed(HashFailureReason.InvalidPath, "Path is empty, blank or contains a NUL character.");
        }

        if (IsDeviceNamespacePath(path))
        {
            return HashResult.NotHashed(HashFailureReason.NotRegularFile,
                "Device-namespace path (pipe, device or volume), not a regular file.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return HashResult.NotHashed(HashFailureReason.InvalidPath, ex.Message);
        }

        if (IsDeviceNamespacePath(fullPath))
        {
            return HashResult.NotHashed(HashFailureReason.NotRegularFile,
                $"Path resolves to a device ({fullPath}), not a regular file.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var handle = NativeFile.OpenForHashing(fullPath, out int error);
        if (handle.IsInvalid)
        {
            var reason = MapWin32Error(error);
            if (reason == HashFailureReason.AccessDenied && IsFileSymlinkToDirectory(fullPath))
            {
                // Windows refuses to open a file-type symlink whose target is a directory.
                return HashResult.NotHashed(HashFailureReason.Directory, "Path is a symbolic link to a directory.");
            }

            return HashResult.NotHashed(reason, $"{Marshal.GetPInvokeErrorMessage(error)} (Win32 error {error})");
        }

        FileStream? stream = null;
        try
        {
            // First thing after opening: only disk files go further. Pipes, consoles and other devices
            // reached through links or junctions are closed here, before any read or metadata call.
            uint fileType = NativeFile.GetFileType(handle);
            if (fileType != NativeFile.FileTypeDisk)
            {
                return HashResult.NotHashed(HashFailureReason.NotRegularFile,
                    $"Not a regular file (file type {fileType}: device, pipe or other non-disk target).");
            }

            var attributes = File.GetAttributes(handle);
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                return HashResult.NotHashed(HashFailureReason.Directory, "Path is a directory.", attributes: attributes);
            }

            var lastWrite = File.GetLastWriteTimeUtc(handle);
            if (IsOfflineOrPlaceholder(attributes))
            {
                return HashResult.NotHashed(HashFailureReason.Offline,
                    "File is offline or a cloud placeholder; not read to avoid a download.",
                    RandomAccess.GetLength(handle), lastWrite, attributes);
            }

            stream = new FileStream(handle, FileAccess.Read, bufferSize: 0, isAsync: true);
            return await HashOpenFileAsync(stream, attributes, lastWrite, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (TryClassify(ex, out var reason))
        {
            return HashResult.NotHashed(reason, ex.Message);
        }
        finally
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false); // also closes the handle
            }
            else
            {
                handle.Dispose();
            }
        }
    }

    public async Task<HashResult> HashStreamAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("Stream must be readable.", nameof(stream));
        }

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            long? knownRemaining = stream.CanSeek ? Math.Max(0, stream.Length - stream.Position) : null;
            if (knownRemaining > MaxSizeBytes)
            {
                return HashResult.NotHashed(HashFailureReason.TooLarge, length: knownRemaining);
            }

            var (sha256, bytesRead) = await HashCoreAsync(stream, cancellationToken).ConfigureAwait(false);
            return sha256 is null
                ? HashResult.NotHashed(HashFailureReason.TooLarge, length: bytesRead)
                : HashResult.Hashed(sha256, bytesRead);
        }
        catch (Exception ex) when (TryClassify(ex, out var reason))
        {
            return HashResult.NotHashed(reason, ex.Message);
        }
    }

    private async Task<HashResult> HashOpenFileAsync(
        FileStream stream, FileAttributes attributes, DateTime lastWrite, CancellationToken cancellationToken)
    {
        // Second backstop after GetFileType: FileStream only reports CanSeek for disk files.
        if (!stream.CanSeek)
        {
            return HashResult.NotHashed(HashFailureReason.NotRegularFile,
                "Not a regular file (device, pipe or other non-disk target).");
        }

        long length = stream.Length;
        if (length > MaxSizeBytes)
        {
            return HashResult.NotHashed(HashFailureReason.TooLarge, length: length,
                lastWriteTimeUtc: lastWrite, attributes: attributes);
        }

        var (sha256, bytesRead) = await HashCoreAsync(stream, cancellationToken).ConfigureAwait(false);
        if (sha256 is null)
        {
            return HashResult.NotHashed(HashFailureReason.TooLarge, length: bytesRead,
                lastWriteTimeUtc: lastWrite, attributes: attributes);
        }

        var lastWriteAfter = File.GetLastWriteTimeUtc(stream.SafeFileHandle);
        long lengthAfter = stream.Length;
        if (lastWriteAfter != lastWrite || lengthAfter != length || bytesRead != length)
        {
            return HashResult.NotHashed(HashFailureReason.ChangedDuringHashing,
                $"File changed during hashing (size {length} -> {lengthAfter}, read {bytesRead} bytes, " +
                $"last write {lastWrite:O} -> {lastWriteAfter:O}).",
                lengthAfter, lastWriteAfter, attributes);
        }

        return HashResult.Hashed(sha256, bytesRead, lastWrite, attributes);
    }

    /// <summary>Hashes to the end of the stream; returns a null hash if more than the limit was read.</summary>
    private async Task<(string? Sha256, long BytesRead)> HashCoreAsync(Stream stream, CancellationToken cancellationToken)
    {
        // Never read more than limit + 1 bytes: one extra byte proves the content is over the limit.
        long readCap = MaxSizeBytes == long.MaxValue ? long.MaxValue : MaxSizeBytes + 1;
        long total = 0;

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(_bufferSize);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (BeforeReadHook is { } hook)
                {
                    await hook(total).ConfigureAwait(false);
                }

                int toRead = (int)Math.Min(_bufferSize, readCap - total);
                int read = await stream.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > MaxSizeBytes)
                {
                    return (null, total);
                }

                sha.AppendData(buffer, 0, read);
            }
        }
        finally
        {
            // Clear: the buffer held file content and goes back to a shared pool.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        return (Convert.ToHexStringLower(sha.GetHashAndReset()), total);
    }

    /// <summary>
    /// True for Win32 device-namespace paths (<c>\\.\...</c> or <c>\\?\...</c>, and the NT form
    /// <c>\??\...</c>) that don't name a file on a drive, UNC share or volume GUID: pipes, devices, raw
    /// volumes and disks. <c>\\?\C:\x</c>, <c>\\?\UNC\server\share\x</c> and <c>\\?\Volume{guid}\x</c> are
    /// regular file paths and return false.
    /// </summary>
    internal static bool IsDeviceNamespacePath(string path)
    {
        bool win32Prefix = path.Length >= 4
            && IsSeparator(path[0]) && IsSeparator(path[1]) && (path[2] is '.' or '?') && IsSeparator(path[3]);
        bool ntPrefix = path.Length >= 4 && path[0] == '\\' && path[1] == '?' && path[2] == '?' && path[3] == '\\';
        if (!win32Prefix && !ntPrefix)
        {
            return false;
        }

        var rest = path.AsSpan(4);
        bool driveFile = rest.Length >= 3 && char.IsAsciiLetter(rest[0]) && rest[1] == ':' && IsSeparator(rest[2]);
        bool uncFile = rest.Length >= 4 && rest[..3].Equals("UNC", StringComparison.OrdinalIgnoreCase) && IsSeparator(rest[3]);
        bool volumeFile = rest.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase) && rest.IndexOfAny('\\', '/') > 0;
        return !(driveFile || uncFile || volumeFile);

        static bool IsSeparator(char c) => c is '\\' or '/';
    }

    /// <summary>
    /// Only used to label an AccessDenied open: reads the first hop of a link from its reparse data
    /// (<see cref="FileSystemInfo.LinkTarget"/> opens the link itself, not the target) and checks whether
    /// it names an existing directory by an ordinary path. It never leads to another open for hashing.
    /// </summary>
    private static bool IsFileSymlinkToDirectory(string fullPath)
    {
        try
        {
            var target = new FileInfo(fullPath).LinkTarget;
            if (target is null || IsDeviceNamespacePath(target))
            {
                return false;
            }

            var resolved = Path.IsPathFullyQualified(target)
                ? target
                : Path.GetFullPath(target, Path.GetDirectoryName(fullPath) ?? string.Empty);
            return !IsDeviceNamespacePath(resolved) && Directory.Exists(resolved);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>True for offline files and cloud placeholders whose content would have to be recalled.</summary>
    internal static bool IsOfflineOrPlaceholder(FileAttributes attributes) =>
        (attributes & (FileAttributes.Offline | RecallOnOpen | RecallOnDataAccess)) != 0;

    /// <summary>Maps a Win32 error from <c>CreateFileW</c> to a reason (exact codes).</summary>
    internal static HashFailureReason MapWin32Error(int error) => error switch
    {
        2 or 3 or 15 or 53 or 67 => HashFailureReason.NotFound,  // FILE_NOT_FOUND, PATH_NOT_FOUND, INVALID_DRIVE, BAD_NETPATH, BAD_NET_NAME
        5 => HashFailureReason.AccessDenied,                      // ACCESS_DENIED
        32 or 33 => HashFailureReason.Locked,                     // SHARING_VIOLATION, LOCK_VIOLATION
        225 or 226 => HashFailureReason.BlockedByAntivirus,       // VIRUS_INFECTED, VIRUS_DELETED
        123 or 161 or 206 => HashFailureReason.InvalidPath,       // INVALID_NAME, BAD_PATHNAME, FILENAME_EXCED_RANGE
        1921 => HashFailureReason.InvalidPath,                    // CANT_RESOLVE_FILENAME (link loop / too many links)
        231 => HashFailureReason.NotRegularFile,                  // PIPE_BUSY: the path led to a pipe
        _ => HashFailureReason.IoError,                           // incl. 1920 CANT_ACCESS_FILE (unsupported reparse point)
    };

    /// <summary>Maps expected I/O failures to a reason. Cancellation and programming errors are not mapped.</summary>
    internal static bool TryClassify(Exception ex, out HashFailureReason reason)
    {
        reason = ex switch
        {
            UnauthorizedAccessException => HashFailureReason.AccessDenied,
            FileNotFoundException or DirectoryNotFoundException or DriveNotFoundException => HashFailureReason.NotFound,
            PathTooLongException => HashFailureReason.InvalidPath,
            IOException { HResult: HResultSharingViolation or HResultLockViolation } => HashFailureReason.Locked,
            IOException { HResult: HResultVirusInfected or HResultVirusDeleted } => HashFailureReason.BlockedByAntivirus,
            IOException { HResult: HResultInvalidName } => HashFailureReason.InvalidPath,
            IOException => HashFailureReason.IoError,
            _ => HashFailureReason.None,
        };

        return reason != HashFailureReason.None;
    }
}
