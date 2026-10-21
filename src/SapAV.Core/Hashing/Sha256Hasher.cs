using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Hashing;

/// <summary>
/// Streaming SHA-256 hasher with a size limit. Reads through one fixed-size pooled buffer, so memory use
/// does not depend on file size. Thread-safe: one instance can hash many files concurrently.
/// </summary>
/// <remarks>
/// File hashing, in order:
/// <list type="number">
/// <item><see cref="HashFileAsync"/> opens the path through <see cref="SecureFile"/>: empty/NUL paths are
/// InvalidPath; device-namespace paths (<c>\.\pipe\x</c>, <c>\.\NUL</c>, raw volumes, and legacy names such as
/// <c>CON</c>, <c>NUL</c>, <c>COM1</c> that <see cref="Path.GetFullPath(string)"/> turns into <c>\.\...</c>) are
/// NotRegularFile and never opened; then one open with shared Read/Write/Delete, backup semantics (directories
/// are reported as Directory), no recall (a cloud placeholder is never downloaded, even through a link), and
/// anonymous impersonation for any pipe reached through a link or junction.</item>
/// <item><see cref="HashHandleAsync"/> hashes a handle the caller already opened (the single-handle scan pipeline).
/// Both paths validate the handle before any read: <c>GetFileType</c> = disk, not a directory, not offline.</item>
/// <item>Reads last-write time and size from the same handle (no separate stat), then hashes with positional
/// reads from offset 0, reading at most limit + 1 bytes, so a file that grows past the limit is reported as
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

        using var handle = SecureFile.OpenRegularFile(path, out var failure, out _);
        if (handle is null)
        {
            return NotHashed(failure);
        }

        return await HashValidatedHandleAsync(handle, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<HashResult> HashHandleAsync(SafeFileHandle handle, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        cancellationToken.ThrowIfCancellationRequested();

        if (!SecureFile.Validate(handle, out var failure, out _))
        {
            return NotHashed(failure);
        }

        return await HashValidatedHandleAsync(handle, cancellationToken).ConfigureAwait(false);
    }

    internal static HashResult NotHashed(SecureOpenFailure failure) =>
        HashResult.NotHashed(failure.Reason, failure.Message, failure.Length, failure.LastWriteTimeUtc, failure.Attributes);

    /// <summary>Hashes a handle that <see cref="SecureFile"/> has validated, with positional reads from offset 0.</summary>
    private async Task<HashResult> HashValidatedHandleAsync(SafeFileHandle handle, CancellationToken cancellationToken)
    {
        try
        {
            var attributes = File.GetAttributes(handle);
            var lastWrite = File.GetLastWriteTimeUtc(handle);
            long length = RandomAccess.GetLength(handle);
            if (length > MaxSizeBytes)
            {
                return HashResult.NotHashed(HashFailureReason.TooLarge, length: length,
                    lastWriteTimeUtc: lastWrite, attributes: attributes);
            }

            var (sha256, bytesRead) = await HashCoreAsync(
                (buffer, offset, ct) => RandomAccess.ReadAsync(handle, buffer, offset, ct), cancellationToken).ConfigureAwait(false);
            if (sha256 is null)
            {
                return HashResult.NotHashed(HashFailureReason.TooLarge, length: bytesRead,
                    lastWriteTimeUtc: lastWrite, attributes: attributes);
            }

            var lastWriteAfter = File.GetLastWriteTimeUtc(handle);
            long lengthAfter = RandomAccess.GetLength(handle);
            if (lastWriteAfter != lastWrite || lengthAfter != length || bytesRead != length)
            {
                return HashResult.NotHashed(HashFailureReason.ChangedDuringHashing,
                    $"File changed during hashing (size {length} -> {lengthAfter}, read {bytesRead} bytes, " +
                    $"last write {lastWrite:O} -> {lastWriteAfter:O}).",
                    lengthAfter, lastWriteAfter, attributes);
            }

            return HashResult.Hashed(sha256, bytesRead, lastWrite, attributes);
        }
        catch (Exception ex) when (TryClassify(ex, out var reason))
        {
            return HashResult.NotHashed(reason, ex.Message);
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

            var (sha256, bytesRead) = await HashCoreAsync((buffer, _, ct) => stream.ReadAsync(buffer, ct), cancellationToken).ConfigureAwait(false);
            return sha256 is null
                ? HashResult.NotHashed(HashFailureReason.TooLarge, length: bytesRead)
                : HashResult.Hashed(sha256, bytesRead);
        }
        catch (Exception ex) when (TryClassify(ex, out var reason))
        {
            return HashResult.NotHashed(reason, ex.Message);
        }
    }


    /// <summary>Hashes until the reader returns 0; returns a null hash if more than the limit was read.</summary>
    private async Task<(string? Sha256, long BytesRead)> HashCoreAsync(
        Func<Memory<byte>, long, CancellationToken, ValueTask<int>> read, CancellationToken cancellationToken)
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
                int got = await read(buffer.AsMemory(0, toRead), total, cancellationToken).ConfigureAwait(false);
                if (got == 0)
                {
                    break;
                }

                total += got;
                if (total > MaxSizeBytes)
                {
                    return (null, total);
                }

                sha.AppendData(buffer, 0, got);
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
