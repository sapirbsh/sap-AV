using System.IO.MemoryMappedFiles;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;

namespace SapAV.Core.Yara;

/// <summary>Scans files and buffers with YARA rules. Implemented by <see cref="YaraScanner"/>; fake it in tests (A7).</summary>
/// <remarks>
/// Synchronous on purpose, like <see cref="Signatures.ISignatureVerifier"/>: YARA-X scans are blocking native
/// calls. Callers run them on the scan worker threads (B3). Implementations are thread-safe.
/// </remarks>
public interface IYaraScanner
{
    /// <summary>Largest content size, in bytes, that is scanned; larger content gives TooLarge.</summary>
    long MaxSizeBytes { get; }

    /// <summary>
    /// Scans the regular file at <paramref name="path"/>. Problems with the path or file (devices, pipes,
    /// directories, offline files, too large, access denied, ...), timeouts and engine errors are reported in
    /// the result, never thrown.
    /// </summary>
    /// <param name="cancellationToken">Honored before opening and before the scan starts; a running YARA-X scan
    /// can't be interrupted (it is bounded by the per-scan timeout instead).</param>
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    YaraScanResult ScanFile(string path, CancellationToken cancellationToken = default);

    /// <summary>Scans a buffer. Same reporting rules as <see cref="ScanFile"/>.</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    YaraScanResult ScanMemory(ReadOnlySpan<byte> data, CancellationToken cancellationToken = default);
}

/// <summary>
/// The YARA scanner: a <see cref="YaraRuleSet"/> plus size limits and a per-scan timeout. Thread-safe.
/// </summary>
/// <remarks>
/// <para>File scanning never lets YARA-X open the path by name (that would bypass the A2 protections). In order:</para>
/// <list type="number">
/// <item>The file is opened through <see cref="SecureFile"/>: the same path checks and hardened flags as the
/// hasher (device paths never opened, <c>GetFileType</c> must be disk, no directories, no offline files /
/// cloud placeholders). Files over <see cref="MaxSizeBytes"/> are TooLarge.</item>
/// <item><b>Crash safety.</b> YARA-X is Rust code with no structured-exception guard, so a page that fails
/// to load while it reads a memory-mapped view (media pulled, network drop, disk error) would kill the process.
/// The file is therefore memory-mapped (read-only, from <b>that handle</b>) only when it is on a local
/// DRIVE_FIXED volume (<see cref="NativeFile.IsOnLocalFixedVolume"/>). Anything else (removable, network,
/// unknown) is read into a pooled buffer instead, where an I/O error is an ordinary IoError, with the lower
/// <see cref="MaxBufferedSizeBytes"/> cap. While a view is mapped, NTFS refuses to truncate the file, and
/// byte-range locks don't fault a view.</item>
/// <item>Empty files are scanned as empty data (rules on <c>filesize == 0</c> still work).</item>
/// <item>If size or last-write time changed during the scan, the result is discarded (ChangedDuringScan).</item>
/// </list>
/// <para>
/// Each scan creates its own YARA-X scanner over the shared compiled rules (the C API's threading model) and
/// destroys it before the rules' reference is released. The timeout is per scan and in whole seconds (the
/// engine's unit; rounded up, at least 1 s). A Rust panic inside the engine still aborts the process; B5 moves
/// scanning into a low-privilege worker process for that reason.
/// </para>
/// </remarks>
public sealed unsafe class YaraScanner : IYaraScanner
{
    /// <summary>Default per-scan timeout: 30 seconds.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Default size cap for files that can't be memory-mapped and are read into memory: 64 MiB.</summary>
    public const long DefaultMaxBufferedSizeBytes = 64L * 1024 * 1024;

    private const int BufferedReadChunk = 1024 * 1024;

    private YaraRuleSet _rules;

    /// <param name="rules">The rules to scan with. Not owned: the caller disposes it (after swapping it out).</param>
    /// <param name="maxSizeBytes">Largest content size that is scanned (default: the hasher's limit, 256 MiB).</param>
    /// <param name="timeout">Per-scan timeout (default <see cref="DefaultTimeout"/>); <see cref="Timeout.InfiniteTimeSpan"/> for none.</param>
    /// <param name="maxBufferedSizeBytes">Largest file read into memory when it can't be mapped (default 64 MiB).</param>
    public YaraScanner(
        YaraRuleSet rules,
        long maxSizeBytes = Sha256Hasher.DefaultMaxSizeBytes,
        TimeSpan? timeout = null,
        long maxBufferedSizeBytes = DefaultMaxBufferedSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBufferedSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxBufferedSizeBytes, (long)Array.MaxLength);
        var t = timeout ?? DefaultTimeout;
        if (t != System.Threading.Timeout.InfiniteTimeSpan && t <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), t, "The timeout must be positive or infinite.");
        }

        _rules = rules;
        MaxSizeBytes = maxSizeBytes;
        MaxBufferedSizeBytes = maxBufferedSizeBytes;
        Timeout = t;
        TimeoutSeconds = t == System.Threading.Timeout.InfiniteTimeSpan
            ? 0
            : (int)Math.Clamp(Math.Ceiling(t.TotalSeconds), 1, int.MaxValue);
    }

    public long MaxSizeBytes { get; }

    /// <summary>Size cap for files read into a buffer because they are not on a local fixed volume.</summary>
    public long MaxBufferedSizeBytes { get; }

    public TimeSpan Timeout { get; }

    /// <summary>The timeout passed to YARA-X, in seconds (0 = none).</summary>
    public int TimeoutSeconds { get; }

    /// <summary>The current rule set.</summary>
    public YaraRuleSet Rules => Volatile.Read(ref _rules);

    /// <summary>Test seam: true forces the buffered path, as for a file on removable or network media.</summary>
    internal bool ForceBufferedRead { get; init; }

    /// <summary>Test seam: called with true when a file is scanned from a mapped view, false when buffered.</summary>
    internal Action<bool>? ScanModeHook { get; init; }

    /// <summary>
    /// Replaces the rule set (e.g. after a reload) and returns the previous one, which the caller should dispose.
    /// Scans already running finish with the old rules; a scan that loses the race against disposal is retried
    /// once with the new rules.
    /// </summary>
    public YaraRuleSet SwapRules(YaraRuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return Interlocked.Exchange(ref _rules, rules);
    }

    /// <inheritdoc/>
    public YaraScanResult ScanMemory(ReadOnlySpan<byte> data, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (data.Length > MaxSizeBytes)
        {
            return YaraScanResult.NotScanned(YaraFailureReason.TooLarge,
                $"Buffer is {data.Length} bytes, over the {MaxSizeBytes}-byte limit.", data.Length);
        }

        fixed (byte* p = data)
        {
            return ScanWithCurrentRules(p, data.Length);
        }
    }

    /// <inheritdoc/>
    public YaraScanResult ScanFile(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        cancellationToken.ThrowIfCancellationRequested();

        using var handle = SecureFile.OpenRegularFile(path, out var failure, out _);
        if (handle is null)
        {
            return YaraScanResult.NotScanned(YaraScanResult.FromHashFailure(failure.Reason), failure.Message, failure.Length);
        }

        return ScanOpenFile(handle, cancellationToken);
    }

    /// <summary>Scans an already opened, already validated regular file (see <see cref="SecureFile"/>).</summary>
    internal YaraScanResult ScanOpenFile(SafeFileHandle handle, CancellationToken cancellationToken)
    {
        try
        {
            long length = RandomAccess.GetLength(handle);
            if (length > MaxSizeBytes)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.TooLarge,
                    $"File is {length} bytes, over the {MaxSizeBytes}-byte limit; not YARA-scanned.", length);
            }

            bool mapped = length > 0 && !ForceBufferedRead && NativeFile.IsOnLocalFixedVolume(handle);
            if (length > 0 && !mapped && length > MaxBufferedSizeBytes)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.TooLarge,
                    $"File is {length} bytes and not on a local fixed disk; over the {MaxBufferedSizeBytes}-byte limit " +
                    "for files that are read into memory.", length);
            }

            var lastWrite = File.GetLastWriteTimeUtc(handle);
            cancellationToken.ThrowIfCancellationRequested();

            ScanModeHook?.Invoke(mapped);
            var result = length == 0 ? ScanWithCurrentRules(null, 0)
                : mapped ? ScanMapped(handle, length)
                : ScanBuffered(handle, length, cancellationToken);

            long lengthAfter = RandomAccess.GetLength(handle);
            var lastWriteAfter = File.GetLastWriteTimeUtc(handle);
            if (lengthAfter != length || lastWriteAfter != lastWrite)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.ChangedDuringScan,
                    $"File changed during the YARA scan (size {length} -> {lengthAfter}, " +
                    $"last write {lastWrite:O} -> {lastWriteAfter:O}).", lengthAfter);
            }

            return result;
        }
        catch (Exception ex) when (Sha256Hasher.TryClassify(ex, out var reason))
        {
            return YaraScanResult.NotScanned(YaraScanResult.FromHashFailure(reason), ex.Message);
        }
    }

    /// <summary>Reads the whole file into a pooled buffer (I/O errors are exceptions here, not page faults) and scans it.</summary>
    private YaraScanResult ScanBuffered(SafeFileHandle handle, long length, CancellationToken cancellationToken)
    {
        int size = (int)length;
        var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(size);
        int total = 0;
        try
        {
            while (total < size)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int read = RandomAccess.Read(handle, buffer.AsSpan(total, Math.Min(BufferedReadChunk, size - total)), total);
                if (read == 0)
                {
                    return YaraScanResult.NotScanned(YaraFailureReason.ChangedDuringScan,
                        $"File ended after {total} of {length} bytes.", total);
                }

                total += read;
            }

            fixed (byte* p = buffer)
            {
                return ScanWithCurrentRules(p, length);
            }
        }
        finally
        {
            Array.Clear(buffer, 0, total); // it held file content and goes back to a shared pool
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private YaraScanResult ScanMapped(SafeFileHandle handle, long length)
    {
        MemoryMappedFile mapping;
        try
        {
            // Capacity 0 = the file's size now. leaveOpen: the caller owns the handle.
            mapping = MemoryMappedFile.CreateFromFile(
                handle, mapName: null, capacity: 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
        }
        catch (ArgumentException ex)
        {
            // The file became empty between the size check and the mapping.
            return YaraScanResult.NotScanned(YaraFailureReason.ChangedDuringScan, ex.Message);
        }

        using (mapping)
        {
            // The mapping fixes the size; the file can't shrink below it while mapped, but it may have grown.
            if (RandomAccess.GetLength(handle) != length)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.ChangedDuringScan,
                    "File size changed before it could be mapped.");
            }

            using var view = mapping.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);
            var viewHandle = view.SafeMemoryMappedViewHandle;
            byte* pointer = null;
            viewHandle.AcquirePointer(ref pointer);
            try
            {
                return ScanWithCurrentRules(pointer + view.PointerOffset, length);
            }
            finally
            {
                viewHandle.ReleasePointer();
            }
        }
    }

    private YaraScanResult ScanWithCurrentRules(byte* data, long length)
    {
        var rules = Rules;
        var result = rules.ScanMemory(data, length, TimeoutSeconds);
        if (result.FailureReason == YaraFailureReason.RulesDisposed && Rules is var current && !ReferenceEquals(current, rules))
        {
            result = current.ScanMemory(data, length, TimeoutSeconds); // lost the race with a reload: retry once
        }

        return result;
    }
}
