using System.IO.MemoryMappedFiles;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;

namespace SapAV.Core.Yara;

/// <summary>Scans files and buffers with YARA rules. Implemented by <see cref="YaraScanner"/>; fake it in tests (A7).</summary>
/// <remarks>
/// Synchronous on purpose, like <see cref="Signatures.ISignatureVerifier"/>: libyara scans are blocking native
/// calls. Callers run them on the scan worker threads (B3). Implementations are thread-safe.
/// </remarks>
public interface IYaraScanner
{
    /// <summary>Largest content size, in bytes, that is scanned; larger content gives TooLarge.</summary>
    long MaxSizeBytes { get; }

    /// <summary>
    /// Scans the regular file at <paramref name="path"/>. Problems with the path or file (devices, pipes,
    /// directories, offline files, too large, access denied, ...), timeouts and libyara errors are reported in
    /// the result, never thrown.
    /// </summary>
    /// <param name="cancellationToken">Honored before opening and before the scan starts; a running libyara scan
    /// can't be interrupted (it is bounded by the per-scan timeout instead).</param>
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    YaraScanResult ScanFile(string path, CancellationToken cancellationToken = default);

    /// <summary>Scans a buffer. Same reporting rules as <see cref="ScanFile"/>.</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    YaraScanResult ScanMemory(ReadOnlySpan<byte> data, CancellationToken cancellationToken = default);
}

/// <summary>
/// The YARA scanner: a <see cref="YaraRuleSet"/> plus a size limit and a per-scan timeout. Thread-safe.
/// </summary>
/// <remarks>
/// <para>File scanning never lets libyara open the path by name (that would bypass the A2 protections). In order:</para>
/// <list type="number">
/// <item>The same path checks as <see cref="Sha256Hasher"/>: empty/NUL paths are InvalidPath; device-namespace
/// paths (raw, or after <see cref="Path.GetFullPath(string)"/>, which maps <c>CON</c>, <c>NUL</c>, ... to
/// <c>\\.\...</c>) are NotRegularFile and never opened.</item>
/// <item>One open with the hardened flags (<see cref="NativeFile.OpenForMemoryMap"/>: shared, backup semantics,
/// no cloud recall, anonymous SQOS for pipes reached through links). Then <c>GetFileType</c> must be disk;
/// directories, offline files and cloud placeholders are not scanned; files over <see cref="MaxSizeBytes"/> are
/// TooLarge.</item>
/// <item>A read-only memory mapping is created from <b>that handle</b> and libyara scans the mapped view
/// (<c>yr_rules_scan_mem</c>). Empty files can't be mapped, so an empty buffer is scanned instead (rules on
/// <c>filesize == 0</c> still work). While the mapping exists, Windows refuses to truncate the file, and
/// libyara's own exception guard turns a page that fails to load into IoError instead of a crash.</item>
/// <item>If size or last-write time changed during the scan, the result is discarded (ChangedDuringScan).</item>
/// </list>
/// <para>
/// The timeout is per scan and in whole seconds (libyara's unit; rounded up, at least 1 s).
/// </para>
/// </remarks>
public sealed unsafe class YaraScanner : IYaraScanner
{
    /// <summary>Default per-scan timeout: 30 seconds.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private YaraRuleSet _rules;

    /// <param name="rules">The rules to scan with. Not owned: the caller disposes it (after swapping it out).</param>
    /// <param name="maxSizeBytes">Largest content size that is scanned (default: the hasher's limit, 256 MiB).</param>
    /// <param name="timeout">Per-scan timeout (default <see cref="DefaultTimeout"/>); <see cref="Timeout.InfiniteTimeSpan"/> for none.</param>
    public YaraScanner(YaraRuleSet rules, long maxSizeBytes = Sha256Hasher.DefaultMaxSizeBytes, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);
        var t = timeout ?? DefaultTimeout;
        if (t != System.Threading.Timeout.InfiniteTimeSpan && t <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), t, "The timeout must be positive or infinite.");
        }

        _rules = rules;
        MaxSizeBytes = maxSizeBytes;
        Timeout = t;
        TimeoutSeconds = t == System.Threading.Timeout.InfiniteTimeSpan
            ? 0
            : (int)Math.Clamp(Math.Ceiling(t.TotalSeconds), 1, int.MaxValue);
    }

    public long MaxSizeBytes { get; }

    public TimeSpan Timeout { get; }

    /// <summary>The timeout passed to libyara, in seconds (0 = none).</summary>
    public int TimeoutSeconds { get; }

    /// <summary>The current rule set.</summary>
    public YaraRuleSet Rules => Volatile.Read(ref _rules);

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

        try
        {
            long length = RandomAccess.GetLength(handle);
            if (length > MaxSizeBytes)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.TooLarge,
                    $"File is {length} bytes, over the {MaxSizeBytes}-byte limit; not YARA-scanned.", length);
            }

            var lastWrite = File.GetLastWriteTimeUtc(handle);
            cancellationToken.ThrowIfCancellationRequested();

            var result = length == 0 ? ScanWithCurrentRules(null, 0) : ScanMapped(handle, length);

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
