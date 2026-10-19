using System.Diagnostics.CodeAnalysis;
using SapAV.Core.Models;

namespace SapAV.Core.Hashing;

/// <summary>
/// Outcome of hashing a file or stream. <see cref="Status"/> uses <see cref="ScanStatus"/> directly so it
/// maps 1:1 to a <see cref="ScanResult"/>: <see cref="ScanStatus.Scanned"/> means "hashed", anything else
/// means the content was not (fully) read and there is no hash. <see cref="FailureReason"/> says why.
/// </summary>
/// <remarks>
/// Invariants: <see cref="Sha256"/> is non-null exactly when <see cref="Status"/> is Scanned, and
/// <see cref="FailureReason"/> is <see cref="HashFailureReason.None"/> exactly then. All properties are
/// get-only, so <c>with</c> cannot break them.
/// <para>Typical use in the scanner (A7):</para>
/// <code>
/// var hash = await hasher.HashFileAsync(item.Path, ct);
/// if (!hash.IsHashed) return hash.ToNotScannedResult(item, now);
/// // ... blocklist lookup with hash.Sha256, then new ScanResult(item, detections, now, hash.Sha256)
/// </code>
/// </remarks>
public sealed record HashResult
{
    private HashResult(
        ScanStatus status,
        HashFailureReason failureReason,
        string? sha256,
        long? length,
        string? errorMessage,
        DateTime? lastWriteTimeUtc,
        FileAttributes? attributes)
    {
        Status = status;
        FailureReason = failureReason;
        Sha256 = sha256;
        Length = length;
        ErrorMessage = errorMessage;
        LastWriteTimeUtc = lastWriteTimeUtc;
        Attributes = attributes;
    }

    /// <summary>Scanned (hashed), SkippedTooLarge, SkippedOffline, AccessDenied, Locked or Error.</summary>
    public ScanStatus Status { get; }

    /// <summary>Why the content was not hashed; <see cref="HashFailureReason.None"/> when it was.</summary>
    public HashFailureReason FailureReason { get; }

    /// <summary>Lowercase hex SHA-256; non-null only when <see cref="IsHashed"/>.</summary>
    public string? Sha256 { get; }

    /// <summary>
    /// When hashed: the number of bytes hashed. When TooLarge: the size that exceeded the limit (the
    /// reported size, or for content that grew while being read, the bytes seen so far, at least
    /// limit + 1). Otherwise the size from the file handle if it was known, else <c>null</c>.
    /// </summary>
    public long? Length { get; }

    /// <summary>Human-readable diagnostic text for logs (not for logic; use <see cref="FailureReason"/>).</summary>
    public string? ErrorMessage { get; }

    /// <summary>
    /// Last-write time read from the same handle that was hashed, before the first read
    /// (file hashing only; <c>null</c> for streams or when the file wasn't opened).
    /// Together with <see cref="Length"/> this is a cache key that needs no separate stat call.
    /// </summary>
    public DateTime? LastWriteTimeUtc { get; }

    /// <summary>
    /// File attributes, read from the opened handle (including for Offline / cloud placeholders).
    /// <c>null</c> for streams, or when the file could not be opened.
    /// </summary>
    public FileAttributes? Attributes { get; }

    [MemberNotNullWhen(true, nameof(Sha256))]
    public bool IsHashed => Status == ScanStatus.Scanned;

    /// <exception cref="ArgumentException"><paramref name="sha256"/> is not 64 hex characters.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is negative.</exception>
    public static HashResult Hashed(
        string sha256, long length, DateTime? lastWriteTimeUtc = null, FileAttributes? attributes = null)
    {
        if (!Sha256Hex.TryNormalize(sha256, out var normalized))
        {
            throw new ArgumentException("SHA-256 must be 64 hexadecimal characters.", nameof(sha256));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(length);
        return new HashResult(
            ScanStatus.Scanned, HashFailureReason.None, normalized, length, null, lastWriteTimeUtc, attributes);
    }

    /// <summary>A result with no hash; the status is derived from <paramref name="reason"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="reason"/> is None or undefined, or <paramref name="length"/> is negative.
    /// </exception>
    public static HashResult NotHashed(
        HashFailureReason reason,
        string? errorMessage = null,
        long? length = null,
        DateTime? lastWriteTimeUtc = null,
        FileAttributes? attributes = null)
    {
        if (length is < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "Length must not be negative.");
        }

        return new HashResult(
            StatusFor(reason), reason, null, length, errorMessage, lastWriteTimeUtc, attributes);
    }

    /// <summary>The <see cref="ScanStatus"/> a failure reason maps to.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None or undefined.</exception>
    public static ScanStatus StatusFor(HashFailureReason reason) => reason switch
    {
        HashFailureReason.AccessDenied => ScanStatus.AccessDenied,
        HashFailureReason.Locked => ScanStatus.Locked,
        HashFailureReason.TooLarge => ScanStatus.SkippedTooLarge,
        HashFailureReason.Offline => ScanStatus.SkippedOffline,
        HashFailureReason.InvalidPath
            or HashFailureReason.NotRegularFile
            or HashFailureReason.Directory
            or HashFailureReason.NotFound
            or HashFailureReason.ChangedDuringHashing
            or HashFailureReason.BlockedByAntivirus
            or HashFailureReason.IoError => ScanStatus.Error,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason,
            "None or undefined; use Hashed() for a successful hash."),
    };

    /// <summary>Builds the <see cref="ScanResult"/> for content that could not be hashed.</summary>
    /// <exception cref="InvalidOperationException">The content was hashed; build a scanned result instead.</exception>
    public ScanResult ToNotScannedResult(ScanItem item, DateTimeOffset timestamp)
    {
        if (IsHashed)
        {
            throw new InvalidOperationException("The content was hashed; build a scanned ScanResult instead.");
        }

        return ScanResult.NotScanned(item, Status, timestamp);
    }
}
