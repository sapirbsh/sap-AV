using SapAV.Core.Hashing;
using SapAV.Core.Models;

namespace SapAV.Core.Yara;

/// <summary>
/// Outcome of a YARA scan, shaped like <see cref="HashResult"/>: <see cref="Status"/> is
/// <see cref="ScanStatus.Scanned"/> exactly when the content was scanned (<see cref="FailureReason"/> None);
/// otherwise there are no matches and <see cref="ToNotScannedResult"/> builds the <see cref="ScanResult"/>.
/// </summary>
/// <remarks>All properties are get-only, so <c>with</c> can't break the invariants.</remarks>
public sealed record YaraScanResult
{
    private YaraScanResult(
        ScanStatus status, YaraFailureReason failureReason, IReadOnlyList<YaraRuleInfo> matches,
        long? length, string? errorMessage, string? rulesFingerprint)
    {
        Status = status;
        FailureReason = failureReason;
        Matches = matches;
        Length = length;
        ErrorMessage = errorMessage;
        RulesFingerprint = rulesFingerprint;
    }

    public ScanStatus Status { get; }

    public YaraFailureReason FailureReason { get; }

    /// <summary>Rules that matched, in rule-set order (each at most once). Empty if not scanned.</summary>
    public IReadOnlyList<YaraRuleInfo> Matches { get; }

    /// <summary>Bytes scanned when scanned; the size that was over the limit for TooLarge; else the size if known.</summary>
    public long? Length { get; }

    /// <summary>Diagnostic text for logs (not for logic; use <see cref="FailureReason"/>).</summary>
    public string? ErrorMessage { get; }

    /// <summary>
    /// <see cref="YaraRuleSet.Fingerprint"/> of the rules used (null if the scan never reached them), so a cache
    /// entry can record which rule version produced the verdict.
    /// </summary>
    public string? RulesFingerprint { get; }

    public bool IsScanned => Status == ScanStatus.Scanned;

    /// <summary>One detection per matching rule (see <see cref="YaraRuleInfo.ToDetection"/>).</summary>
    public IReadOnlyList<Detection> Detections => Matches.Select(m => m.ToDetection()).ToArray();

    internal static YaraScanResult Scanned(IReadOnlyList<YaraRuleInfo> matches, long length, string rulesFingerprint) =>
        new(ScanStatus.Scanned, YaraFailureReason.None, matches, length, null, rulesFingerprint);

    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None or undefined.</exception>
    public static YaraScanResult NotScanned(
        YaraFailureReason reason, string? errorMessage = null, long? length = null, string? rulesFingerprint = null) =>
        new(StatusFor(reason), reason, Array.Empty<YaraRuleInfo>(), length, errorMessage, rulesFingerprint);

    /// <summary>The <see cref="ScanStatus"/> a failure reason maps to (same mapping as <see cref="HashResult.StatusFor"/>).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None or undefined.</exception>
    public static ScanStatus StatusFor(YaraFailureReason reason) => reason switch
    {
        YaraFailureReason.AccessDenied => ScanStatus.AccessDenied,
        YaraFailureReason.Locked => ScanStatus.Locked,
        YaraFailureReason.TooLarge => ScanStatus.SkippedTooLarge,
        YaraFailureReason.Offline => ScanStatus.SkippedOffline,
        YaraFailureReason.InvalidPath
            or YaraFailureReason.NotRegularFile
            or YaraFailureReason.Directory
            or YaraFailureReason.NotFound
            or YaraFailureReason.ChangedDuringScan
            or YaraFailureReason.BlockedByAntivirus
            or YaraFailureReason.IoError
            or YaraFailureReason.Timeout
            or YaraFailureReason.RulesDisposed
            or YaraFailureReason.EngineError => ScanStatus.Error,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "None or undefined."),
    };

    /// <summary>The YARA reason for a file-level <see cref="HashFailureReason"/> (same name; ChangedDuringHashing → ChangedDuringScan).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="reason"/> is None or undefined.</exception>
    public static YaraFailureReason FromHashFailure(HashFailureReason reason) => reason switch
    {
        HashFailureReason.InvalidPath => YaraFailureReason.InvalidPath,
        HashFailureReason.NotRegularFile => YaraFailureReason.NotRegularFile,
        HashFailureReason.Directory => YaraFailureReason.Directory,
        HashFailureReason.NotFound => YaraFailureReason.NotFound,
        HashFailureReason.AccessDenied => YaraFailureReason.AccessDenied,
        HashFailureReason.Locked => YaraFailureReason.Locked,
        HashFailureReason.TooLarge => YaraFailureReason.TooLarge,
        HashFailureReason.Offline => YaraFailureReason.Offline,
        HashFailureReason.ChangedDuringHashing => YaraFailureReason.ChangedDuringScan,
        HashFailureReason.BlockedByAntivirus => YaraFailureReason.BlockedByAntivirus,
        HashFailureReason.IoError => YaraFailureReason.IoError,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "None or undefined."),
    };

    /// <summary>Builds the <see cref="ScanResult"/> for content that could not be scanned (verdict null, never Clean).</summary>
    /// <exception cref="InvalidOperationException">The content was scanned.</exception>
    public ScanResult ToNotScannedResult(ScanItem item, DateTimeOffset timestamp, string? sha256 = null)
    {
        if (IsScanned)
        {
            throw new InvalidOperationException("The content was scanned; build a scanned ScanResult instead.");
        }

        return ScanResult.NotScanned(item, Status, timestamp, sha256);
    }
}
