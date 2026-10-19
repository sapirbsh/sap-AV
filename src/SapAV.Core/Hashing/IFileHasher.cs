namespace SapAV.Core.Hashing;

/// <summary>Computes SHA-256 hashes with a size limit. Implemented by <see cref="Sha256Hasher"/>.</summary>
/// <remarks>
/// <para>
/// <b>Not a "file is ready" check.</b> Files are opened with <c>FileShare.ReadWrite | FileShare.Delete</c>
/// so scanning never blocks other programs. That also means a successful open does <i>not</i> prove the
/// file is unlocked or finished downloading: a writer may still have it open. Real-time scanning (D1)
/// needs its own "wait until unlocked" probe before hashing. Changes that happen <i>during</i> hashing
/// are detected and reported as <see cref="HashFailureReason.ChangedDuringHashing"/>.
/// </para>
/// <para>
/// <b>Devices, pipes and links.</b> Device paths (<c>\\.\pipe\x</c>, <c>\\.\NUL</c>, raw volumes, and legacy
/// names such as <c>CON</c>, <c>NUL</c>, <c>COM1</c>, <c>LPT1</c> that <see cref="Path.GetFullPath(string)"/>
/// turns into <c>\\.\...</c>) are never opened. Anything reached through a reparse point (symlink,
/// junction, a chain of them, or an intermediate junction in the path) <i>may</i> be opened, but only:
/// with anonymous impersonation (a pipe server can't act as the scanner's identity), with no recall
/// (a cloud placeholder is never downloaded), and it is rejected as NotRegularFile before any read
/// or write unless <c>GetFileType</c> reports a disk file. Windows itself limits link chains (63 reparse
/// points); loops come back as a non-hashed result. Callers that enumerate folders (Full Scan, C6) don't
/// follow reparse points in the first place.
/// </para>
/// <para>
/// <b>Backup semantics.</b> Files are opened with <c>FILE_FLAG_BACKUP_SEMANTICS</c> so directories can be
/// recognized. Only a process that has explicitly <i>enabled</i> SeBackupPrivilege bypasses file ACLs
/// this way. LocalSystem holds the privilege but it is disabled by default, so today ACL denials
/// (including a user-added "deny SYSTEM" entry) still come back as AccessDenied. If the engine ever
/// enables it, on-demand scans requested over the pipe must check the requesting user's access first,
/// or they would reveal hash/size/timestamps of files that user can't read.
/// </para>
/// <para>
/// <b>Run on worker threads.</b> Opening a file (and the attribute checks before it) is synchronous and
/// cannot be canceled; on slow, network or filter-driver-heavy volumes it can block for a long time.
/// Callers should run hashing on dedicated background workers (B3's scan threads), not on the UI thread
/// or a pipe-handling thread. The cancellation token is honored before opening and between reads.
/// </para>
/// </remarks>
public interface IFileHasher
{
    /// <summary>Maximum content size in bytes that will be hashed; larger content gives SkippedTooLarge.</summary>
    long MaxSizeBytes { get; }

    /// <summary>
    /// Hashes the regular file at <paramref name="path"/>. Invalid paths, directories, devices/pipes,
    /// offline/cloud-only files, access denied, sharing/lock violations, AV blocks, missing files and
    /// files modified during hashing are reported in the result (<see cref="HashResult.FailureReason"/>),
    /// not thrown.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    Task<HashResult> HashFileAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Hashes <paramref name="stream"/> from its current position to the end. The stream is not disposed.
    /// I/O failures while reading are reported in the result, not thrown.
    /// </summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    Task<HashResult> HashStreamAsync(Stream stream, CancellationToken cancellationToken = default);
}
