namespace SapAV.Core.Signatures;

/// <summary>
/// Checks a file's Authenticode signature (embedded or Windows catalog) and classifies it as Microsoft,
/// OtherTrusted or UnsignedOrInvalid. Implemented by <see cref="AuthenticodeVerifier"/>; fake it in tests (A7).
/// </summary>
/// <remarks>
/// <para>
/// <b>Synchronous on purpose.</b> WinVerifyTrust and the catalog APIs are blocking calls that read the whole
/// file and can take from milliseconds to seconds on large files or slow volumes. There is no honest async
/// version, so this interface doesn't pretend to have one. Callers run it on the scan worker threads (B3),
/// never on the UI thread, a pipe handler or the shared thread pool.
/// </para>
/// <para>
/// <b>No network.</b> Revocation checks are off and URL retrieval is cache-only, so a scan never contacts a
/// CA. A revoked certificate is only reported if Windows already knows it locally.
/// </para>
/// <para>Implementations are thread-safe.</para>
/// </remarks>
public interface ISignatureVerifier
{
    /// <summary>Largest file size, in bytes, that is checked; larger files give a not-checked TooLarge result.</summary>
    long MaxSizeBytes { get; }

    /// <summary>
    /// Checks the file at <paramref name="path"/>. Problems with the path or file (devices, pipes, directories,
    /// offline files, too large, access denied, ...) are reported as a not-checked result, never thrown.
    /// </summary>
    /// <param name="cancellationToken">Honored before opening and between the embedded and catalog checks;
    /// a WinVerifyTrust call that has started can't be interrupted.</param>
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    SignatureCheckResult Verify(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks the file behind an already open handle (the single-handle scan pipeline). Every read uses the handle;
    /// <paramref name="displayPath"/> only tells Windows which subject interface package (SIP) to use and names
    /// the file in messages. The handle is validated first and is not closed.
    /// </summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    SignatureCheckResult Verify(Microsoft.Win32.SafeHandles.SafeFileHandle handle, string displayPath, CancellationToken cancellationToken = default);
}
