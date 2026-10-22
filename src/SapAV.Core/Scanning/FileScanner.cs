using Microsoft.Win32.SafeHandles;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Signatures;
using SapAV.Core.Yara;

namespace SapAV.Core.Scanning;

/// <summary>Scans one file through the whole local detection pipeline. Implemented by <see cref="FileScanner"/>.</summary>
public interface IFileScanner
{
    /// <summary>
    /// Scans <paramref name="item"/>. File problems are reported in the result (a not-scanned status, never
    /// Clean), not thrown.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="item"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default);
}

/// <summary>
/// The detection pipeline (ROADMAP feature 2; CLAUDE.md "Detection pipeline") over <b>one file handle</b>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Single handle.</b> The file is opened once through <see cref="SecureFile"/> and that handle is passed to every
/// step (hash, signature, YARA, Mark-of-the-Web, heuristics); no step opens the path again. So a path swapped
/// between steps (rename, junction flip, made deterministic with an oplock) can't make the signature step see a
/// Microsoft-signed file while the hash and YARA saw something else: every step judges the same file object.
/// </para>
/// <para>
/// <b>No writers.</b> The handle is opened with share Read | Delete, so nobody can open the file for writing during the
/// scan. If a writer already has it open (sharing violation), the scanner falls back to a shared handle and records
/// the file's change-journal USN before and after the whole pipeline; any change (including a same-size rewrite
/// with a restored timestamp) makes the result NotScanned (Error). If the volume has no change journal, a file that
/// is open for writing is reported as Locked. Limitation: a writer that already holds the file open and has already
/// produced a journal record for every kind of change can modify it without a new record; real-time scanning (D1)
/// waits until no writer is left, and B5 moves the readers into a separate process.
/// </para>
/// <para>Steps, in order:</para>
/// <list type="number">
/// <item><b>SHA-256</b> (A2). If the file can't be opened or hashed, the result is <see cref="ScanResult.NotScanned"/>
/// via <see cref="HashResult.ToNotScannedResult"/>, never Clean, and nothing else reads the file. Skipped files get
/// a clear Warning note: SkippedTooLarge (with size and limit) and SkippedOffline (not downloaded). One exception:
/// an oversized file still gets the name and padding heuristics (A5; headers and samples only), and if they flag
/// it the result is Scanned + Suspicious with no SHA-256.</item>
/// <item><b>Blocklist</b>: a hit is Malicious <i>even if signed</i>. The signature is still checked so the result
/// records who signed it; YARA and heuristics are skipped (the verdict can't get worse).</item>
/// <item><b>Authenticode</b> (A3): Microsoft → Clean, all later steps skipped. OtherTrusted → no online lookup,
/// but YARA and heuristics run. Unsigned, invalid or not checked → every step runs.</item>
/// <item><b>YARA</b> (A4). If YARA can't scan the file (timeout, file changed, ...) and nothing else found
/// anything, the result is NotScanned with YARA's status, because "Clean" would be a guess.</item>
/// <item><b>Mark-of-the-Web</b> (A6, read relative to the handle) and <b>heuristics</b> (A5).</item>
/// <item><b>Online lookup</b> (seam for D2, <see cref="IOnlineHashLookup"/>): only without a trusted signature.</item>
/// <item><b>Verdict</b>: the worst detection; signature status and trusted signer on the <see cref="ScanResult"/>.</item>
/// </list>
/// <para>
/// Thread-safe if the components are (the built-in ones are). The signature check, YARA, MOTW and heuristics
/// are synchronous native/file calls: run scans on the scan worker threads (B3).
/// </para>
/// </remarks>
public sealed class FileScanner : IFileScanner
{
    private readonly IFileHasher _hasher;
    private readonly Func<HashBlocklist> _blocklist;
    private readonly ISignatureVerifier _signatures;
    private readonly IYaraScanner _yara;
    private readonly IMarkOfTheWebReader _motw;
    private readonly IFileHeuristics _heuristics;
    private readonly IOnlineHashLookup? _online;
    private readonly TimeProvider _time;

    /// <param name="blocklist">Returns the current blocklist (so a reload is picked up by the next scan).</param>
    /// <param name="online">Optional online lookup (D2); null = off.</param>
    /// <param name="time">Clock for result timestamps (default: system clock).</param>
    public FileScanner(
        IFileHasher hasher,
        Func<HashBlocklist> blocklist,
        ISignatureVerifier signatures,
        IYaraScanner yara,
        IMarkOfTheWebReader markOfTheWeb,
        IFileHeuristics heuristics,
        IOnlineHashLookup? online = null,
        TimeProvider? time = null)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
        _blocklist = blocklist ?? throw new ArgumentNullException(nameof(blocklist));
        _signatures = signatures ?? throw new ArgumentNullException(nameof(signatures));
        _yara = yara ?? throw new ArgumentNullException(nameof(yara));
        _motw = markOfTheWeb ?? throw new ArgumentNullException(nameof(markOfTheWeb));
        _heuristics = heuristics ?? throw new ArgumentNullException(nameof(heuristics));
        _online = online;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Test seam: runs after the file is opened and before the first step reads it.</summary>
    internal Action<SafeFileHandle>? AfterOpenHook { get; init; }

    /// <inheritdoc/>
    public async Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<ScanNote>();

        var opened = Open(item.Path, notes);
        if (opened.Handle is null)
        {
            return NotHashed(item, HashResult.NotHashed(opened.Failure.Reason, opened.Failure.Message,
                opened.Failure.Length, opened.Failure.LastWriteTimeUtc, opened.Failure.Attributes), notes, null, cancellationToken);
        }

        using var handle = opened.Handle;
        AfterOpenHook?.Invoke(handle);

        // Which file object this scan judged (B2: the quarantine acts only on this exact object).
        var identity = FileIdentity.TryCapture(handle);
        var report = await ScanOpenAsync(item, handle, notes, cancellationToken).ConfigureAwait(false) with { Identity = identity };

        // Shared fallback: the whole pipeline must have seen one unchanged version of the file.
        if (opened.UsnBefore is { } before && (!NativeFile.TryGetUsn(handle, out long after) || after != before))
        {
            notes.Add(new(ScanNoteLevel.Warning,
                $"{item.Path}: the file changed during the scan (it was open for writing by another program); not scanned."));
            return report with
            {
                Result = ScanResult.NotScanned(item, ScanStatus.Error, Now),
                Notes = notes.AsReadOnly(),
            };
        }

        return report;
    }

    private readonly record struct OpenedFile(SafeFileHandle? Handle, SecureOpenFailure Failure, long? UsnBefore);

    /// <summary>Opens denying writers; if a writer has it open, a shared handle plus a USN baseline.</summary>
    private static OpenedFile Open(string path, List<ScanNote> notes)
    {
        var handle = SecureFile.OpenRegularFile(path, out var failure, out _, denyWriters: true);
        if (handle is not null || failure.Reason != HashFailureReason.Locked)
        {
            return new(handle, failure, null);
        }

        handle = SecureFile.OpenRegularFile(path, out failure, out _, denyWriters: false);
        if (handle is null)
        {
            return new(null, failure, null);
        }

        if (!NativeFile.TryGetUsn(handle, out long usn))
        {
            handle.Dispose();
            return new(null, new SecureOpenFailure(HashFailureReason.Locked,
                "The file is open for writing by another program and the volume has no change journal to detect changes."), null);
        }

        notes.Add(new(ScanNoteLevel.Information, $"{path} is open for writing by another program; scanned with a change-journal check."));
        return new(handle, default, usn);
    }

    private async Task<FileScanReport> ScanOpenAsync(ScanItem item, SafeFileHandle handle, List<ScanNote> notes, CancellationToken cancellationToken)
    {
        string path = item.Path;

        // 1. Hash.
        var hash = await _hasher.HashHandleAsync(handle, cancellationToken).ConfigureAwait(false);
        if (!hash.IsHashed)
        {
            return NotHashed(item, hash, notes, handle, cancellationToken);
        }

        string sha256 = hash.Sha256;

        // 2. Blocklist (Malicious even if signed), 3. Signature.
        bool blocklisted = _blocklist().TryMatch(sha256, out var blocklistDetection);
        cancellationToken.ThrowIfCancellationRequested();
        var signature = _signatures.Verify(handle, path, cancellationToken);
        if (!signature.IsChecked)
        {
            notes.Add(new(ScanNoteLevel.Information,
                $"Signature not checked ({signature.NotCheckedReason}): {signature.Message}; treated as unsigned."));
        }

        var signatureStatus = signature.Status;
        var signer = signature.TrustedSignerName;

        if (blocklisted)
        {
            notes.Add(new(ScanNoteLevel.Warning, $"{path}: SHA-256 {sha256} is in the local blocklist" +
                (signature.IsTrusted ? $" (signed by {signer}; a blocklist hit wins over the signature)." : ".")));
            return Report(new ScanResult(item, [blocklistDetection!], Now, sha256, ScanStatus.Scanned, signatureStatus, signer),
                hash, signature, null, null, null, notes);
        }

        if (signatureStatus == SignatureStatus.Microsoft)
        {
            return Report(ScanResult.Clean(item, Now, sha256, signatureStatus, signer), hash, signature, null, null, null, notes);
        }

        // 4. YARA.
        cancellationToken.ThrowIfCancellationRequested();
        var yara = _yara.ScanHandle(handle, cancellationToken);
        if (yara.IsScanned && yara.Length != hash.Length)
        {
            notes.Add(new(ScanNoteLevel.Warning,
                $"{path}: the file changed between hashing ({hash.Length} bytes) and the YARA scan ({yara.Length} bytes); not scanned."));
            return Report(ScanResult.NotScanned(item, ScanStatus.Error, Now, sha256), hash, signature, yara, null, null, notes);
        }

        // 5. Mark-of-the-Web, then heuristics.
        cancellationToken.ThrowIfCancellationRequested();
        var motw = _motw.Read(handle, cancellationToken);
        var heuristics = _heuristics.Analyze(handle, path, new HeuristicContext(signature, motw.Mark), cancellationToken);

        var detections = new List<Detection>(yara.Detections);
        if (heuristics.Detection is { } heuristicDetection)
        {
            detections.Add(heuristicDetection);
        }

        if (!yara.IsScanned)
        {
            string why = $"YARA could not scan {path} ({yara.FailureReason}): {yara.ErrorMessage}";
            if (detections.Count == 0)
            {
                notes.Add(new(ScanNoteLevel.Warning, why + "; not scanned."));
                return Report(yara.ToNotScannedResult(item, Now, sha256), hash, signature, yara, motw, heuristics, notes);
            }

            notes.Add(new(ScanNoteLevel.Warning, why + "; the verdict uses the other steps."));
        }

        // 6. Online lookup (D2 seam): never for trusted-signed files.
        if (_online is not null && !signature.IsTrusted)
        {
            var local = detections.Count == 0 ? Verdict.Clean : detections.Max(d => d.Verdict);
            var online = await _online.LookupAsync(new OnlineLookupRequest(item, sha256, signatureStatus, local), cancellationToken)
                .ConfigureAwait(false);
            if (online is not null)
            {
                detections.Add(online);
            }
        }

        // 7. Verdict.
        var result = new ScanResult(item, detections, Now, sha256, ScanStatus.Scanned, signatureStatus, signer);
        return Report(result, hash, signature, yara, motw, heuristics, notes);
    }

    private FileScanReport NotHashed(ScanItem item, HashResult hash, List<ScanNote> notes, SafeFileHandle? handle, CancellationToken cancellationToken)
    {
        string path = item.Path;
        switch (hash.FailureReason)
        {
            case HashFailureReason.TooLarge when handle is not null:
                notes.Add(new(ScanNoteLevel.Warning,
                    $"Skipped (too large): {path} is {hash.Length} bytes, over the {_hasher.MaxSizeBytes}-byte limit. " +
                    "Not hashed and not YARA-scanned; only the name and padding heuristics ran."));

                // Carried over from the A2 review: padding a file past the limit must not make it invisible.
                var heuristics = _heuristics.Analyze(handle, path, HeuristicContext.None, cancellationToken);
                if (heuristics.Detection is { } detection)
                {
                    return Report(new ScanResult(item, [detection], Now), hash, null, null, null, heuristics, notes);
                }

                return Report(hash.ToNotScannedResult(item, Now), hash, null, null, null, heuristics, notes);

            case HashFailureReason.Offline:
                notes.Add(new(ScanNoteLevel.Warning,
                    $"Skipped (offline): {path} is an offline or cloud-only file; it was not downloaded to scan it."));
                break;

            default:
                notes.Add(new(ScanNoteLevel.Warning, $"Not scanned ({hash.FailureReason}): {path}: {hash.ErrorMessage}"));
                break;
        }

        return Report(hash.ToNotScannedResult(item, Now), hash, null, null, null, null, notes);
    }

    private DateTimeOffset Now => _time.GetUtcNow();

    private static FileScanReport Report(
        ScanResult result, HashResult hash, SignatureCheckResult? signature, YaraScanResult? yara,
        MarkOfTheWebResult? motw, HeuristicResult? heuristics, List<ScanNote> notes) =>
        new(result, hash, signature, yara, motw, heuristics, notes.AsReadOnly());
}
