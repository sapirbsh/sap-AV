using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Models;

namespace SapAV.Core.Scanning;

/// <summary>
/// A file opened for the scan pipeline by <see cref="ScanFileOpener"/>: the one handle every step reads, the identity
/// of the file object behind it, and (for the shared fallback) the change-journal USN to compare after the scan.
/// </summary>
/// <remarks>Owns the handle; dispose it when the scan is over.</remarks>
public sealed class OpenedScanFile : IDisposable
{
    internal OpenedScanFile(SafeFileHandle handle, long? usnBefore)
    {
        Handle = handle;
        UsnBefore = usnBefore;
        Identity = FileIdentity.TryCapture(handle);
    }

    /// <summary>The synchronous, read-only scan handle (GENERIC_READ, writers denied unless <see cref="UsnBefore"/> is set).</summary>
    public SafeFileHandle Handle { get; }

    /// <summary>
    /// Set when a writer already had the file open, so it was opened shared: the USN before the scan. The pipeline
    /// result is valid only if the USN is unchanged afterwards (<see cref="ScanFileOpener.VerifyUnchanged"/>).
    /// </summary>
    public long? UsnBefore { get; }

    /// <summary>Which file object this is (B2: the quarantine acts only on this object), from this handle.</summary>
    public FileIdentity? Identity { get; }

    public void Dispose() => Handle.Dispose();
}

/// <summary>
/// The scan pipeline's open, shared by the in-process <see cref="FileScanner"/> and the engine's scan broker (B5),
/// which opens the file here and hands a read-only duplicate of the handle to the sandboxed worker.
/// </summary>
/// <remarks>
/// The hardened open (<see cref="SecureFile"/>) with share Read | Delete, so nobody can open the file for writing
/// during the scan. If a writer already has it open (sharing violation), the file is opened shared and its
/// change-journal USN recorded, so a change during the scan can be detected; without a change journal it is Locked.
/// Opening reads no file content: only the handle's type and attributes are checked.
/// </remarks>
public static class ScanFileOpener
{
    /// <summary>
    /// Opens <paramref name="item"/>'s path. On failure returns null and the finished not-scanned report in
    /// <paramref name="failureReport"/> (never Clean). Notes about the open are added to <paramref name="notes"/>.
    /// </summary>
    public static OpenedScanFile? Open(ScanItem item, List<ScanNote> notes, TimeProvider time, out FileScanReport? failureReport)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(notes);
        ArgumentNullException.ThrowIfNull(time);

        var handle = SecureFile.OpenRegularFile(item.Path, out var failure, out _, denyWriters: true);
        if (handle is not null)
        {
            failureReport = null;
            return new OpenedScanFile(handle, null);
        }

        long? usn = null;
        if (failure.Reason == HashFailureReason.Locked)
        {
            handle = SecureFile.OpenRegularFile(item.Path, out failure, out _, denyWriters: false);
            if (handle is not null)
            {
                if (NativeFile.TryGetUsn(handle, out long baseline))
                {
                    notes.Add(new(ScanNoteLevel.Information,
                        $"{item.Path} is open for writing by another program; scanned with a change-journal check."));
                    usn = baseline;
                }
                else
                {
                    handle.Dispose();
                    handle = null;
                    failure = new SecureOpenFailure(HashFailureReason.Locked,
                        "The file is open for writing by another program and the volume has no change journal to detect changes.");
                }
            }
        }

        if (handle is not null)
        {
            failureReport = null;
            return new OpenedScanFile(handle, usn);
        }

        var hash = HashResult.NotHashed(failure.Reason, failure.Message, failure.Length, failure.LastWriteTimeUtc, failure.Attributes);
        failureReport = NotOpenedReport(item, hash, notes, time.GetUtcNow());
        return null;
    }

    /// <summary>
    /// The shared-fallback check after the pipeline: if the file was opened shared (<see cref="OpenedScanFile.UsnBefore"/>)
    /// and its USN changed (or can't be read), the report becomes NotScanned (Error). Otherwise it is returned as is.
    /// </summary>
    public static FileScanReport VerifyUnchanged(OpenedScanFile file, FileScanReport report, List<ScanNote> notes, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(notes);
        ArgumentNullException.ThrowIfNull(time);

        if (file.UsnBefore is not { } before || (NativeFile.TryGetUsn(file.Handle, out long after) && after == before))
        {
            return report;
        }

        var item = report.Result.Item;
        notes.Add(new(ScanNoteLevel.Warning,
            $"{item.Path}: the file changed during the scan (it was open for writing by another program); not scanned."));
        return report with
        {
            Result = ScanResult.NotScanned(item, ScanStatus.Error, time.GetUtcNow()),
            Notes = notes.AsReadOnly(),
        };
    }

    /// <summary>The report for a file that could not be opened: NotScanned with the open failure's status.</summary>
    internal static FileScanReport NotOpenedReport(ScanItem item, HashResult hash, List<ScanNote> notes, DateTimeOffset now)
    {
        notes.Add(hash.FailureReason == HashFailureReason.Offline
            ? new(ScanNoteLevel.Warning, $"Skipped (offline): {item.Path} is an offline or cloud-only file; it was not downloaded to scan it.")
            : new(ScanNoteLevel.Warning, $"Not scanned ({hash.FailureReason}): {item.Path}: {hash.ErrorMessage}"));
        return new FileScanReport(hash.ToNotScannedResult(item, now), hash, null, null, null, null, notes.AsReadOnly());
    }
}
