using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning;

/// <summary>
/// The engine's scan open for <b>every</b> job and the broker's own path scans (review B4 M2, review B H2): like
/// <see cref="ScanFileOpener.Open"/>, but never a following path open. A file the walker listed is opened relative to the
/// listed folder's handle (<see cref="SharedFolder"/>); any other path is reached through <see cref="SafeTree"/> (component
/// by component, no reparse point followed, name surrogates refused). Either way a link or a renamed / replaced parent
/// folder can't make SYSTEM open another local object or a remote path. The file is opened for read with writers denied
/// (Read | Delete sharing); if a writer has it open, it is opened shared with a change-journal baseline, as the normal
/// opener does. The handle then passes <see cref="SecureFile.Validate"/>.
/// </summary>
internal static class SafeScanOpen
{
    private const uint ShareNoWriters = N.ShareRead | N.ShareDelete;

    /// <param name="folder">The folder <paramref name="name"/> was listed in (the caller keeps its reference), or null to open by path.</param>
    public static OpenedScanFile? Open(
        ScanItem item, List<ScanNote> notes, TimeProvider time, out FileScanReport? failureReport, SharedFolder? folder = null, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (folder is not null && string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("A folder-relative open needs the file name.", nameof(name));
        }

        uint options = N.FileNonDirectoryFile | SafeTree.OpenNoRecall;
        var handle = OpenOnce(item, folder, name, ShareNoWriters, options, out var failure, out int error);
        long? usn = null;
        if (handle is null && failure == SafeTreeFailure.Locked)
        {
            handle = OpenOnce(item, folder, name, SafeTree.ShareAll, options, out failure, out error);
            if (handle is not null)
            {
                if (NativeFile.TryGetUsn(handle, out long baseline))
                {
                    notes.Add(new(ScanNoteLevel.Information, $"{item.Path} is open for writing by another program; scanned with a change-journal check."));
                    usn = baseline;
                }
                else
                {
                    handle.Dispose();
                    handle = null;
                    failure = SafeTreeFailure.Locked;
                }
            }
        }

        if (handle is null)
        {
            failureReport = Failed(item, notes, time, Reason(failure), $"The file could not be opened safely ({failure}, Win32 error {error}).");
            return null;
        }

        if (!SecureFile.Validate(handle, out var invalid, out _))
        {
            handle.Dispose();
            failureReport = Failed(item, notes, time, invalid.Reason, invalid.Message, invalid.Length, invalid.LastWriteTimeUtc, invalid.Attributes);
            return null;
        }

        failureReport = null;
        return new OpenedScanFile(handle, usn);
    }

    private static SafeFileHandle? OpenOnce(
        ScanItem item, SharedFolder? folder, string? name, uint share, uint options, out SafeTreeFailure failure, out int error) =>
        folder is null
            ? SafeTree.Open(item.Path, N.GenericRead, share, options, out failure, out error)
            : SafeTree.OpenChild(folder.Handle, name!, N.GenericRead, share, options, out failure, out error);

    private static HashFailureReason Reason(SafeTreeFailure failure) => failure switch
    {
        SafeTreeFailure.NotFound => HashFailureReason.NotFound,
        SafeTreeFailure.AccessDenied => HashFailureReason.AccessDenied,
        SafeTreeFailure.Locked => HashFailureReason.Locked,
        SafeTreeFailure.Redirected or SafeTreeFailure.Unsupported => HashFailureReason.NotRegularFile,
        _ => HashFailureReason.IoError,
    };

    private static FileScanReport Failed(
        ScanItem item, List<ScanNote> notes, TimeProvider time, HashFailureReason reason, string message, long? length = null,
        DateTime? lastWrite = null, FileAttributes? attributes = null) =>
        ScanFileOpener.NotOpenedReport(item, HashResult.NotHashed(reason, message, length, lastWrite, attributes), notes, time.GetUtcNow());
}
