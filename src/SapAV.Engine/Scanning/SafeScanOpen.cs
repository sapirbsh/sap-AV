using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning;

/// <summary>
/// The scan open for jobs a standard user requested (review B4 M2): like <see cref="ScanFileOpener.Open"/>, but the file
/// is reached through <see cref="SafeTree"/> (component by component, no reparse point followed, name surrogates refused),
/// never with a following path open, so a symlink swapped in on the way can't make SYSTEM open a remote path. The file is
/// opened for read with writers denied (Read | Delete sharing); if a writer has it open, it is opened shared with a
/// change-journal baseline, as the normal opener does. The handle then passes <see cref="SecureFile.Validate"/>.
/// </summary>
internal static class SafeScanOpen
{
    private const uint ShareNoWriters = N.ShareRead | N.ShareDelete;

    public static OpenedScanFile? Open(ScanItem item, List<ScanNote> notes, TimeProvider time, out FileScanReport? failureReport)
    {
        uint options = N.FileNonDirectoryFile | SafeTree.OpenNoRecall;
        var handle = SafeTree.Open(item.Path, N.GenericRead, ShareNoWriters, options, out var failure, out int error);
        long? usn = null;
        if (handle is null && failure == SafeTreeFailure.Locked)
        {
            handle = SafeTree.Open(item.Path, N.GenericRead, SafeTree.ShareAll, options, out failure, out error);
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
