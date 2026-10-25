using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning;

/// <summary>What a scan open checks besides the hardened open itself (C1).</summary>
/// <param name="Access">The requester's access (standard-user jobs), checked <b>first</b>; null = no check.</param>
/// <param name="AllowRemote">A2 W-A: accept a file on a remote file system (administrator opt-in; default off).</param>
/// <param name="Remote">Classifies the opened handle (fake in tests).</param>
internal sealed record ScanOpenChecks(IScanAccessCheck? Access = null, bool AllowRemote = false, IRemoteFileProbe? Remote = null)
{
    public static ScanOpenChecks None { get; } = new();

    public IRemoteFileProbe RemoteProbe => Remote ?? RemoteFileProbe.Instance;
}

/// <summary>
/// The engine's scan open for <b>every</b> job and the broker's own path scans (review B4 M2, review B H2): like
/// <see cref="ScanFileOpener.Open"/>, but never a following path open. A file the walker listed is opened relative to the
/// listed folder's handle (<see cref="SharedFolder"/>); any other path is reached through <see cref="SafeTree"/> (component
/// by component, no reparse point followed, name surrogates refused). Either way a link or a renamed / replaced parent
/// folder can't make SYSTEM open another local object or a remote path. The file is opened for read with writers denied
/// (Read | Delete sharing); if a writer has it open, it is opened shared with a change-journal baseline, as the normal
/// opener does. Then, in this order (C1):
/// <list type="number">
/// <item><b>The requester's read access</b> (B4 L3), when the job has one: before anything about the file is looked at, so
/// a user who can't read it learns nothing (not locked, too large, offline, remote...). If the open itself failed, an
/// attributes-only open answers the access question; if even that fails, or the user can't read the file, the result is
/// the generic <see cref="ScanSkipReason.NoAccess"/>.</item>
/// <item><b>Remote or not</b> (A2 W-A, <see cref="RemoteFileProbe"/>): a remote file is refused unless the job allows it.</item>
/// <item><see cref="SecureFile.Validate"/> (regular disk file, size limit, offline placeholders).</item>
/// </list>
/// </summary>
internal static class SafeScanOpen
{
    private const uint ShareNoWriters = N.ShareRead | N.ShareDelete;

    /// <param name="folder">The folder <paramref name="name"/> was listed in (the caller keeps its reference), or null to open by path.</param>
    public static OpenedScanFile? Open(
        ScanItem item, List<ScanNote> notes, TimeProvider time, out FileScanReport? failureReport, SharedFolder? folder = null, string? name = null) =>
        Open(item, notes, time, out failureReport, out _, ScanOpenChecks.None, folder, name);

    /// <param name="skipReason">Why it wasn't opened (null when it was).</param>
    public static OpenedScanFile? Open(
        ScanItem item, List<ScanNote> notes, TimeProvider time, out FileScanReport? failureReport, out ScanSkipReason? skipReason,
        ScanOpenChecks checks, SharedFolder? folder = null, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(checks);
        if (folder is not null && string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("A folder-relative open needs the file name.", nameof(name));
        }

        uint options = N.FileNonDirectoryFile | SafeTree.OpenNoRecall;
        var handle = OpenOnce(item, folder, name, ShareNoWriters, options, checks.AllowRemote, out var failure, out int error);
        long? usn = null;
        if (handle is null && failure == SafeTreeFailure.Locked)
        {
            handle = OpenOnce(item, folder, name, SafeTree.ShareAll, options, checks.AllowRemote, out failure, out error);
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
            if (checks.Access is { } access && !RequesterCanRead(item, folder, name, access, checks.AllowRemote))
            {
                return NoAccess(item, notes, time, out failureReport, out skipReason);
            }

            skipReason = failure == SafeTreeFailure.Remote ? ScanSkipReason.RemoteFile : null;
            failureReport = Failed(item, notes, time, Reason(failure), failure == SafeTreeFailure.Remote
                ? "The file is on a remote file system; remote files are not scanned."
                : $"The file could not be opened safely ({failure}, Win32 error {error}).");
            return null;
        }

        if (checks.Access is { } requester && !requester.CanRead(handle))
        {
            handle.Dispose();
            return NoAccess(item, notes, time, out failureReport, out skipReason);
        }

        if (!checks.AllowRemote && checks.RemoteProbe.Classify(handle) != FileLocation.Local)
        {
            // Defense in depth (see RemoteFileProbe): the open can't have authenticated anywhere it shouldn't, but whatever
            // turns out remote is never judged as a local file.
            handle.Dispose();
            skipReason = ScanSkipReason.RemoteFile;
            failureReport = Failed(item, notes, time, HashFailureReason.NotRegularFile, "The file is on a remote file system; remote files are not scanned.");
            return null;
        }

        if (!SecureFile.Validate(handle, out var invalid, out _))
        {
            handle.Dispose();
            skipReason = null;
            failureReport = Failed(item, notes, time, invalid.Reason, invalid.Message, invalid.Length, invalid.LastWriteTimeUtc, invalid.Attributes);
            return null;
        }

        skipReason = null;
        failureReport = null;
        return new OpenedScanFile(handle, usn);
    }

    /// <summary>
    /// B4 L3: after a failed open, may the requester read the object at all? Answered from an attributes-only open (never
    /// recalls, never follows links); false when even that fails, so the failure's details stay hidden.
    /// </summary>
    private static bool RequesterCanRead(ScanItem item, SharedFolder? folder, string? name, IScanAccessCheck access, bool allowRemote)
    {
        using var inspect = folder is null
            ? SafeTree.Open(item.Path, SafeTree.InspectAccess, SafeTree.ShareAll, SafeTree.OpenNoRecall, out _, out _, allowRemote)
            : SafeTree.OpenChild(folder.Handle, name!, SafeTree.InspectAccess, SafeTree.ShareAll, SafeTree.OpenNoRecall, out _, out _);
        return inspect is not null && access.CanRead(inspect);
    }

    /// <summary>The generic result for a file the requester can't read: AccessDenied, no hash, no reason beyond that.</summary>
    private static OpenedScanFile? NoAccess(
        ScanItem item, List<ScanNote> notes, TimeProvider time, out FileScanReport? failureReport, out ScanSkipReason? skipReason)
    {
        skipReason = ScanSkipReason.NoAccess;
        failureReport = Failed(item, notes, time, HashFailureReason.AccessDenied, "The user who requested the scan can't read this file.");
        return null;
    }

    private static SafeFileHandle? OpenOnce(
        ScanItem item, SharedFolder? folder, string? name, uint share, uint options, bool allowRemote, out SafeTreeFailure failure, out int error) =>
        folder is null
            ? SafeTree.Open(item.Path, N.GenericRead, share, options, out failure, out error, allowRemote)
            : SafeTree.OpenChild(folder.Handle, name!, N.GenericRead, share, options, out failure, out error);

    private static HashFailureReason Reason(SafeTreeFailure failure) => failure switch
    {
        SafeTreeFailure.NotFound => HashFailureReason.NotFound,
        SafeTreeFailure.AccessDenied => HashFailureReason.AccessDenied,
        SafeTreeFailure.Locked => HashFailureReason.Locked,
        SafeTreeFailure.Redirected or SafeTreeFailure.Unsupported or SafeTreeFailure.Remote => HashFailureReason.NotRegularFile,
        _ => HashFailureReason.IoError,
    };

    private static FileScanReport Failed(
        ScanItem item, List<ScanNote> notes, TimeProvider time, HashFailureReason reason, string message, long? length = null,
        DateTime? lastWrite = null, FileAttributes? attributes = null) =>
        ScanFileOpener.NotOpenedReport(item, HashResult.NotHashed(reason, message, length, lastWrite, attributes), notes, time.GetUtcNow());
}
