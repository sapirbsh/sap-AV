using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Persistence.Remediation;

internal sealed partial class PersistenceRemediator
{
    /// <summary>Access the quarantine needs on the handle it is given (read, DELETE, WRITE_DAC; writers denied).</summary>
    private const uint QuarantineAccess = N.GenericRead | N.Delete | N.WriteDac;

    /// <summary>
    /// A Startup folder item (shortcut, exe, script): moved into the quarantine (reversible, B2), never deleted. The file is
    /// found by its exact name in the folder (listed without following links; a link in the folder is refused), opened with the
    /// hardened no-reparse open, and handed to the quarantine on that handle, bound to its file ID and SHA-256. A standard user
    /// needs DELETE on the file (or DELETE_CHILD on the folder) themselves: a user's Startup folder can be redirected anywhere.
    /// </summary>
    private RemediationResult BlockStartupItem(BlockContext context)
    {
        var entry = context.Entry;
        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return new(RemediationStatus.Unavailable, "The quarantine is not available, so the Startup item can't be moved.");
        }

        if (entry.ValueName is null || entry.Location.Contains('�') || PersistenceText.NormalizeLocalPath(entry.Location) is not { } folder
            || !string.Equals(folder, entry.Location, StringComparison.OrdinalIgnoreCase))
        {
            return NotAddressable();
        }

        if (ResolveFileName(folder, entry.ValueName, out var name) is { } unresolved)
        {
            return unresolved;
        }

        string path = SafeTree.Child(folder, name);
        using var file = SafeFile.TryOpen(path, QuarantineAccess, N.ShareRead | N.ShareDelete, out var directory, out var failure, out int error, out var reason);
        using (directory)
        {
            if (file is null)
            {
                return failure switch
                {
                    SafeDirectoryFailure.NotFound => Changed(),
                    SafeDirectoryFailure.Redirected or SafeDirectoryFailure.PathMismatch => new(RemediationStatus.Redirected, "A link is on the Startup item's path; not followed."),
                    _ when error is N.ErrorSharingViolation or N.ErrorLockViolation => new(RemediationStatus.Failed, "The Startup item is in use; close the program and try again."),
                    _ => new(RemediationStatus.Failed, $"The Startup item can't be opened: {reason}"),
                };
            }

            var identity = FileIdentity.TryCapture(file);
            if (identity is null)
            {
                return new(RemediationStatus.Failed, "The Startup item's identity can't be read.");
            }

            if (!context.Client.IsAdmin && !ClientMayDelete(context.Client, path, identity))
            {
                return new(RemediationStatus.AccessDenied, "You may not delete this file yourself, so you can't move it into quarantine; ask an administrator.");
            }

            var (sha256, length) = StoredContent.Hash(file, context.Cancellation);
            var report = StartupReport(path, sha256, length, identity, context.Now);
            var requester = context.Client.IsAdmin ? null : new QuarantineRequester(context.Client.User);
            var moved = quarantine.QuarantineHandleAsync(file, report, null, context.Cancellation, requester).GetAwaiter().GetResult();
            if (moved.Status != QuarantineStatus.Quarantined || moved.Entry is not { } item)
            {
                return new(moved.Status == QuarantineStatus.QuotaExceeded ? RemediationStatus.QuotaExceeded : RemediationStatus.Failed,
                    $"The Startup item couldn't be moved into quarantine ({moved.Status}): {moved.Reason}");
            }

            var record = context.NewRecord(PersistenceBackupAction.FileQuarantined) with { QuarantineItemId = item.Id, OriginalPath = path };
            if (SaveFirst(context, record) is not null)
            {
                // The quarantine item is the backup itself: the file can still be restored from the quarantine screen.
                _logger.LogError("Block & remove: Startup item {Path} is in quarantine as item {Item}, but its backup record couldn't be written.", path, item.Id);
                return new(RemediationStatus.Blocked, $"The Startup item was moved into quarantine (item {item.Id}); restore it from the quarantine screen.", record);
            }

            return new(RemediationStatus.Blocked, $"The Startup item was moved into quarantine (item {item.Id}). It was not deleted.", record);
        }
    }

    /// <summary>
    /// Puts the item back at its original path from the quarantine. Refused when a file holds that name now (nothing is
    /// overwritten, and the quarantine's "(restored N)" names aren't used: a Startup item must be back under its own name).
    /// </summary>
    private RemediationResult RestoreStartupItem(PersistenceBackupRecord record, IClientIdentity client, CancellationToken ct)
    {
        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return new(RemediationStatus.Unavailable, "The quarantine is not available.");
        }

        // Review M2: the quarantine's own rule for who may see (and so restore) an item: an administrator, or a user who could
        // read the original file (its recorded descriptor).
        if (quarantine.Get(record.QuarantineItemId!) is not { Integrity: QuarantineEntryIntegrity.Valid } item)
        {
            return new(RemediationStatus.InvalidBackup, "The quarantine item is gone or invalid (it was restored or deleted from the quarantine screen).");
        }

        if (!client.IsAdmin && !ClientAccess.IsGrantedByStoredDescriptor(client, item.OriginalSecurityDescriptor, Pipe.Native.PipeNative.FileReadData))
        {
            return new(RemediationStatus.AccessDenied, "You may not restore this quarantine item; ask an administrator.");
        }

        string path = record.OriginalPath!;
        using (var existing = ClientAccess.OpenForCheck(path, out var found))
        {
            if (existing is not null || found is AccessDecision.Redirected)
            {
                return found is AccessDecision.Redirected
                    ? new(RemediationStatus.Redirected, "A link is on the Startup item's path now; not followed.")
                    : new(RemediationStatus.LocationChanged, "A file with that name is in the Startup folder now; nothing was overwritten.");
            }
        }

        if (!client.IsAdmin && ClientAccess.CanAddFileNextTo(client, path) != AccessDecision.Granted)
        {
            return new(RemediationStatus.AccessDenied, "You may not create files in that folder; ask an administrator to restore it.");
        }

        var restored = quarantine.RestoreAsync(record.QuarantineItemId!, ct, client.User).GetAwaiter().GetResult();
        return restored.Status switch
        {
            RestoreStatus.Restored when string.Equals(restored.RestoredPath, path, StringComparison.OrdinalIgnoreCase) =>
                new(RemediationStatus.Restored, "The Startup item was put back from quarantine."),
            RestoreStatus.Restored => new(RemediationStatus.Restored,
                $"The Startup item was put back from quarantine as {restored.RestoredPath} (a file took its name meanwhile)."),
            RestoreStatus.TargetExists => new(RemediationStatus.LocationChanged, "A file with that name is in the Startup folder now; nothing was overwritten."),
            RestoreStatus.TargetDirectoryMissing => new(RemediationStatus.LocationMissing, "The Startup folder doesn't exist any more."),
            RestoreStatus.TargetRedirected => new(RemediationStatus.Redirected, "A link is on the Startup folder's path now; not followed."),
            RestoreStatus.NotFound => new(RemediationStatus.InvalidBackup, "The quarantine item is gone (it was restored or deleted from the quarantine screen)."),
            _ => new(RemediationStatus.Failed, $"The quarantine couldn't restore it ({restored.Status}): {restored.Reason}"),
        };
    }

    /// <summary>The one item in the folder whose (sanitised) name is the entry's; a link (name surrogate) or a folder is refused.</summary>
    private static RemediationResult? ResolveFileName(string folder, string shown, out string name)
    {
        name = string.Empty;
        using var handle = SafeFolderReader.OpenFolder(folder, out var failure);
        if (handle is null)
        {
            return failure == PersistenceIssueReason.LinkNotFollowed
                ? new(RemediationStatus.Redirected, "The Startup folder is reached through a link; not followed.")
                : Changed();
        }

        List<SafeTreeEntry> items;
        try
        {
            items = SafeTree.List(handle, StartupFolderSource.MaxItems, out _);
        }
        catch (IOException)
        {
            return new(RemediationStatus.Failed, "The Startup folder can't be listed.");
        }

        var matches = items.Where(i => PersistenceText.Identifier(i.Name, PersistenceEntry.MaxValueNameLength) == shown).Take(2).ToArray();
        if (matches.Length != 1)
        {
            return matches.Length == 0 ? Changed() : new(RemediationStatus.NotSupported, "Several items in the Startup folder look the same; move them yourself.");
        }

        if (matches[0].IsNameSurrogate || matches[0].IsDirectory)
        {
            return new(RemediationStatus.Redirected, "The Startup item is a link or a folder; it isn't followed or moved.");
        }

        name = matches[0].Name;
        return null;
    }

    /// <summary>The client could delete this exact file (DELETE on it, or DELETE_CHILD on its folder).</summary>
    private static bool ClientMayDelete(IClientIdentity client, string path, FileIdentity identity) =>
        ClientAccess.Check(client, path, Pipe.Native.PipeNative.Delete, identity) == AccessDecision.Granted
        || (ClientAccess.ParentOf(path) is { } parent && ClientAccess.Check(client, parent, Pipe.Native.PipeNative.FileDeleteChild) == AccessDecision.Granted);

    /// <summary>The quarantine's input: this exact file (identity, hash), "Suspicious" because the user chose to block it.</summary>
    private static FileScanReport StartupReport(string path, string sha256, long length, FileIdentity identity, DateTimeOffset now)
    {
        var detection = new Detection(Verdict.Suspicious, "Blocked by the user: Block & remove of a Startup folder item.",
            MitreTechniqueIds.RegistryRunKeysStartupFolder, DetectionSource.Persistence, []);
        var result = new ScanResult(new ScanItem(path, ScanTrigger.Persistence), [detection], now, sha256);
        return new FileScanReport(result, HashResult.Hashed(sha256, length), null, null, null, null, []) { Identity = identity };
    }
}
