using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Alerts;
using SapAV.Core.Motw;
using SapAV.Core.Quarantine;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

public sealed partial class QuarantineManager
{
    /// <summary>Attributes put back on a restored file; everything else (compressed, sparse, reparse, ...) is not settable.</summary>
    private const FileAttributes RestorableAttributes = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System
        | FileAttributes.Archive | FileAttributes.Temporary | FileAttributes.NotContentIndexed;

    private const uint CreateAccess = N.GenericRead | N.GenericWrite | N.Delete | N.ReadControl | N.WriteDac;

    /// <inheritdoc/>
    /// <remarks>
    /// <para>The target is <b>only</b> the original path from the HMAC-verified metadata. Its folder is opened with
    /// <see cref="SafeDirectory"/> (no reparse point anywhere in the chain, final path checked), and the file is created
    /// <b>relative to that folder handle</b> under a random temp name with FILE_CREATE (never overwrites), filled and
    /// verified, then renamed (no replace) to the original name, or <c>name (restored N).ext</c> (N = 1..99) if that is
    /// taken. If every name is taken the restore fails with <see cref="RestoreStatus.TargetExists"/>.</para>
    /// <para>Restored: content, attributes, creation/last-write/last-access times, the DACL (explicit entries, or the
    /// whole protected DACL), the owner when the engine is allowed to set it, and the Zone.Identifier stream.</para>
    /// </remarks>
    public Task<RestoreResult> RestoreAsync(string itemId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!QuarantineItemId.IsValid(itemId))
        {
            return Task.FromResult(new RestoreResult(RestoreStatus.NotFound, "Invalid item ID."));
        }

        if (!TryGetStore(out var store, out var key))
        {
            return Task.FromResult(new RestoreResult(RestoreStatus.StoreUnavailable, "The quarantine store is not available."));
        }

        return Task.Run(() => RestoreLockedAsync(store, key, itemId), CancellationToken.None);
    }

    private async Task<RestoreResult> RestoreLockedAsync(QuarantineStore store, byte[] key, string id)
    {
        RestoreResult result;
        QuarantineMetadata? metadata;
        using (var lease = _locks.TryAcquire("item:" + id))
        {
            if (lease is null)
            {
                return new(RestoreStatus.Busy, "Another operation on this item is running.");
            }

            (result, metadata) = RestoreCore(store, key, id);
        }

        if (result.Status != RestoreStatus.Restored)
        {
            _logger.LogWarning("Restore of quarantine item {Id} failed ({Status}): {Reason}", id, result.Status, result.Reason);
            return result;
        }

        _logger.LogInformation("Restored quarantine item {Id} to {Path}.", id, result.RestoredPath);
        await EmitRestoredAlertAsync(metadata!, result.RestoredPath!).ConfigureAwait(false);
        return result;
    }

    private (RestoreResult, QuarantineMetadata?) RestoreCore(QuarantineStore store, byte[] key, string id)
    {
        if (!TryLoadForRestore(store, key, id, out var metadata, out var refusal))
        {
            return (refusal, null);
        }

        string directoryPath = Path.GetDirectoryName(metadata.OriginalPath)!;
        using var directory = SafeDirectory.TryOpen(directoryPath, out var failure, out var why);
        if (directory is null)
        {
            return (new(MapDirectoryFailure(failure), why), null);
        }

        var restoring = metadata with { State = QuarantineState.Restoring, RestoreTempName = QuarantinePath.NewRestoreTempName() };
        try
        {
            store.WriteMetadata(restoring, key);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            return (new(RestoreStatus.Failed, $"Can't write the quarantine journal: {ex.Message}"), null);
        }

        Hook(QuarantineStep.RestoreJournalWritten);
        var written = WriteTarget(store, directory, restoring, out var notes);
        if (written.Status != RestoreStatus.Restored)
        {
            Revert(store, key, metadata);
            return (written, null);
        }

        string restoredPath = Path.Combine(directoryPath, written.RestoredPath!);
        RemoveEntry(store, key, metadata);
        return (new(RestoreStatus.Restored, "Restored.", restoredPath, notes), metadata);
    }

    private bool TryLoadForRestore(QuarantineStore store, byte[] key, string id, out QuarantineMetadata metadata, out RestoreResult refusal)
    {
        metadata = null!;
        try
        {
            metadata = store.ReadMetadata(id, key);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            refusal = new(RestoreStatus.NotFound, "No such quarantine item.");
            return false;
        }
        catch (QuarantineMetadataException ex)
        {
            refusal = new(RestoreStatus.MetadataInvalid, $"The item's metadata failed verification ({ex.Error}); refusing to restore it.");
            return false;
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            refusal = new(RestoreStatus.Failed, $"Can't read the item's metadata: {ex.Message}");
            return false;
        }

        if (metadata.State != QuarantineState.Quarantined)
        {
            refusal = new(RestoreStatus.NotRestorable, $"The item is in state {metadata.State}, not Quarantined.");
            return false;
        }

        if (!StoredContent.Verify(store.DataPath(id), metadata.TransformKey, metadata.SizeBytes, metadata.Sha256))
        {
            refusal = new(RestoreStatus.StoredContentInvalid, "The stored copy doesn't match the recorded size and SHA-256.");
            return false;
        }

        refusal = null!;
        return true;
    }

    /// <summary>
    /// Creates the temp file relative to the verified folder, writes and verifies the content, applies metadata, and
    /// renames it to a free name. On success <see cref="RestoreResult.RestoredPath"/> holds the final <b>file name</b>.
    /// On failure the temp file is deleted by handle.
    /// </summary>
    private RestoreResult WriteTarget(QuarantineStore store, SafeFileHandle directory, QuarantineMetadata metadata, out List<string> notes)
    {
        notes = [];
        var target = CreateTemp(directory, metadata.RestoreTempName!, out bool canSetOwner, out int error);
        if (target is null)
        {
            return new(RestoreStatus.Failed, $"Can't create the restored file in the target folder (Win32 error {error}).");
        }

        using (target)
        {
            try
            {
                using (var stored = File.OpenHandle(store.DataPath(metadata.Id), FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    StoredContent.DecodeTo(stored, metadata.TransformKey, target);
                }

                N.Flush(target);
                var (sha, length) = StoredContent.Hash(target);
                if (sha != metadata.Sha256 || length != metadata.SizeBytes)
                {
                    throw new InvalidDataException("The restored content did not verify.");
                }

                ApplyMetadata(target, metadata, canSetOwner, notes);
                Hook(QuarantineStep.RestoreTempWritten);
                string? name = RenameToFreeName(target, directory, Path.GetFileName(metadata.OriginalPath));
                if (name is null)
                {
                    N.TryDeleteByHandle(target, out _);
                    return new(RestoreStatus.TargetExists,
                        $"The original name and every '(restored N)' name up to {QuarantinePath.MaxRestoreSuffix} exist; nothing was overwritten.");
                }

                Hook(QuarantineStep.RestoreRenamed);
                return new(RestoreStatus.Restored, "Restored.", name);
            }
            catch (Exception ex) when (IsIoFailure(ex))
            {
                N.TryDeleteByHandle(target, out _);
                return new(RestoreStatus.Failed, $"Writing the restored file failed: {ex.Message}");
            }
        }
    }

    private static SafeFileHandle? CreateTemp(SafeFileHandle directory, string name, out bool canSetOwner, out int error)
    {
        const uint Options = N.FileNonDirectoryFile | N.FileOpenReparsePoint;
        const uint Attributes = N.ObjCaseInsensitive | N.ObjDontReparse;

        // Share mode 0: nobody else can open the file at all while it is filled and its metadata applied.
        canSetOwner = true;
        var handle = N.OpenRelative(directory, name, CreateAccess | N.WriteOwner, 0, N.FileCreate, Options, out error, Attributes, 0x80);
        if (handle is null && error == N.ErrorAccessDenied)
        {
            canSetOwner = false;
            handle = N.OpenRelative(directory, name, CreateAccess, 0, N.FileCreate, Options, out error, Attributes, 0x80);
        }

        return handle;
    }

    /// <summary>MOTW stream, DACL, owner, then attributes and times last (writes would change the times).</summary>
    private static void ApplyMetadata(SafeFileHandle target, QuarantineMetadata metadata, bool canSetOwner, List<string> notes)
    {
        if (metadata.ZoneIdentifier is { } zone)
        {
            WriteZoneIdentifier(target, zone, notes);
        }

        if (metadata.SecurityDescriptor is { } sddl)
        {
            ApplySecurity(target, sddl, canSetOwner, notes);
        }

        var attributes = (uint)((FileAttributes)metadata.Attributes & RestorableAttributes);
        N.SetBasicInfo(target,
            metadata.CreationTimeUtc.UtcDateTime.ToFileTimeUtc(),
            metadata.LastAccessTimeUtc.UtcDateTime.ToFileTimeUtc(),
            metadata.LastWriteTimeUtc.UtcDateTime.ToFileTimeUtc(),
            attributes == 0 ? (uint)FileAttributes.Normal : attributes);
        N.Flush(target);
    }

    private static void WriteZoneIdentifier(SafeFileHandle target, byte[] zone, List<string> notes)
    {
        // FILE_SHARE_DELETE on the stream: NTFS checks it against our own main-stream handle, which holds DELETE.
        using var stream = N.OpenRelative(target, ":" + MarkOfTheWebReader.StreamName, N.GenericWrite, N.ShareDelete, N.FileCreate,
            N.FileNonDirectoryFile, out int error);
        if (stream is null)
        {
            notes.Add($"The Mark-of-the-Web stream could not be restored (Win32 error {error}).");
            return;
        }

        RandomAccess.Write(stream, zone, 0);
    }

    /// <summary>
    /// A protected original DACL is restored as is. An inheriting one: only its explicit entries are set (unprotected),
    /// so the inherited part comes from the folder as for any new file; with no explicit entries the new file's
    /// inherited DACL is already right and nothing is set. The owner is set only if allowed (SYSTEM needs
    /// SeRestorePrivilege to give a file to another user; it is not enabled, so that becomes a note).
    /// </summary>
    private static void ApplySecurity(SafeFileHandle target, string sddl, bool canSetOwner, List<string> notes)
    {
        RawSecurityDescriptor original;
        try
        {
            original = new RawSecurityDescriptor(sddl);
        }
        catch (ArgumentException)
        {
            notes.Add("The original security descriptor could not be parsed; the folder's default ACL applies.");
            return;
        }

        if (original.DiscretionaryAcl is { } dacl)
        {
            bool isProtected = (original.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
            var explicitAces = new RawAcl(dacl.Revision, dacl.Count);
            foreach (var ace in dacl)
            {
                if (isProtected || (ace.AceFlags & AceFlags.Inherited) == 0)
                {
                    explicitAces.InsertAce(explicitAces.Count, ace);
                }
            }

            if (isProtected || explicitAces.Count > 0)
            {
                var bytes = new byte[explicitAces.BinaryLength];
                explicitAces.GetBinaryForm(bytes, 0);
                uint info = N.DaclSecurityInformation | (isProtected ? N.ProtectedDaclSecurityInformation : N.UnprotectedDaclSecurityInformation);
                int result = N.SetSecurity(target, info, null, bytes);
                if (result != 0)
                {
                    notes.Add($"The original access control list could not be restored (Win32 error {result}).");
                }
            }
        }

        if (original.Owner is { } owner && owner != CurrentOwner(target))
        {
            if (!canSetOwner)
            {
                notes.Add($"The original owner ({owner.Value}) could not be restored (no permission to change the owner).");
                return;
            }

            var sid = new byte[owner.BinaryLength];
            owner.GetBinaryForm(sid, 0);
            int result = N.SetSecurity(target, N.OwnerSecurityInformation, sid, null);
            if (result != 0)
            {
                notes.Add($"The original owner ({owner.Value}) could not be restored (Win32 error {result}).");
            }
        }
    }

    private static SecurityIdentifier? CurrentOwner(SafeFileHandle handle)
    {
        var sd = N.TryGetSecurity(handle, N.OwnerSecurityInformation, out _);
        return sd is null ? null : new RawSecurityDescriptor(sd, 0).Owner;
    }

    /// <summary>Renames to the original name, else <c>name (restored N).ext</c>; never replaces. Null if all are taken.</summary>
    private static string? RenameToFreeName(SafeFileHandle target, SafeFileHandle directory, string fileName)
    {
        for (int n = 0; n <= QuarantinePath.MaxRestoreSuffix; n++)
        {
            string candidate = QuarantinePath.RestoredName(fileName, n);
            if (candidate.Length > 255)
            {
                continue;
            }

            if (N.TryRenameRelative(target, directory, candidate, out int error))
            {
                return candidate;
            }

            if (error is not (N.ErrorAlreadyExists or N.ErrorFileExists or N.ErrorAccessDenied))
            {
                throw new IOException($"Renaming the restored file to '{candidate}' failed (Win32 error {error}).");
            }
        }

        return null;
    }

    /// <summary>Restored: mark it, remove the stored copy, then the metadata. A failure here is finished by recovery.</summary>
    private void RemoveEntry(QuarantineStore store, byte[] key, QuarantineMetadata metadata)
    {
        try
        {
            store.WriteMetadata(metadata with { State = QuarantineState.Restored, RestoreTempName = null }, key);
            Hook(QuarantineStep.RestoreMarkedRestored);
            QuarantineStore.DeleteIfExists(store.DataPath(metadata.Id));
            Hook(QuarantineStep.RestoreDataDeleted);
            QuarantineStore.DeleteIfExists(store.MetadataPath(metadata.Id));
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            _logger.LogWarning("Quarantine item {Id} was restored but its store entry could not be removed ({Message}); recovery finishes it.",
                metadata.Id, ex.Message);
        }
    }

    /// <summary>Back to Quarantined after a failed restore (the stored copy was never touched).</summary>
    private void Revert(QuarantineStore store, byte[] key, QuarantineMetadata quarantined)
    {
        try
        {
            store.WriteMetadata(quarantined with { State = QuarantineState.Quarantined, RestoreTempName = null }, key);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            _logger.LogWarning("Quarantine item {Id}: reverting the journal failed ({Message}); recovery reverts it.", quarantined.Id, ex.Message);
        }
    }

    private async Task EmitRestoredAlertAsync(QuarantineMetadata metadata, string restoredPath)
    {
        try
        {
            var now = _time.GetUtcNow();
            var reasons = new List<string> { $"Restored from quarantine at the user's request (item {metadata.Id})." };
            reasons.AddRange(metadata.Reasons);
            var alert = new Alert(
                Alert.ComputeAlertId(AlertType.QuarantineRestored, now, restoredPath, metadata.Sha256, metadata.Trigger),
                now, AlertType.QuarantineRestored, metadata.Verdict, restoredPath, metadata.Sha256, null, null,
                metadata.TechniqueIds.FirstOrDefault(), metadata.TechniqueIds.Skip(1).ToArray(), reasons, null,
                AlertAction.Restored, metadata.Trigger, EngineInfo.Version);
            await _alerts.WriteAsync(alert, CancellationToken.None).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex, "Could not build the QuarantineRestored alert for item {Id}.", metadata.Id);
        }
    }

    private static RestoreStatus MapDirectoryFailure(SafeDirectoryFailure failure) => failure switch
    {
        SafeDirectoryFailure.NotFound => RestoreStatus.TargetDirectoryMissing,
        SafeDirectoryFailure.Redirected or SafeDirectoryFailure.PathMismatch => RestoreStatus.TargetRedirected,
        SafeDirectoryFailure.Unsupported => RestoreStatus.UnsupportedTarget,
        _ => RestoreStatus.Failed,
    };
}
