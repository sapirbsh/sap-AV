using SapAV.Core.Hashing;
using SapAV.Core.Quarantine;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

/// <remarks>
/// <para><b>Startup recovery</b> (evidence-based: the journal state says what may be half done, the files say how far
/// it got). Nothing outside the store is ever deleted, except a restore temp file whose random name the journal
/// recorded, opened relative to the verified target folder.</para>
/// <list type="table">
/// <item><term>Quarantining</term><description>
/// <c>.partial</c> is always discarded. Stored copy verifies + staged raw file present → delete staged, mark Quarantined.
/// Stored copy verifies, no staged file → if the original is still in place with the same hash the move never
/// happened: discard the copy and the metadata (roll back); otherwise mark Quarantined.
/// No valid stored copy + staged file with the right hash → finish: neutralise from the staged file, verify, delete it.
/// No valid stored copy, no staged file → the original must still be in place: discard the metadata (and a bad copy).
/// Anything that doesn't verify and isn't backed by an intact original is left untouched and logged.</description></item>
/// <item><term>Restoring</term><description>Stored copy missing → the restore had finished: drop the metadata.
/// Otherwise delete the recorded temp file if it exists (relative to the safely opened folder) and go back to
/// Quarantined (a completed rename that wasn't journalled leaves a restored file <i>and</i> the stored copy).</description></item>
/// <item><term>Restored</term><description>Remove the stored copy, then the metadata.</description></item>
/// <item><term>Quarantined</term><description>Nothing to do. Stray <c>.json.tmp</c> files (our own half-written
/// metadata replacements) are removed.</description></item>
/// </list>
/// Items whose metadata fails the HMAC are never touched.
/// </remarks>
public sealed partial class QuarantineManager
{
    private List<QuarantineRecoveryAction> Recover(QuarantineStore store, byte[] key)
    {
        var actions = new List<QuarantineRecoveryAction>();
        foreach (var temp in Directory.EnumerateFiles(store.RootPath, "*.json.tmp"))
        {
            DeleteQuietly(temp);
        }

        foreach (var id in store.EnumerateItemIds())
        {
            QuarantineMetadata metadata;
            try
            {
                metadata = store.ReadMetadata(id, key);
            }
            catch (Exception ex) when (ex is QuarantineMetadataException || IsIoFailure(ex))
            {
                _logger.LogError("Quarantine item {Id}: metadata can't be verified ({Message}); left untouched.", id, ex.Message);
                actions.Add(new(id, null, "metadata invalid; left untouched"));
                continue;
            }

            string? action = metadata.State switch
            {
                QuarantineState.Quarantining => RecoverQuarantining(store, key, metadata),
                QuarantineState.Restoring => RecoverRestoring(store, key, metadata),
                QuarantineState.Restored => FinishRestored(store, metadata),
                _ => null,
            };

            if (action is not null)
            {
                _logger.LogWarning("Quarantine recovery, item {Id} ({State}): {Action}", id, metadata.State, action);
                actions.Add(new(id, metadata.State, action));
            }
        }

        return actions;
    }

    private string RecoverQuarantining(QuarantineStore store, byte[] key, QuarantineMetadata metadata)
    {
        string id = metadata.Id;
        DeleteQuietly(store.PartialPath(id));
        bool dataOk = StoredContent.Verify(store.DataPath(id), metadata.TransformKey, metadata.SizeBytes, metadata.Sha256);
        bool staged = File.Exists(store.StagedPath(id));

        if (dataOk && staged)
        {
            DeleteQuietly(store.StagedPath(id));
            return Finalise(store, key, metadata, "stored copy verified; staged raw file removed; completed");
        }

        if (dataOk)
        {
            if (OriginalStillInPlace(metadata))
            {
                DeleteQuietly(store.DataPath(id));
                DeleteMetadataQuietly(store, id);
                return "the original was never removed; rolled back (the file stays where it was)";
            }

            return Finalise(store, key, metadata, "stored copy verified; completed");
        }

        if (staged)
        {
            return ResumeFromStaged(store, key, metadata);
        }

        if (OriginalStillInPlace(metadata))
        {
            DeleteQuietly(store.DataPath(id));
            DeleteMetadataQuietly(store, id);
            return "the move never happened; rolled back (the file stays where it was)";
        }

        return "no verified copy and the original is not in place; left untouched for an administrator";
    }

    private string ResumeFromStaged(QuarantineStore store, byte[] key, QuarantineMetadata metadata)
    {
        using var staged = SecureFile.OpenRegularFile(store.StagedPath(metadata.Id), out var failure, out _,
            denyWriters: true, additionalAccess: N.Delete);
        if (staged is null)
        {
            return $"staged raw file can't be opened ({failure.Message}); left untouched";
        }

        try
        {
            var (sha, length) = StoredContent.Hash(staged);
            if (sha != metadata.Sha256 || length != metadata.SizeBytes)
            {
                return "staged raw file doesn't match the recorded hash; left untouched for an administrator";
            }

            DeleteQuietly(store.DataPath(metadata.Id));
            WriteStoredCopy(store, staged, metadata);
            if (!N.TryDeleteByHandle(staged, out int error))
            {
                return $"neutralised copy written, but the staged raw file can't be removed (Win32 error {error}); retried next start";
            }
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            DeleteQuietly(store.PartialPath(metadata.Id));
            return $"finishing from the staged raw file failed ({ex.Message}); retried next start";
        }

        staged.Dispose();
        return Finalise(store, key, metadata, "neutralised from the staged raw file; completed");
    }

    private string RecoverRestoring(QuarantineStore store, byte[] key, QuarantineMetadata metadata)
    {
        if (!File.Exists(store.DataPath(metadata.Id)))
        {
            DeleteMetadataQuietly(store, metadata.Id);
            return "the restore had completed; store entry removed";
        }

        string removed = RemoveRestoreTemp(metadata);
        Revert(store, key, metadata);
        return $"restore interrupted; {removed}; back to Quarantined";
    }

    /// <summary>Deletes the journalled temp file (exact random name, relative to the verified folder, link count 1).</summary>
    private static string RemoveRestoreTemp(QuarantineMetadata metadata)
    {
        using var directory = SafeDirectory.TryOpen(Path.GetDirectoryName(metadata.OriginalPath)!, out _, out var why);
        if (directory is null)
        {
            return $"target folder not verifiable ({why}), temp file not looked for";
        }

        using var temp = N.OpenRelative(directory, metadata.RestoreTempName!, N.Delete | N.FileReadAttributes,
            N.ShareRead | N.ShareWrite | N.ShareDelete, N.FileOpen, N.FileNonDirectoryFile | N.FileOpenReparsePoint,
            out _, N.ObjCaseInsensitive | N.ObjDontReparse);
        if (temp is null)
        {
            return "no temp file (a restored copy may already be in the folder)";
        }

        bool plain = N.TryGetAttributeTag(temp, out uint attributes, out _) && (attributes & N.FileAttributeReparsePoint) == 0
            && N.GetFileInformation(temp).NumberOfLinks == 1;
        return plain && N.TryDeleteByHandle(temp, out _) ? "partial temp file removed" : "temp file left in place (not a plain file)";
    }

    private string FinishRestored(QuarantineStore store, QuarantineMetadata metadata)
    {
        DeleteQuietly(store.DataPath(metadata.Id));
        DeleteMetadataQuietly(store, metadata.Id);
        return "restore had completed; store entry removed";
    }

    private string Finalise(QuarantineStore store, byte[] key, QuarantineMetadata metadata, string action)
    {
        try
        {
            store.WriteMetadata(metadata with { State = QuarantineState.Quarantined }, key);
            return action;
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            return $"{action}, but the journal write failed ({ex.Message}); retried next start";
        }
    }

    /// <summary>The original is at its recorded path with the recorded size and hash (read-only hardened open).</summary>
    private static bool OriginalStillInPlace(QuarantineMetadata metadata)
    {
        using var file = SecureFile.OpenRegularFile(metadata.OriginalPath, out _, out _);
        if (file is null)
        {
            return false;
        }

        try
        {
            var (sha, length) = StoredContent.Hash(file);
            return sha == metadata.Sha256 && length == metadata.SizeBytes;
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            return false;
        }
    }
}
