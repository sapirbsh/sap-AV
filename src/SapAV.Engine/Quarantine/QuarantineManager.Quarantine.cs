using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Quarantine;
using SapAV.Core.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

public sealed partial class QuarantineManager
{
    /// <inheritdoc/>
    public Task<QuarantineResult> QuarantineAsync(FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsEligible(report, out var refusal))
        {
            return Task.FromResult(refusal);
        }

        if (!TryGetStore(out var store, out var key))
        {
            return Task.FromResult(new QuarantineResult(QuarantineStatus.StoreUnavailable, "The quarantine store is not available."));
        }

        // Cancellation is honoured until the journal is written; after that the operation always runs to a consistent end.
        return Task.Run(() => QuarantineLocked(store, key, report, alertId, cancellationToken), CancellationToken.None);
    }

    private static bool IsEligible(FileScanReport report, out QuarantineResult refusal)
    {
        var result = report.Result;
        string? why =
            result.Status != ScanStatus.Scanned ? $"the file was not scanned ({result.Status})"
            : result.Verdict is not (Verdict.Suspicious or Verdict.Malicious) ? "the verdict is Clean"
            : result.Sha256 is null || report.Hash.Sha256 is null || report.Hash.Length is null ? "the scan has no SHA-256 / size"
            : !string.Equals(result.Sha256, report.Hash.Sha256, StringComparison.OrdinalIgnoreCase) ? "the scan result and hash disagree"
            : null;
        refusal = new QuarantineResult(QuarantineStatus.NotEligible, why ?? string.Empty);
        return why is null;
    }

    private QuarantineResult QuarantineLocked(QuarantineStore store, byte[] key, FileScanReport report, Guid? alertId, CancellationToken ct)
    {
        string path = report.Result.Item.Path;
        using var lease = _locks.TryAcquire("path:" + path);
        if (lease is null)
        {
            return new(QuarantineStatus.Busy, "Another quarantine operation on this file is running.");
        }

        var result = QuarantineCore(store, key, report, alertId, ct);
        if (result.Status == QuarantineStatus.Quarantined)
        {
            _logger.LogInformation("Quarantined {Path} as item {Id}.", path, result.Entry!.Id);
        }
        else
        {
            _logger.LogWarning("Quarantine of {Path} failed ({Status}): {Reason}", path, result.Status, result.Reason);
        }

        return result;
    }

    private QuarantineResult QuarantineCore(QuarantineStore store, byte[] key, FileScanReport report, Guid? alertId, CancellationToken ct)
    {
        // The hardened open, denying writers, with DELETE so the same handle can be moved / deleted.
        using var file = SecureFile.OpenRegularFile(report.Result.Item.Path, out var openFailure, out _,
            allowOffline: false, denyWriters: true, additionalAccess: N.Delete);
        if (file is null)
        {
            return new(MapOpenFailure(openFailure.Reason), $"Can't open the file: {openFailure.Message}");
        }

        N.ByHandleFileInformation info;
        string finalPath;
        try
        {
            if (!CheckSource(file, report, ct, out info, out finalPath, out var refusal))
            {
                return refusal;
            }
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            // E.g. a byte-range lock held by another process (ERROR_LOCK_VIOLATION) while hashing.
            bool locked = (ex.HResult & 0xFFFF) is N.ErrorLockViolation or N.ErrorSharingViolation;
            return new(locked ? QuarantineStatus.Locked : QuarantineStatus.Failed, $"Can't read the file: {ex.Message}");
        }

        // The path lock doesn't see other spellings of the same file (case, 8.3 names, links in the path): lock the file itself.
        using var fileLease = _locks.TryAcquire($"file:{info.VolumeSerialNumber:x8}:{info.FileIndexHigh:x8}{info.FileIndexLow:x8}");
        if (fileLease is null)
        {
            return new(QuarantineStatus.Busy, "Another quarantine operation on this file is running.");
        }

        string directory = Path.GetDirectoryName(finalPath)!;
        using var originalDirectory = SafeDirectory.TryOpen(directory, out var dirFailure, out var dirReason);
        if (originalDirectory is null)
        {
            return new(dirFailure is SafeDirectoryFailure.Redirected or SafeDirectoryFailure.PathMismatch
                ? QuarantineStatus.PathRedirected : QuarantineStatus.Failed, $"The file's folder can't be verified: {dirReason}");
        }

        bool sameVolume = !ForceCrossVolume && info.VolumeSerialNumber == store.VolumeSerial;
        QuarantineMetadata metadata;
        try
        {
            metadata = BuildMetadata(file, info, report, finalPath, alertId, sameVolume);
            ct.ThrowIfCancellationRequested();
            store.WriteMetadata(metadata, key);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            return new(QuarantineStatus.Failed, $"Can't write the quarantine metadata: {ex.Message}");
        }

        Hook(QuarantineStep.QuarantineJournalWritten);
        return sameVolume
            ? MoveSameVolume(store, key, file, originalDirectory, metadata)
            : MoveCrossVolume(store, key, file, metadata);
    }

    private bool CheckSource(
        SafeFileHandle file, FileScanReport report, CancellationToken ct,
        out N.ByHandleFileInformation info, out string finalPath, out QuarantineResult refusal)
    {
        info = N.GetFileInformation(file);
        finalPath = string.Empty;
        long length = RandomAccess.GetLength(file);
        string? why = null;
        var status = QuarantineStatus.ContentChanged;
        if (info.NumberOfLinks != 1)
        {
            (status, why) = (QuarantineStatus.MultipleHardLinks, $"the file has {info.NumberOfLinks} hard links");
        }
        else if (length != report.Hash.Length)
        {
            why = $"the size changed since the scan ({report.Hash.Length} -> {length} bytes)";
        }
        else if (length > _options.MaxFileSizeBytes)
        {
            (status, why) = (QuarantineStatus.UnsupportedLocation, $"the file is over the {_options.MaxFileSizeBytes}-byte limit");
        }
        else if (StoredContent.Hash(file, ct).Sha256 != report.Result.Sha256!.ToLowerInvariant())
        {
            why = "the SHA-256 changed since the scan; refusing to quarantine something that wasn't scanned";
        }
        else if (N.GetFinalDosPath(file) is not { } final || !QuarantinePath.TryValidateOriginalPath(final, out _))
        {
            (status, why) = (QuarantineStatus.UnsupportedLocation, "the file is not on a local drive-letter path");
        }
        else
        {
            finalPath = final;
        }

        refusal = new(status, why ?? string.Empty);
        return why is null;
    }

    private QuarantineMetadata BuildMetadata(
        SafeFileHandle file, N.ByHandleFileInformation info, FileScanReport report, string finalPath, Guid? alertId, bool sameVolume)
    {
        var result = report.Result;
        var ordered = result.Detections.OrderByDescending(d => d.Verdict).ToArray();
        return new QuarantineMetadata
        {
            Id = QuarantineItemId.New(),
            State = QuarantineState.Quarantining,
            MoveKind = sameVolume ? QuarantineMoveKind.SameVolume : QuarantineMoveKind.CrossVolume,
            OriginalPath = finalPath,
            ScannedPath = result.Item.Path,
            SizeBytes = report.Hash.Length!.Value,
            Sha256 = result.Sha256!.ToLowerInvariant(),
            Attributes = (int)info.FileAttributes,
            CreationTimeUtc = FromFileTime(info.CreationTime),
            LastWriteTimeUtc = FromFileTime(info.LastWriteTime),
            LastAccessTimeUtc = FromFileTime(info.LastAccessTime),
            SecurityDescriptor = ReadSddl(file),
            ZoneIdentifier = ReadZoneIdentifier(file),
            Verdict = result.Verdict!.Value,
            Reasons = ordered.Select(d => d.Reason).Take(QuarantineMetadata.MaxReasons).ToArray(),
            TechniqueIds = ordered.SelectMany(d => d.SecondaryTechniqueIds.Prepend(d.TechniqueId)).Distinct(StringComparer.Ordinal)
                .Take(QuarantineMetadata.MaxReasons * 4).ToArray(),
            Trigger = result.Item.Trigger,
            ScanTimestamp = result.Timestamp,
            QuarantinedAtUtc = _time.GetUtcNow(),
            AlertId = alertId,
            TransformAlgorithm = QuarantineContentTransform.Algorithm,
            TransformKey = QuarantineContentTransform.CreateKey(),
        };
    }

    /// <summary>Same volume: rename by handle into the store, neutralise from the handle, delete the staged raw file.</summary>
    private QuarantineResult MoveSameVolume(
        QuarantineStore store, byte[] key, SafeFileHandle file, SafeFileHandle originalDirectory, QuarantineMetadata metadata)
    {
        if (!N.TryRenameRelative(file, store.RootHandle, QuarantineStore.StagedName(metadata.Id), out int error))
        {
            if (error == N.ErrorNotSameDevice)
            {
                return MoveCrossVolume(store, key, file, metadata with { MoveKind = QuarantineMoveKind.CrossVolume });
            }

            DeleteMetadataQuietly(store, metadata.Id);
            return new(MapWin32(error), $"Can't move the file into quarantine (Win32 error {error}); it was left in place.");
        }

        Hook(QuarantineStep.QuarantineStaged);
        try
        {
            WriteStoredCopy(store, file, metadata);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            DeleteQuietly(store.PartialPath(metadata.Id));
            string name = Path.GetFileName(metadata.OriginalPath);
            if (N.TryRenameRelative(file, originalDirectory, name, out int backError))
            {
                DeleteMetadataQuietly(store, metadata.Id);
                return new(QuarantineStatus.Failed, $"Can't write the neutralised copy ({ex.Message}); the file was moved back.");
            }

            _logger.LogError("Quarantine item {Id}: the neutralised copy failed ({Message}) and moving the file back failed " +
                "(Win32 error {Error}); it stays in the protected staging area and is finished at the next start.", metadata.Id, ex.Message, backError);
            return new(QuarantineStatus.Failed, $"Can't write the neutralised copy ({ex.Message}); the original is kept in the quarantine staging area.");
        }

        Hook(QuarantineStep.QuarantineStoredCopyWritten);
        if (!N.TryDeleteByHandle(file, out error))
        {
            _logger.LogWarning("Quarantine item {Id}: removing the staged raw file failed (Win32 error {Error}); recovery finishes it.",
                metadata.Id, error);
            return new(QuarantineStatus.Quarantined, "Quarantined; the staged raw copy is removed at the next start.", QuarantineEntry.From(metadata));
        }

        file.Dispose();
        Hook(QuarantineStep.QuarantineSourceDeleted);
        return Finish(store, key, metadata);
    }

    /// <summary>Different volume: neutralised copy from the handle, verify it, then delete the original by the same handle.</summary>
    private QuarantineResult MoveCrossVolume(QuarantineStore store, byte[] key, SafeFileHandle file, QuarantineMetadata metadata)
    {
        try
        {
            WriteStoredCopy(store, file, metadata);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            DeleteQuietly(store.PartialPath(metadata.Id));
            DeleteMetadataQuietly(store, metadata.Id);
            return new(QuarantineStatus.Failed, $"Can't write the neutralised copy ({ex.Message}); the file was left in place.");
        }

        Hook(QuarantineStep.QuarantineStoredCopyWritten);

        // Part of the move, not a deletion of user data: the verified copy is already in the store.
        if (!N.TryDeleteByHandle(file, out int error))
        {
            DeleteQuietly(store.DataPath(metadata.Id));
            DeleteMetadataQuietly(store, metadata.Id);
            return new(MapWin32(error), $"Can't remove the original after copying (Win32 error {error}); it was left in place.");
        }

        file.Dispose();
        Hook(QuarantineStep.QuarantineSourceDeleted);
        return Finish(store, key, metadata);
    }

    /// <summary>Copies + neutralises from the handle, checks the plaintext hash, verifies the stored file, then publishes it.</summary>
    private static void WriteStoredCopy(QuarantineStore store, SafeFileHandle source, QuarantineMetadata metadata)
    {
        string partial = store.PartialPath(metadata.Id);
        var (sha, length) = StoredContent.WriteNeutralised(source, partial, metadata.TransformKey);
        if (sha != metadata.Sha256 || length != metadata.SizeBytes)
        {
            throw new InvalidDataException("The content changed while it was copied.");
        }

        if (!StoredContent.Verify(partial, metadata.TransformKey, metadata.SizeBytes, metadata.Sha256))
        {
            throw new InvalidDataException("The stored copy did not verify.");
        }

        File.Move(partial, store.DataPath(metadata.Id));
    }

    private QuarantineResult Finish(QuarantineStore store, byte[] key, QuarantineMetadata metadata)
    {
        var done = metadata with { State = QuarantineState.Quarantined };
        try
        {
            store.WriteMetadata(done, key);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            _logger.LogWarning("Quarantine item {Id}: the final journal write failed ({Message}); recovery finishes it.", metadata.Id, ex.Message);
        }

        return new(QuarantineStatus.Quarantined, "Quarantined.", QuarantineEntry.From(done));
    }

    private static string? ReadSddl(SafeFileHandle file)
    {
        var sd = N.TryGetSecurity(file, N.OwnerSecurityInformation | N.GroupSecurityInformation | N.DaclSecurityInformation, out _);
        if (sd is null)
        {
            return null;
        }

        var sddl = new RawSecurityDescriptor(sd, 0).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
        return sddl.Length <= QuarantineMetadata.MaxSddlLength ? sddl : null;
    }

    /// <summary>The raw Zone.Identifier stream, read relative to the handle (never parsed here); null if absent or too large.</summary>
    private static byte[]? ReadZoneIdentifier(SafeFileHandle file)
    {
        using var stream = NativeFile.OpenStreamRelative(file, ":" + MarkOfTheWebReader.StreamName, out _);
        if (stream is null || NativeFile.GetFileType(stream) != NativeFile.FileTypeDisk)
        {
            return null;
        }

        long length = RandomAccess.GetLength(stream);
        if (length is 0 or > QuarantineMetadata.MaxZoneIdentifierBytes)
        {
            return null;
        }

        var bytes = new byte[length];
        int total = 0;
        while (total < bytes.Length)
        {
            int read = RandomAccess.Read(stream, bytes.AsSpan(total), total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total == bytes.Length ? bytes : bytes[..total];
    }

    private static DateTimeOffset FromFileTime(long fileTime) =>
        new(DateTime.FromFileTimeUtc(Math.Max(0, fileTime)), TimeSpan.Zero);

    private static QuarantineStatus MapOpenFailure(HashFailureReason reason) => reason switch
    {
        HashFailureReason.Locked => QuarantineStatus.Locked,
        HashFailureReason.AccessDenied => QuarantineStatus.AccessDenied,
        HashFailureReason.NotFound => QuarantineStatus.NotFound,
        HashFailureReason.Directory or HashFailureReason.NotRegularFile or HashFailureReason.Offline => QuarantineStatus.NotRegularFile,
        _ => QuarantineStatus.Failed,
    };

    private static QuarantineStatus MapWin32(int error) => error switch
    {
        N.ErrorSharingViolation or N.ErrorLockViolation => QuarantineStatus.Locked,
        N.ErrorAccessDenied => QuarantineStatus.AccessDenied,
        _ => QuarantineStatus.Failed,
    };

    private void DeleteMetadataQuietly(QuarantineStore store, string id)
    {
        DeleteQuietly(store.MetadataPath(id));
        DeleteQuietly(store.MetadataTempPath(id));
    }

    private void DeleteQuietly(string storePath)
    {
        try
        {
            QuarantineStore.DeleteIfExists(storePath);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            _logger.LogWarning("Can't remove quarantine store file {Path}: {Message}", storePath, ex.Message);
        }
    }
}
