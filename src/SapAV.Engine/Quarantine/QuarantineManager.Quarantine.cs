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
    /// <summary>Access the source handle must have: read, DELETE (move / delete by handle), WRITE_DAC (lock down the staged file).</summary>
    private const uint SourceAccess = N.GenericRead | N.Delete | N.WriteDac;

    /// <summary>The specific rights GENERIC_READ | DELETE | WRITE_DAC map to that matter here (FILE_READ_DATA = 0x1).</summary>
    private const uint RequiredGranted = 0x1 | N.Delete | N.WriteDac;

    /// <inheritdoc/>
    public Task<QuarantineResult> QuarantineAsync(FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsEligible(report, out var scannedPath, out var refusal) || IsEngineFolder(report, scannedPath, out refusal)
            || !TryGetStore(out var store, out var key, out refusal))
        {
            return Task.FromResult(refusal);
        }

        // Cancellation is honoured until the journal is written; after that the operation always runs to a consistent end.
        return Task.Run(() => QuarantineByPath(store, key, report, scannedPath, alertId, cancellationToken), CancellationToken.None);
    }

    /// <inheritdoc/>
    public Task<QuarantineResult> QuarantineHandleAsync(
        SafeFileHandle handle, FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(report);
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsEligible(report, out var scannedPath, out var refusal) || IsEngineFolder(report, scannedPath, out refusal)
            || !TryGetStore(out var store, out var key, out refusal))
        {
            return Task.FromResult(refusal);
        }

        if (handle.IsInvalid || handle.IsClosed || !N.TryGetGrantedAccess(handle, out uint granted) || (granted & RequiredGranted) != RequiredGranted)
        {
            return Task.FromResult(new QuarantineResult(QuarantineStatus.NotEligible,
                "The handle must be open with read, DELETE and WRITE_DAC access (and deny writers)."));
        }

        return Task.Run(() => QuarantineByHandle(store, key, handle, report, scannedPath, alertId, cancellationToken), CancellationToken.None);
    }

    /// <summary>
    /// The scan must be actionable, carry the scanned object's identity, and the scan itself must not have gone through a
    /// redirect: the normalised requested path equals the final path of the handle the scan used.
    /// </summary>
    private static bool IsEligible(FileScanReport report, out string scannedPath, out QuarantineResult refusal)
    {
        var result = report.Result;
        scannedPath = string.Empty;
        string? normalized = null;
        try
        {
            normalized = Path.GetFullPath(result.Item.Path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
        }

        string? why =
            result.Status != ScanStatus.Scanned ? $"the file was not scanned ({result.Status})"
            : result.Verdict is not (Verdict.Suspicious or Verdict.Malicious) ? "the verdict is Clean"
            : result.Sha256 is null || report.Hash.Sha256 is null || report.Hash.Length is null ? "the scan has no SHA-256 / size"
            : !string.Equals(result.Sha256, report.Hash.Sha256, StringComparison.OrdinalIgnoreCase) ? "the scan result and hash disagree"
            : report.Identity?.FinalPath is null ? "the scan has no file identity (file ID and final path)"
            : normalized is null || !QuarantinePath.TryValidateOriginalPath(normalized, out _) ? "the scanned path is not a local drive-letter path"
            : null;
        if (why is not null)
        {
            refusal = new QuarantineResult(QuarantineStatus.NotEligible, why);
            return false;
        }

        if (!string.Equals(normalized, report.Identity!.FinalPath, StringComparison.OrdinalIgnoreCase))
        {
            refusal = new QuarantineResult(QuarantineStatus.PathRedirected,
                $"The scan's handle resolved to {report.Identity.FinalPath}, not the requested {normalized}; refusing to act on it.");
            return false;
        }

        scannedPath = normalized!;
        refusal = null!;
        return true;
    }

    /// <summary>Review B2 follow-up Medium: the engine's own folders (data, store, install, rules) are never quarantined.</summary>
    private bool IsEngineFolder(FileScanReport report, string scannedPath, out QuarantineResult refusal)
    {
        if (_engineFolders.Contains(scannedPath) || _engineFolders.Contains(report.Identity?.FinalPath))
        {
            refusal = new QuarantineResult(QuarantineStatus.EngineFolder, "The file is in one of sap-AV's own folders; it is never quarantined.");
            return true;
        }

        refusal = null!;
        return false;
    }

    /// <summary>
    /// Review B2 M4: the neutralised copy needs <paramref name="length"/> more bytes in the store (the raw file is moved,
    /// or copied and deleted). Refused if that takes the store over its quota or its drive under the free-space floor.
    /// </summary>
    private QuarantineResult? CheckSpace(QuarantineStore store, long length)
    {
        long used = 0;
        try
        {
            foreach (var file in new DirectoryInfo(store.RootPath).EnumerateFiles("*", new EnumerationOptions { AttributesToSkip = 0, RecurseSubdirectories = false }))
            {
                used += file.Length;
            }

            long free = new DriveInfo(Path.GetPathRoot(store.RootPath)!).AvailableFreeSpace;
            string? why =
                used + length > _options.MaxStoreBytes
                    ? $"the store holds {used} bytes and this file needs {length} more, over the {_options.MaxStoreBytes}-byte quota"
                : free - length < _options.MinFreeSpaceBytes
                    ? $"the store's drive has {free} bytes free; quarantining {length} bytes would go below the {_options.MinFreeSpaceBytes}-byte floor"
                : null;
            return why is null ? null : new QuarantineResult(QuarantineStatus.StoreFull, $"The quarantine store is full: {why}.");
        }
        catch (Exception ex) when (IsIoFailure(ex) || ex is ArgumentException)
        {
            return new QuarantineResult(QuarantineStatus.StoreFull, $"The quarantine store's size or free space could not be read ({ex.GetType().Name}).");
        }
    }

    private bool TryGetStore(out QuarantineStore store, out byte[] key, out QuarantineResult refusal)
    {
        refusal = new QuarantineResult(QuarantineStatus.StoreUnavailable, "The quarantine store is not available.");
        return TryGetStore(out store, out key);
    }

    /// <summary>Path entry: opens the scanned path with no reparse point anywhere (folders and the file itself).</summary>
    private QuarantineResult QuarantineByPath(QuarantineStore store, byte[] key, FileScanReport report, string scannedPath, Guid? alertId, CancellationToken ct)
    {
        using var lease = _locks.TryAcquire("path:" + scannedPath);
        if (lease is null)
        {
            return Log(scannedPath, new(QuarantineStatus.Busy, "Another quarantine operation on this file is running."));
        }

        using var file = SafeFile.TryOpen(scannedPath, SourceAccess, N.ShareRead | N.ShareDelete,
            out var directory, out var failure, out int error, out var reason);
        using (directory)
        {
            if (file is null)
            {
                return Log(scannedPath, new(MapOpenFailure(failure, error), $"Can't open the file: {reason}"));
            }

            return Log(scannedPath, QuarantineCore(store, key, file, ownsHandle: true, directory!, report, scannedPath, alertId, ct));
        }
    }

    /// <summary>Handle entry (B3): the scan's own writer-denied handle; it is never reopened by path and not closed here.</summary>
    private QuarantineResult QuarantineByHandle(
        QuarantineStore store, byte[] key, SafeFileHandle file, FileScanReport report, string scannedPath, Guid? alertId, CancellationToken ct)
    {
        using var lease = _locks.TryAcquire("path:" + scannedPath);
        if (lease is null)
        {
            return Log(scannedPath, new(QuarantineStatus.Busy, "Another quarantine operation on this file is running."));
        }

        if (!SecureFile.Validate(file, out var invalid, out _))
        {
            return Log(scannedPath, new(QuarantineStatus.NotRegularFile, $"The handle is not a usable file: {invalid.Message}"));
        }

        using var directory = SafeDirectory.TryOpen(Path.GetDirectoryName(scannedPath)!, out var failure, out var reason);
        if (directory is null)
        {
            return Log(scannedPath, new(MapOpenFailure(failure, 0), $"The file's folder can't be verified: {reason}"));
        }

        return Log(scannedPath, QuarantineCore(store, key, file, ownsHandle: false, directory, report, scannedPath, alertId, ct));
    }

    private QuarantineResult Log(string path, QuarantineResult result)
    {
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

    private QuarantineResult QuarantineCore(
        QuarantineStore store, byte[] key, SafeFileHandle file, bool ownsHandle, SafeFileHandle originalDirectory,
        FileScanReport report, string scannedPath, Guid? alertId, CancellationToken ct)
    {
        // Bound to the scanned object: same volume + 128-bit file ID, and the handle is at exactly the scanned path.
        var now = FileIdentity.TryCapture(file);
        if (now is null || !now.IsSameObject(report.Identity))
        {
            return new(QuarantineStatus.IdentityMismatch, "This is not the file object that was scanned (volume / file ID differ).");
        }

        if (!string.Equals(now.FinalPath, scannedPath, StringComparison.OrdinalIgnoreCase))
        {
            return new(QuarantineStatus.PathRedirected, $"The file is at {now.FinalPath ?? "an unknown path"}, not the scanned {scannedPath}.");
        }

        N.ByHandleFileInformation info;
        try
        {
            if (!CheckSource(file, report, ct, out info, out var refusal))
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

        if (CheckSpace(store, report.Hash.Length!.Value) is { } full)
        {
            return full;
        }

        // The path lock doesn't see other spellings of the same file: lock the file object itself.
        using var fileLease = _locks.TryAcquire($"file:{now.VolumeSerialNumber:x16}:{now.FileId}");
        if (fileLease is null)
        {
            return new(QuarantineStatus.Busy, "Another quarantine operation on this file is running.");
        }

        bool sameVolume = !ForceCrossVolume && info.VolumeSerialNumber == store.VolumeSerial;
        QuarantineMetadata metadata;
        try
        {
            metadata = BuildMetadata(file, info, now, report, scannedPath, alertId, sameVolume);
            ct.ThrowIfCancellationRequested();
            store.WriteMetadata(metadata, key);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            return new(QuarantineStatus.Failed, $"Can't write the quarantine metadata: {ex.Message}");
        }

        Hook(QuarantineStep.QuarantineJournalWritten);
        var move = new SourceHandle(file, ownsHandle, originalDirectory);
        return sameVolume ? MoveSameVolume(store, key, move, metadata) : MoveCrossVolume(store, key, move, metadata);
    }

    /// <summary>The source handle, whether this code closes it, and its verified original folder (for moving back).</summary>
    private readonly record struct SourceHandle(SafeFileHandle File, bool Owns, SafeFileHandle OriginalDirectory)
    {
        public void CloseIfOwned()
        {
            if (Owns)
            {
                File.Dispose();
            }
        }
    }

    private bool CheckSource(SafeFileHandle file, FileScanReport report, CancellationToken ct, out N.ByHandleFileInformation info, out QuarantineResult refusal)
    {
        info = N.GetFileInformation(file);
        long length = RandomAccess.GetLength(file);
        (QuarantineStatus Status, string Why)? problem =
            info.NumberOfLinks != 1 ? (QuarantineStatus.MultipleHardLinks, $"the file has {info.NumberOfLinks} hard links")
            : length != report.Hash.Length ? (QuarantineStatus.ContentChanged, $"the size changed since the scan ({report.Hash.Length} -> {length} bytes)")
            : length > _options.MaxFileSizeBytes ? (QuarantineStatus.UnsupportedLocation, $"the file is over the {_options.MaxFileSizeBytes}-byte limit")
            : StoredContent.Hash(file, ct).Sha256 != report.Result.Sha256!.ToLowerInvariant()
                ? (QuarantineStatus.ContentChanged, "the SHA-256 changed since the scan; refusing to quarantine something that wasn't scanned")
            : null;
        refusal = problem is { } p ? new(p.Status, p.Why) : null!;
        return problem is null;
    }

    private QuarantineMetadata BuildMetadata(
        SafeFileHandle file, N.ByHandleFileInformation info, FileIdentity identity, FileScanReport report, string finalPath,
        Guid? alertId, bool sameVolume)
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
            SourceVolumeSerial = identity.VolumeSerialNumber,
            SourceFileId = identity.FileId,
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

    /// <summary>
    /// Same volume: rename by handle into the store, lock the staged file down (protected SYSTEM/Administrators DACL,
    /// no implicit owner rights), neutralise from the handle, re-check the link count, delete the staged raw file.
    /// </summary>
    private QuarantineResult MoveSameVolume(QuarantineStore store, byte[] key, SourceHandle source, QuarantineMetadata metadata)
    {
        if (!N.TryRenameRelative(source.File, store.RootHandle, QuarantineStore.StagedName(metadata.Id), out int error))
        {
            if (error == N.ErrorNotSameDevice)
            {
                var cross = metadata with { MoveKind = QuarantineMoveKind.CrossVolume };
                TryWriteJournal(store, key, cross);
                return MoveCrossVolume(store, key, source, cross);
            }

            DeleteMetadataQuietly(store, metadata.Id);
            return new(MapWin32(error), $"Can't move the file into quarantine (Win32 error {error}); it was left in place.");
        }

        Hook(QuarantineStep.QuarantineStaged);
        int aclError = N.SetSecurity(source.File, N.DaclSecurityInformation | N.ProtectedDaclSecurityInformation, null,
            _policy.CreateStagedFileDaclBytes());
        if (aclError != 0)
        {
            return MoveBack(store, source, metadata, QuarantineStatus.Failed, $"Can't protect the staged file (Win32 error {aclError})");
        }

        try
        {
            WriteStoredCopy(store, source.File, metadata);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            DeleteQuietly(store.PartialPath(metadata.Id));
            return MoveBack(store, source, metadata, QuarantineStatus.Failed, $"Can't write the neutralised copy ({ex.Message})");
        }

        Hook(QuarantineStep.QuarantineStoredCopyWritten);
        if (LinkCount(source.File) != 1)
        {
            DeleteQuietly(store.DataPath(metadata.Id));
            return MoveBack(store, source, metadata, QuarantineStatus.MultipleHardLinks, "A hard link to the file appeared during the move");
        }

        if (!N.TryDeleteByHandle(source.File, out error))
        {
            _logger.LogWarning("Quarantine item {Id}: removing the staged raw file failed (Win32 error {Error}); recovery finishes it.",
                metadata.Id, error);
            return new(QuarantineStatus.Quarantined, "Quarantined; the staged raw copy is removed at the next start.", QuarantineEntry.From(metadata));
        }

        source.CloseIfOwned();
        Hook(QuarantineStep.QuarantineSourceDeleted);
        return Finish(store, key, metadata);
    }

    /// <summary>
    /// Undo a same-volume move: rename back relative to the verified original folder (never by path), put the original
    /// DACL back, drop the journal. If that fails, the raw file stays in the protected staging area for recovery.
    /// </summary>
    private QuarantineResult MoveBack(QuarantineStore store, SourceHandle source, QuarantineMetadata metadata, QuarantineStatus status, string why)
    {
        if (N.TryRenameRelative(source.File, source.OriginalDirectory, Path.GetFileName(metadata.OriginalPath), out int backError))
        {
            var notes = new List<string>();
            if (metadata.SecurityDescriptor is { } sddl)
            {
                ApplySecurity(source.File, sddl, canSetOwner: false, notes);
            }

            DeleteMetadataQuietly(store, metadata.Id);
            return new(status, $"{why}; the file was moved back." + (notes.Count > 0 ? " " + string.Join(" ", notes) : string.Empty));
        }

        _logger.LogError("Quarantine item {Id}: {Why}, and moving the file back failed (Win32 error {Error}); it stays in the " +
            "protected staging area and is finished at the next start.", metadata.Id, why, backError);
        return new(status, $"{why}; the original is kept in the quarantine staging area.");
    }

    /// <summary>Different volume: neutralised copy from the handle, verify it, re-check links, then delete the original by the same handle.</summary>
    private QuarantineResult MoveCrossVolume(QuarantineStore store, byte[] key, SourceHandle source, QuarantineMetadata metadata)
    {
        try
        {
            WriteStoredCopy(store, source.File, metadata);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            DeleteQuietly(store.PartialPath(metadata.Id));
            DeleteMetadataQuietly(store, metadata.Id);
            return new(QuarantineStatus.Failed, $"Can't write the neutralised copy ({ex.Message}); the file was left in place.");
        }

        Hook(QuarantineStep.QuarantineStoredCopyWritten);
        string? refusal = LinkCount(source.File) != 1 ? "A hard link to the file appeared during the copy" : null;

        // Part of the move, not a deletion of user data: the verified copy is already in the store.
        int error = 0;
        if (refusal is not null || !N.TryDeleteByHandle(source.File, out error))
        {
            DeleteQuietly(store.DataPath(metadata.Id));
            DeleteMetadataQuietly(store, metadata.Id);
            return refusal is not null
                ? new(QuarantineStatus.MultipleHardLinks, refusal + "; the file was left in place.")
                : new(MapWin32(error), $"Can't remove the original after copying (Win32 error {error}); it was left in place.");
        }

        source.CloseIfOwned();
        Hook(QuarantineStep.QuarantineSourceDeleted);
        return Finish(store, key, metadata);
    }

    private static uint LinkCount(SafeFileHandle file)
    {
        try
        {
            return N.GetFileInformation(file).NumberOfLinks;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return uint.MaxValue;
        }
    }

    private void TryWriteJournal(QuarantineStore store, byte[] key, QuarantineMetadata metadata)
    {
        try
        {
            store.WriteMetadata(metadata, key);
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            _logger.LogWarning("Quarantine item {Id}: journal update failed ({Message}).", metadata.Id, ex.Message);
        }
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

    private static QuarantineStatus MapOpenFailure(SafeDirectoryFailure failure, int win32Error) => failure switch
    {
        SafeDirectoryFailure.NotFound => QuarantineStatus.NotFound,
        SafeDirectoryFailure.Redirected or SafeDirectoryFailure.PathMismatch => QuarantineStatus.PathRedirected,
        SafeDirectoryFailure.Unsupported => QuarantineStatus.UnsupportedLocation,
        _ when win32Error is N.ErrorSharingViolation or N.ErrorLockViolation => QuarantineStatus.Locked,
        _ when win32Error == N.ErrorAccessDenied => QuarantineStatus.AccessDenied,
        _ when win32Error == 0 => QuarantineStatus.NotRegularFile, // opened, but not a usable regular file
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
