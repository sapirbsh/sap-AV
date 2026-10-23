using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Quarantine;

namespace SapAV.Engine.Quarantine;

/// <summary>Outcome of <see cref="IQuarantineService.QuarantineAsync"/>. Everything except Quarantined leaves the file in place.</summary>
public enum QuarantineStatus
{
    Quarantined,

    /// <summary>The scan result can't be acted on (not scanned, Clean, no SHA-256 or size).</summary>
    NotEligible,

    /// <summary>The store isn't initialised or was refused (see the engine log).</summary>
    StoreUnavailable,

    /// <summary>Another quarantine operation on the same file is running.</summary>
    Busy,

    NotFound,

    /// <summary>The file is open by a writer, or by someone who doesn't share delete (and it isn't scheduled for reboot; that's E12).</summary>
    Locked,

    AccessDenied,

    /// <summary>Not a regular local file (directory, device, offline/cloud placeholder, ...).</summary>
    NotRegularFile,

    /// <summary>The size or SHA-256 differs from the scan result being acted on: the file changed since the scan.</summary>
    ContentChanged,

    /// <summary>The file has more than one hard link; moving one name would leave the content reachable.</summary>
    MultipleHardLinks,

    /// <summary>Not on a drive-letter path (network share, volume without a letter) or the size is over the limit.</summary>
    UnsupportedLocation,

    /// <summary>
    /// The path (or a folder on it) is a reparse point, or the scan.s handle / the opened file is not at the scanned path.
    /// </summary>
    PathRedirected,

    /// <summary>The opened file is a different file object (volume serial / 128-bit file ID) than the one that was scanned.</summary>
    IdentityMismatch,

    /// <summary>The move, copy or removal failed; the original is still in place (see Reason).</summary>
    Failed,

    /// <summary>The store is over its quota or its drive is low on space (review B2 M4). The file is left in place.</summary>
    StoreFull,
}

/// <summary>Result of a quarantine attempt.</summary>
public sealed record QuarantineResult(QuarantineStatus Status, string Reason, QuarantineEntry? Entry = null)
{
    /// <summary>The alert action to report: Quarantined, or QuarantineFailed for every other status.</summary>
    public AlertAction Action => Status == QuarantineStatus.Quarantined ? AlertAction.Quarantined : AlertAction.QuarantineFailed;
}

/// <summary>Outcome of <see cref="IQuarantineService.RestoreAsync"/>.</summary>
public enum RestoreStatus
{
    Restored,
    StoreUnavailable,
    NotFound,
    Busy,

    /// <summary>The metadata failed its HMAC or validation: refused, nothing written.</summary>
    MetadataInvalid,

    /// <summary>The item isn't in the Quarantined state (an operation is in progress or needs recovery).</summary>
    NotRestorable,

    /// <summary>The stored copy doesn't decode to the recorded size and SHA-256.</summary>
    StoredContentInvalid,

    /// <summary>The original folder no longer exists (folders are never re-created).</summary>
    TargetDirectoryMissing,

    /// <summary>The original folder chain now contains a junction / symlink / mount point, or resolves elsewhere.</summary>
    TargetRedirected,

    /// <summary>The original name and every <c>name (restored N).ext</c> up to N = 99 exist.</summary>
    TargetExists,

    /// <summary>The target is a network drive or otherwise unsupported.</summary>
    UnsupportedTarget,

    Failed,
}

/// <summary>Result of a restore. <see cref="Notes"/> lists what couldn't be restored exactly (owner, DACL, MOTW).</summary>
public sealed record RestoreResult(RestoreStatus Status, string Reason, string? RestoredPath = null, IReadOnlyList<string>? Notes = null)
{
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? [];
}

/// <summary>Whether an entry's metadata verified.</summary>
public enum QuarantineEntryIntegrity
{
    Valid,

    /// <summary>The metadata failed the HMAC or validation; only <see cref="QuarantineEntry.Id"/> is meaningful.</summary>
    Invalid,
}

/// <summary>One quarantine item as shown to the UI (no key, no SDDL).</summary>
public sealed record QuarantineEntry(
    string Id,
    QuarantineEntryIntegrity Integrity,
    QuarantineState? State,
    string? OriginalPath,
    long? SizeBytes,
    string? Sha256,
    Verdict? Verdict,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> TechniqueIds,
    DateTimeOffset? QuarantinedAtUtc,
    Guid? AlertId,
    bool HasMarkOfTheWeb)
{
    internal static QuarantineEntry From(QuarantineMetadata m) => new(
        m.Id, QuarantineEntryIntegrity.Valid, m.State, m.OriginalPath, m.SizeBytes, m.Sha256, m.Verdict,
        m.Reasons.ToArray(), m.TechniqueIds.ToArray(), m.QuarantinedAtUtc, m.AlertId, m.ZoneIdentifier is not null);

    internal static QuarantineEntry Invalid(string id) =>
        new(id, QuarantineEntryIntegrity.Invalid, null, null, null, null, null, [], [], null, null, false);
}

/// <summary>What startup recovery did with one half-done item.</summary>
public sealed record QuarantineRecoveryAction(string Id, QuarantineState? FoundState, string Action);

/// <summary>
/// The reversible quarantine (ROADMAP B2). Implemented by <see cref="QuarantineManager"/>; fake it in tests of callers.
/// </summary>
public interface IQuarantineService
{
    /// <summary>True once the store is open, verified and recovered.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Quarantines exactly the file object that <paramref name="report"/> describes. The scanned path is opened with no
    /// reparse point anywhere (<see cref="SafeFile"/>), and must equal the final path the scan saw; the opened object must
    /// have the scanned volume serial + 128-bit file ID (<see cref="Core.Scanning.FileScanReport.Identity"/>), size and
    /// SHA-256. Never throws for file problems; see <see cref="QuarantineStatus"/>.
    /// </summary>
    /// <remarks>
    /// <b>Caller authorisation (B4).</b> The engine acts as SYSTEM. A request that comes from a user over the pipe must
    /// only be honoured if <i>that user</i> could delete the file: before calling this, the pipe server impersonates the
    /// client and checks that the client token is granted DELETE on the file (or DELETE_CHILD on its folder), and refuses
    /// otherwise. Engine-initiated quarantine (real-time / scan jobs acting on a Malicious verdict) needs no such check.
    /// </remarks>
    Task<QuarantineResult> QuarantineAsync(Core.Scanning.FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Quarantines through an already-open handle (the scan.s own handle, B3), so the file is never reopened by path.
    /// The handle must be open with read, DELETE and WRITE_DAC access and must deny writers (share Read | Delete); it
    /// must be the handle the scan used (its identity and final path are checked against <paramref name="report"/>).
    /// It is not closed; after success the file is gone and the handle only refers to a deleted file.
    /// </summary>
    /// <remarks>The B4 authorisation rule of <see cref="QuarantineAsync"/> applies here too.</remarks>
    Task<QuarantineResult> QuarantineHandleAsync(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle, Core.Scanning.FileScanReport report, Guid? alertId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Restores an item to its recorded original path only (explicit user request). Emits a QuarantineRestored alert.
    /// </summary>
    Task<RestoreResult> RestoreAsync(string itemId, CancellationToken cancellationToken = default);

    /// <summary>All items (invalid metadata is listed as <see cref="QuarantineEntryIntegrity.Invalid"/>).</summary>
    IReadOnlyList<QuarantineEntry> List();

    /// <summary>One item, or null if there is none with that ID.</summary>
    QuarantineEntry? Get(string itemId);
}
