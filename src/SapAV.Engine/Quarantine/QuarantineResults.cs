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

    /// <summary>The folder chain of the file's real location contains a reparse point.</summary>
    PathRedirected,

    /// <summary>The move, copy or removal failed; the original is still in place (see Reason).</summary>
    Failed,
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
    /// Quarantines exactly the file that <paramref name="report"/> describes (same size and SHA-256, checked on the
    /// writer-denied handle that is then moved). Never throws for file problems; see <see cref="QuarantineStatus"/>.
    /// </summary>
    Task<QuarantineResult> QuarantineAsync(Core.Scanning.FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Restores an item to its recorded original path only (explicit user request). Emits a QuarantineRestored alert.
    /// </summary>
    Task<RestoreResult> RestoreAsync(string itemId, CancellationToken cancellationToken = default);

    /// <summary>All items (invalid metadata is listed as <see cref="QuarantineEntryIntegrity.Invalid"/>).</summary>
    IReadOnlyList<QuarantineEntry> List();

    /// <summary>One item, or null if there is none with that ID.</summary>
    QuarantineEntry? Get(string itemId);
}
