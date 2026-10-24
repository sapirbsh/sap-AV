using System.Text.Json;
using System.Text.Json.Serialization;
using SapAV.Core.Models;
using SapAV.Core.Quarantine;
using SapAV.Core.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.Pipe;

// ---------------------------------------------------------------------------------------------------------------------
// Envelopes. Client -> engine: PipeRequest. Engine -> client: PipeFrame (a reply to a request, or an event).
// Clients send only IDs and paths; nothing a client sends is ever read as a scan report, file identity or result.
// ---------------------------------------------------------------------------------------------------------------------

[JsonConverter(typeof(StrictEnumConverter<PipeRequestKind>))]
public enum PipeRequestKind
{
    /// <summary>Must be the first request. Body: <see cref="HelloRequest"/>; reply: <see cref="HelloReply"/>.</summary>
    Hello,

    /// <summary>No body; reply: <see cref="EngineStatusReply"/>.</summary>
    GetStatus,

    /// <summary>Body: <see cref="ScanCreateRequest"/>; reply: <see cref="ScanCreateReply"/>. The job is Created, not started.</summary>
    ScanCreate,

    /// <summary>Body: <see cref="JobRequest"/>; reply: <see cref="JobActionReply"/>.</summary>
    ScanStart,

    ScanPause,

    ScanResume,

    ScanCancel,

    /// <summary>Body: <see cref="ScanGetRequest"/>; reply: <see cref="JobDetails"/> (one page of results).</summary>
    ScanGet,

    /// <summary>No body; reply: <see cref="ScanListReply"/> (only jobs the caller may see).</summary>
    ScanList,

    /// <summary>Body: <see cref="JobRequest"/>; reply: no body. Then <see cref="PipeEventKind"/> events for the job.</summary>
    Subscribe,

    Unsubscribe,

    /// <summary>No body; reply: <see cref="QuarantineListReply"/>.</summary>
    QuarantineList,

    /// <summary>Body: <see cref="QuarantineItemRequest"/>; reply: <see cref="QuarantineItemInfo"/>.</summary>
    QuarantineGet,

    /// <summary>Body: <see cref="QuarantineItemRequest"/>; reply: <see cref="RestoreReply"/>.</summary>
    QuarantineRestore,

    /// <summary>Body: <see cref="QuarantineFromResultRequest"/>; reply: <see cref="QuarantineFromResultReply"/>.</summary>
    QuarantineFromResult,
}

/// <param name="Id">Client-chosen request ID (positive), echoed in <see cref="PipeFrame.ReplyTo"/>.</param>
/// <param name="Body">The kind's body object, or absent.</param>
public sealed record PipeRequest(long Id, PipeRequestKind Kind, JsonElement? Body = null)
{
    public long Id { get; init; } = Id > 0 ? Id : throw new ArgumentOutOfRangeException(nameof(Id), Id, "Request IDs are positive.");
}

[JsonConverter(typeof(StrictEnumConverter<PipeFrameKind>))]
public enum PipeFrameKind
{
    Reply,
    Event,
}

/// <summary>The outcome of a request.</summary>
[JsonConverter(typeof(StrictEnumConverter<PipeStatus>))]
public enum PipeStatus
{
    Ok,

    /// <summary>The frame or its JSON was invalid (syntax, duplicate key, unknown member, wrong enum, bad value).</summary>
    BadRequest,

    /// <summary>The request was over <see cref="PipeProtocol.MaxRequestBytes"/>.</summary>
    TooLarge,

    /// <summary>The first request must be a successful Hello.</summary>
    HelloRequired,

    UnsupportedVersion,

    /// <summary>No such job / result / item, or the caller may not see it (the two are not told apart).</summary>
    NotFound,

    /// <summary>The caller's own token lacks the access the action needs.</summary>
    AccessDenied,

    /// <summary>A path was refused by the scan path policy or is on a network drive.</summary>
    InvalidPath,

    /// <summary>The job or item isn't in a state that allows the action.</summary>
    InvalidState,

    /// <summary>A per-user or engine cap was reached (jobs, connections, subscriptions).</summary>
    LimitReached,

    RateLimited,

    /// <summary>A required engine part (e.g. the quarantine store) isn't available.</summary>
    Unavailable,

    Failed,
}

[JsonConverter(typeof(StrictEnumConverter<PipeEventKind>))]
public enum PipeEventKind
{
    /// <summary>Body: <see cref="JobStateEvent"/>.</summary>
    JobState,

    /// <summary>Body: <see cref="JobProgressInfo"/>.</summary>
    JobProgress,

    /// <summary>Body: <see cref="JobFileResultEvent"/>.</summary>
    JobFileResult,

    /// <summary>Body: <see cref="EventsDroppedEvent"/>. The client fell behind; resync with ScanGet.</summary>
    EventsDropped,
}

/// <summary>One engine frame. Reply: <see cref="ReplyTo"/> + <see cref="Status"/>; Event: <see cref="Event"/>.</summary>
/// <param name="ReplyTo">The request ID (null when the request couldn't be parsed far enough to know it).</param>
/// <param name="Error">Engine text explaining a non-Ok status.</param>
public sealed record PipeFrame(
    PipeFrameKind Kind, long? ReplyTo = null, PipeStatus? Status = null, string? Error = null, PipeEventKind? Event = null,
    JsonElement? Body = null);

// ---------------------------------------------------------------------------------------------------------------------
// Shared value types
// ---------------------------------------------------------------------------------------------------------------------

/// <summary>
/// A path as the engine saw it, untrusted. <see cref="Value"/> is the exact path (controls replaced by U+FFFD, nothing
/// else changed: evidence). A UI must always show it isolated (FSI ... PDI) or escaped; <see cref="HasHiddenCharacters"/>
/// says it contains bidi controls or invisible format characters, so the UI should also warn.
/// </summary>
public sealed record WirePath(string Value, bool HasHiddenCharacters)
{
    public static WirePath From(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string value = SafeText.Identifier(path);
        return new WirePath(value, SafeText.ContainsHiddenCharacters(value) || value.Contains('�'));
    }
}

[JsonConverter(typeof(StrictEnumConverter<JobState>))]
public enum JobState
{
    Created,
    Running,
    Pausing,
    Paused,
    Cancelling,
    Completed,
    Cancelled,
    TimedOut,
    Failed,
}

[JsonConverter(typeof(StrictEnumConverter<FileAction>))]
public enum FileAction
{
    None,
    Quarantined,
    QuarantineFailed,
    NeedsUserConfirmation,
    StoreFull,
}

[JsonConverter(typeof(StrictEnumConverter<QuarantineOutcome>))]
public enum QuarantineOutcome
{
    Quarantined,
    NotEligible,
    StoreUnavailable,
    Busy,
    NotFound,
    Locked,
    AccessDenied,
    NotRegularFile,
    ContentChanged,
    MultipleHardLinks,
    UnsupportedLocation,
    PathRedirected,
    IdentityMismatch,
    Failed,
    StoreFull,
    EngineFolder,
}

[JsonConverter(typeof(StrictEnumConverter<RestoreOutcome>))]
public enum RestoreOutcome
{
    Restored,
    StoreUnavailable,
    NotFound,
    Busy,
    MetadataInvalid,
    NotRestorable,
    StoredContentInvalid,
    TargetDirectoryMissing,
    TargetRedirected,
    TargetExists,
    UnsupportedTarget,
    Failed,
}

[JsonConverter(typeof(StrictEnumConverter<QuarantineIntegrity>))]
public enum QuarantineIntegrity
{
    Valid,
    Invalid,
}

// ---------------------------------------------------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------------------------------------------------

/// <param name="ClientName">Free text for the engine log (capped, sanitised).</param>
public sealed record HelloRequest(int MinVersion, int MaxVersion, string? ClientName = null);

public sealed record ClientInfo(string UserSid, int SessionId, bool IsAdmin);

public sealed record PipeLimits(int MaxRequestBytes, int MaxScanPaths, int MaxResultsPage, int MaxPendingJobs, int MaxActiveJobs, int MaxSubscriptions);

public sealed record HelloReply(int Version, string EngineVersion, ClientInfo Client, PipeLimits Limits);

public sealed record EngineStatusReply(string EngineVersion, bool QuarantineAvailable, int VisibleJobs, int RunningJobs);

public sealed record ScanCreateRequest(IReadOnlyList<string> Paths);

/// <param name="Paths">The normalised paths the job will scan.</param>
public sealed record ScanCreateReply(Guid JobId, IReadOnlyList<WirePath> Paths);

public sealed record JobRequest(Guid JobId);

public sealed record JobActionReply(Guid JobId, JobState State);

public sealed record ScanGetRequest(Guid JobId, int ResultsOffset = 0, int ResultsLimit = 100)
{
    public int ResultsOffset { get; init; } = ResultsOffset >= 0
        ? ResultsOffset
        : throw new ArgumentOutOfRangeException(nameof(ResultsOffset), ResultsOffset, "The offset can't be negative.");

    public int ResultsLimit { get; init; } = ResultsLimit is >= 0 and <= PipeProtocol.MaxResultsPage
        ? ResultsLimit
        : throw new ArgumentOutOfRangeException(nameof(ResultsLimit), ResultsLimit, $"The page size is 0-{PipeProtocol.MaxResultsPage}.");
}

/// <param name="OwnedByCaller">The caller created the job (admins also see other jobs).</param>
public sealed record JobSummary(Guid JobId, JobState State, ScanTrigger Trigger, DateTimeOffset CreatedAt, IReadOnlyList<WirePath> Paths, bool OwnedByCaller);

public sealed record JobCountersInfo(
    long Clean, long Suspicious, long Malicious, long NotScanned, long Excluded, long Quarantined, long NeedsUserConfirmation, long QuarantineFailed);

public sealed record JobProgressInfo(
    Guid JobId, JobState State, long FilesFound, long? FilesTotal, long FilesDone, long BytesDone, long? BytesTotal,
    WirePath? CurrentFile, TimeSpan? Eta, TimeSpan Elapsed, JobCountersInfo Counters);

/// <param name="ResultId">Stable index of the result in its job (results are only ever appended).</param>
/// <param name="Detail">Engine text only (never scan-worker text), sanitised and capped.</param>
/// <param name="CanQuarantine">The engine kept what it needs to quarantine this file on request (QuarantineFromResult).</param>
public sealed record JobFileResultInfo(
    int ResultId, WirePath Path, ScanStatus Status, Verdict? Verdict, FileAction Action, string? Detail, string? Sha256,
    string? QuarantineItemId, Guid? AlertId, bool CanQuarantine);

/// <param name="NextResultsOffset">The offset of the next page, or null when this page reached the end.</param>
public sealed record JobDetails(
    JobSummary Summary, JobProgressInfo Progress, IReadOnlyList<JobFileResultInfo> Results, int? NextResultsOffset,
    long ResultsOmitted, IReadOnlyList<string> Warnings, long SkippedLinks, long UnreadableFolders);

public sealed record ScanListReply(IReadOnlyList<JobSummary> Jobs);

public sealed record QuarantineItemRequest(string ItemId);

public sealed record QuarantineItemInfo(
    string Id, QuarantineIntegrity Integrity, QuarantineState? State, WirePath? OriginalPath, long? SizeBytes, string? Sha256,
    Verdict? Verdict, IReadOnlyList<string> Reasons, IReadOnlyList<string> TechniqueIds, DateTimeOffset? QuarantinedAtUtc,
    Guid? AlertId, bool HasMarkOfTheWeb);

public sealed record QuarantineListReply(IReadOnlyList<QuarantineItemInfo> Items);

public sealed record RestoreReply(RestoreOutcome Status, string Reason, WirePath? RestoredPath, IReadOnlyList<string> Notes);

public sealed record QuarantineFromResultRequest(Guid JobId, int ResultId);

public sealed record QuarantineFromResultReply(QuarantineOutcome Status, string Reason, string? ItemId);

public sealed record JobStateEvent(Guid JobId, JobState From, JobState To, DateTimeOffset Timestamp);

public sealed record JobFileResultEvent(Guid JobId, JobFileResultInfo Result);

public sealed record EventsDroppedEvent(long Count);
