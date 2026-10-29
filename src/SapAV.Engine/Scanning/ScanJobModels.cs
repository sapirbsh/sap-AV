using SapAV.Core.Models;

namespace SapAV.Engine.Scanning;

/// <summary>
/// "Scan these files and folders" (B3). Folders are walked recursively; junctions, symlinks and other name-surrogate
/// reparse points are skipped. Engine-internal only: B4 builds requests from pipe input after C1's ScanPathPolicy.
/// </summary>
/// <param name="Paths">Fully qualified file or folder paths (at least one).</param>
/// <param name="Trigger">Why the scan runs (Custom, Quick, Full, ...).</param>
/// <param name="TimeBudget">Overrides <see cref="ScanJobOptions.TimeBudget"/> for this job.</param>
public sealed record ScanJobRequest(IReadOnlyList<string> Paths, ScanTrigger Trigger, TimeSpan? TimeBudget = null)
{
    /// <summary>
    /// The requester's access (B4): set for jobs a standard user asked for over the pipe, so the job lists and scans only
    /// what that user can read. Null = scan everything (engine-initiated jobs, administrators).
    /// </summary>
    internal IScanAccessCheck? Access { get; init; }

    /// <summary>Who asked (review B H3): capacity reservation, the pause / orphan limits and the worker priority depend on it.</summary>
    internal ScanJobOrigin Origin { get; init; } = ScanJobOrigin.Engine;

    /// <summary>
    /// A2 W-A: scan files and folders on remote file systems (UNC paths, network drives, objects that report themselves
    /// remote). Off by default: remote objects are refused before they are opened where possible, and reported NotScanned
    /// (<see cref="ScanSkipReason.RemoteFile"/>) when they turn out remote after the open. The pipe sets it only for an
    /// administrator who asked for it.
    /// </summary>
    internal bool AllowRemoteFiles { get; init; }

    /// <summary>
    /// Section B M1 / M2: whose budget the job's alerts, auto-quarantines and quarantine quota count against. Null =
    /// the engine's own (per trigger). The pipe sets the requesting user.
    /// </summary>
    internal System.Security.Principal.SecurityIdentifier? Requester { get; init; }

    /// <exception cref="ArgumentException">No paths, or a path that isn't fully qualified.</exception>
    /// <summary>
    /// C4: run these checks in order instead of walking <see cref="Paths"/> (Quick Scan: processes → persistence → folders →
    /// recent files; Full Scan in C6). <see cref="Paths"/> may then be empty.
    /// </summary>
    internal IReadOnlyList<Checks.IScanCheck>? Checks { get; init; }

    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Paths);
        if (Checks is { Count: > 0 } checks)
        {
            if (checks.Any(c => c is null))
            {
                throw new ArgumentException("A scan check is null.", nameof(Checks));
            }
        }
        else if (Paths.Count == 0)
        {
            throw new ArgumentException("A scan job needs at least one path.", nameof(Paths));
        }

        foreach (var path in Paths)
        {
            if (string.IsNullOrWhiteSpace(path) || path.Contains('\0') || !Path.IsPathFullyQualified(path))
            {
                throw new ArgumentException($"Scan paths must be fully qualified: '{path}'.", nameof(Paths));
            }
        }

        if (!Enum.IsDefined(Trigger))
        {
            throw new ArgumentOutOfRangeException(nameof(Trigger), Trigger, "Undefined scan trigger.");
        }

        if (TimeBudget is { } budget && budget <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(TimeBudget), budget, "The time budget must be positive.");
        }
    }
}

/// <summary>Who created a scan job (review B H3).</summary>
public enum ScanJobOrigin
{
    /// <summary>The engine itself (scheduled, startup, later real-time follow-ups): highest worker priority.</summary>
    Engine,

    /// <summary>An administrator over the pipe.</summary>
    Administrator,

    /// <summary>A standard user over the pipe: at most <see cref="ScanJobOptions.MaxRunningStandardUserJobs"/> run at once.</summary>
    StandardUser,
}

/// <summary>What the job did with a file after the scan.</summary>
public enum ScanFileAction
{
    /// <summary>Nothing to do (Clean, Suspicious, not scanned), or nothing allowed (Suspicious and PUP are never auto-quarantined).</summary>
    None,

    Quarantined,

    /// <summary>Quarantine was tried and refused or failed; the file is in place (see <see cref="ScanJobFileResult.Detail"/>).</summary>
    QuarantineFailed,

    /// <summary>Malicious, but auto-quarantine is not allowed here (protected location, owner, rate limit): the user decides.</summary>
    NeedsUserConfirmation,

    /// <summary>Malicious, but the quarantine store is full (quota or free-space floor).</summary>
    StoreFull,
}

/// <summary>One file's outcome in a job.</summary>
/// <param name="Path">The scanned path.</param>
/// <param name="Status">Scan status (anything but Scanned = no verdict).</param>
/// <param name="Verdict">The verdict, if scanned.</param>
/// <param name="Action">What happened after the scan.</param>
/// <param name="Detail">Why (for NotScanned, refusals and failures), engine text only.</param>
/// <param name="Sha256">The SHA-256, if computed.</param>
/// <param name="QuarantineItemId">The quarantine item, when quarantined.</param>
/// <param name="AlertId">The alert raised for the file, if any.</param>
public sealed record ScanJobFileResult(
    string Path, ScanStatus Status, Verdict? Verdict, ScanFileAction Action, string? Detail, string? Sha256,
    string? QuarantineItemId, Guid? AlertId)
{
    /// <summary>
    /// The engine's own report, kept only for flagged files that are still in place (Scanned, not Clean, not quarantined,
    /// with a file identity), so the user can ask to quarantine the file by result ID (B4). Never sent to or read from a client.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    internal Core.Scanning.FileScanReport? Report { get; init; }

    /// <summary>True if the file can be quarantined on request (<see cref="Report"/> is kept).</summary>
    public bool CanQuarantine => Report is not null;

    /// <summary>
    /// The detections, worst first (C1, for the results screen). Their reasons are scan-worker text: the pipe sends them
    /// only to administrators and builds engine templates for everyone else (<see cref="Pipe.PipeMapping"/>).
    /// </summary>
    public IReadOnlyList<Core.Models.Detection> Detections { get; init; } = [];

    /// <summary>The Authenticode outcome, if the signature was checked.</summary>
    public Core.Signatures.SignatureStatus? SignatureStatus { get; init; }

    /// <summary>The trusted signer's name (only with a Microsoft / OtherTrusted signature), scan-worker text.</summary>
    public string? Signer { get; init; }

    /// <summary>The Mark-of-the-Web download URL in log form (<see cref="Core.Motw.MarkOfTheWeb.SanitizeUrlForLog"/>), or null.</summary>
    public string? SourceUrl { get; init; }

    /// <summary>Why the file wasn't scanned (null when it was), engine-classified.</summary>
    public ScanSkipReason? SkipReason { get; init; }

    /// <summary>
    /// C1 / B4 L3: false when the job runs with a requester's access and that user could not read the file (or it could not
    /// be checked). Such a result carries nothing about the file: no hash, verdict or details.
    /// </summary>
    public bool RequesterCouldRead { get; init; } = true;

    /// <summary>C5: the verdict came from the scan cache (the file was unchanged since an earlier scan), not a fresh scan.</summary>
    public bool FromCache { get; init; }
}

/// <summary>Why a file wasn't scanned (C1), as the engine classified it. Never derived from scan-worker text.</summary>
public enum ScanSkipReason
{
    /// <summary>
    /// B4 L3: the requester can't read the file, or it couldn't be checked. Deliberately says nothing else (whether it
    /// exists, is locked, too large, excluded, or reached a different file).
    /// </summary>
    NoAccess,

    AccessDenied,
    Locked,
    TooLarge,
    Offline,
    NotFound,

    /// <summary>A directory, device, refused link, or another object that isn't a regular file.</summary>
    NotRegularFile,

    /// <summary>A2 W-A: the opened object is on a remote file system and the job doesn't allow remote files.</summary>
    RemoteFile,

    /// <summary>B3 H1: the open reached a different file than the one requested.</summary>
    DifferentFile,

    /// <summary>The file changed while it was being scanned.</summary>
    ChangedDuringScan,

    /// <summary>Another antivirus blocked the read.</summary>
    BlockedByAntivirus,

    Error,
}

/// <summary>Exact counters of a job (results lists may be capped; these never are).</summary>
public sealed record ScanJobCounters(
    long Clean, long Suspicious, long Malicious, long NotScanned, long Excluded, long Quarantined, long NeedsUserConfirmation,
    long QuarantineFailed)
{
    /// <summary>C5: files whose verdict came from the scan cache (also counted under their verdict).</summary>
    public long Cached { get; init; }
}

/// <summary>A progress snapshot (B4 streams these).</summary>
/// <param name="FilesFound">Files enumerated so far.</param>
/// <param name="FilesTotal">Total files, or null while still enumerating.</param>
/// <param name="FilesDone">Files handled (scanned, not scanned, or excluded).</param>
/// <param name="BytesTotal">Total bytes (from enumeration), or null while still enumerating.</param>
/// <param name="CurrentFile">A file being scanned right now, if any.</param>
/// <param name="Eta">Estimated time left from the smoothed throughput, or null while unknown.</param>
public sealed record ScanJobProgress(
    Guid JobId, ScanJobState State, long FilesFound, long? FilesTotal, long FilesDone, long BytesDone, long? BytesTotal,
    string? CurrentFile, TimeSpan? Eta, TimeSpan Elapsed, ScanJobCounters Counters)
{
    /// <summary>C4: the running phase of a multi-phase job (Quick Scan); null for a plain file / folder job.</summary>
    public ScanPhaseProgress? Phase { get; init; }
}

/// <summary>Which phase of a multi-phase job is running.</summary>
/// <param name="Index">0-based.</param>
public sealed record ScanPhaseProgress(string Name, int Index, int Count);

/// <summary>A job-level warning (rules missing, store full, budget, ...), engine text only.</summary>
public sealed record ScanJobWarning(DateTimeOffset Timestamp, string Message);

/// <summary>A state change of a job.</summary>
public sealed record ScanJobStateChange(Guid JobId, ScanJobState From, ScanJobState To, DateTimeOffset Timestamp);

/// <summary>Result of <see cref="IScanJobService.Start"/>.</summary>
public enum ScanJobStartResult
{
    Started,
    NotFound,

    /// <summary>The job isn't in the Created state.</summary>
    AlreadyStarted,

    /// <summary><see cref="ScanJobOptions.MaxConcurrentJobs"/> jobs are running.</summary>
    TooManyJobs,
}
