using System.Text.Json;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Pipe;

/// <summary>A reply to one request (the body is serialized by the connection).</summary>
internal readonly record struct PipeReply(PipeStatus Status, object? Body = null, string? Error = null)
{
    public static PipeReply Ok(object? body = null) => new(PipeStatus.Ok, body);

    public static PipeReply Fail(PipeStatus status, string error) => new(status, null, error);
}

/// <summary>
/// Protocol v1 requests → engine calls, with the authorization rules (B4). Every request is hostile until checked:
/// <list type="bullet">
/// <item><b>Paths</b> must pass <see cref="ScanPathPolicy"/>, must not be on a network drive, and a standard user must be able
/// to read/list each root (AccessCheck with the client's token against the object the engine opens); the job then lists and
/// scans only what that user can read (<see cref="ClientScanAccess"/>). Administrators scan anything.</item>
/// <item><b>Jobs</b>: a client sees and controls only jobs its user created, unless it is an administrator
/// (<see cref="JobRegistry"/>); an invisible job is reported NotFound, like a missing one.</item>
/// <item><b>Quarantine a result</b>: by job + result ID only (the engine's own report); a standard user needs DELETE on the
/// file or FILE_DELETE_CHILD on its folder.</item>
/// <item><b>Restore</b>: an administrator, or a user with FILE_ADD_FILE on the original folder.</item>
/// <item><b>Quarantine list/get</b>: an administrator, or a user who can list the item's original folder.</item>
/// <item><b>Caps</b>: request rate per user, pending / active jobs per user, pending jobs in total, subscriptions.</item>
/// </list>
/// Malformed bodies (<see cref="JsonException"/>, model <see cref="ArgumentException"/>s) become BadRequest replies.
/// </summary>
internal sealed class PipeRequestHandler
{
    private readonly IScanJobService _jobs;
    private readonly IQuarantineService? _quarantine;
    private readonly JobRegistry _registry;
    private readonly UserRateLimiter _rate;
    private readonly PipeServerOptions _options;
    private readonly ILogger _logger;
    private readonly Func<string, int> _driveType;

    public PipeRequestHandler(
        IScanJobService jobs, IQuarantineService? quarantine, PipeServerOptions options, TimeProvider time, ILogger logger,
        Func<string, int>? driveType = null)
    {
        _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
        _quarantine = quarantine;
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _registry = new JobRegistry(jobs, options, time);
        _rate = new UserRateLimiter(time, options.RequestsPerSecond, options.RequestBurst);
        _driveType = driveType ?? PipeNative.DriveType;
    }

    internal JobRegistry Registry => _registry;

    public PipeLimits Limits => new(PipeProtocol.MaxRequestBytes, PipeProtocol.MaxScanPaths, PipeProtocol.MaxResultsPage,
        _options.MaxPendingJobsPerUser, _options.MaxActiveJobsPerUser, _options.MaxSubscriptionsPerConnection);

    public async Task<PipeReply> HandleAsync(PipeSession session, PipeRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(request);
        if (!_rate.TryAcquire(session.Identity.User))
        {
            return PipeReply.Fail(PipeStatus.RateLimited, "Too many requests; slow down.");
        }

        if (!session.HelloDone && request.Kind != PipeRequestKind.Hello)
        {
            return PipeReply.Fail(PipeStatus.HelloRequired, "Send Hello first.");
        }

        try
        {
            return request.Kind switch
            {
                PipeRequestKind.Hello => Hello(session, PipeJson.Body<HelloRequest>(request.Body)),
                PipeRequestKind.GetStatus => NoBody(request) ?? Status(session),
                PipeRequestKind.ScanCreate => Create(session, PipeJson.Body<ScanCreateRequest>(request.Body)),
                PipeRequestKind.ScanStart => Start(session, PipeJson.Body<JobRequest>(request.Body)),
                PipeRequestKind.ScanPause => Control(session, PipeJson.Body<JobRequest>(request.Body), _jobs.Pause),
                PipeRequestKind.ScanResume => Control(session, PipeJson.Body<JobRequest>(request.Body), _jobs.Resume),
                PipeRequestKind.ScanCancel => Control(session, PipeJson.Body<JobRequest>(request.Body), _jobs.Cancel),
                PipeRequestKind.ScanGet => Get(session, PipeJson.Body<ScanGetRequest>(request.Body)),
                PipeRequestKind.ScanList => NoBody(request) ?? List(session),
                PipeRequestKind.Subscribe => Subscribe(session, PipeJson.Body<JobRequest>(request.Body)),
                PipeRequestKind.Unsubscribe => session.Unsubscribe(PipeJson.Body<JobRequest>(request.Body).JobId)
                    ? PipeReply.Ok()
                    : PipeReply.Fail(PipeStatus.NotFound, "Not subscribed to that job."),
                PipeRequestKind.QuarantineList => NoBody(request) ?? QuarantineList(session),
                PipeRequestKind.QuarantineGet => QuarantineGet(session, PipeJson.Body<QuarantineItemRequest>(request.Body)),
                PipeRequestKind.QuarantineRestore =>
                    await RestoreAsync(session, PipeJson.Body<QuarantineItemRequest>(request.Body), cancellationToken).ConfigureAwait(false),
                PipeRequestKind.QuarantineFromResult =>
                    await QuarantineFromResultAsync(session, PipeJson.Body<QuarantineFromResultRequest>(request.Body), cancellationToken)
                        .ConfigureAwait(false),
                _ => PipeReply.Fail(PipeStatus.BadRequest, "Unknown request."),
            };
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException)
        {
            return PipeReply.Fail(PipeStatus.BadRequest, PipeMapping.Text(ex.Message));
        }
    }

    /// <summary>The connection ended.</summary>
    public void Disconnected(PipeSession session) => _registry.CancelPendingOf(session);

    private static PipeReply? NoBody(PipeRequest request) =>
        request.Body is null or { ValueKind: JsonValueKind.Null } ? null : PipeReply.Fail(PipeStatus.BadRequest, $"{request.Kind} takes no body.");

    // ---- Hello / status ----

    private PipeReply Hello(PipeSession session, HelloRequest hello)
    {
        if (session.HelloDone)
        {
            return PipeReply.Fail(PipeStatus.BadRequest, "Hello was already done.");
        }

        if (hello.MinVersion > PipeProtocol.Version || hello.MaxVersion < PipeProtocol.Version || hello.MinVersion > hello.MaxVersion)
        {
            return PipeReply.Fail(PipeStatus.UnsupportedVersion, $"The engine speaks protocol version {PipeProtocol.Version} only.");
        }

        session.HelloDone = true;
        var id = session.Identity;
        _logger.LogInformation("Pipe client hello: user {User}, session {Session}, process {Pid}, admin {IsAdmin}, client '{Client}'.",
            id.User.Value, id.SessionId, id.ProcessId, id.IsAdmin, PipeMapping.Text(hello.ClientName, 64));
        return PipeReply.Ok(new HelloReply(PipeProtocol.Version, EngineInfo.Version, new ClientInfo(id.User.Value, id.SessionId, id.IsAdmin), Limits));
    }

    private PipeReply Status(PipeSession session)
    {
        var visible = _registry.Visible(session.Identity);
        return PipeReply.Ok(new EngineStatusReply(EngineInfo.Version, _quarantine?.IsAvailable ?? false, visible.Count,
            visible.Count(j => j.State is ScanJobState.Running or ScanJobState.Pausing or ScanJobState.Paused)));
    }

    // ---- Scan jobs ----

    private PipeReply Create(PipeSession session, ScanCreateRequest request)
    {
        var client = session.Identity;
        if (request.Paths.Count is 0 or > PipeProtocol.MaxScanPaths)
        {
            return PipeReply.Fail(PipeStatus.BadRequest, $"A scan needs 1-{PipeProtocol.MaxScanPaths} paths.");
        }

        var roots = new List<string>();
        for (int i = 0; i < request.Paths.Count; i++)
        {
            if (CheckRoot(client, request.Paths[i], i, out string normalized) is { } refused)
            {
                return refused;
            }

            if (!roots.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                roots.Add(normalized);
            }
        }

        var access = client.IsAdmin ? null : new ClientScanAccess(client.Duplicate());
        var (job, status, error) = _registry.TryCreate(client, session, new ScanJobRequest(roots, ScanTrigger.CustomScan), access);
        if (job is null)
        {
            return PipeReply.Fail(status, error);
        }

        _logger.LogInformation("Pipe: user {User} created scan job {JobId} ({Count} path(s), {Mode}).", client.User.Value, job.Id, roots.Count,
            client.IsAdmin ? "administrator" : "requester's access");
        return PipeReply.Ok(new ScanCreateReply(job.Id, roots.Select(WirePath.From).ToArray()));
    }

    /// <summary>Policy, drive type and (standard users) the client's own read access to the root.</summary>
    private PipeReply? CheckRoot(IClientIdentity client, string? path, int index, out string normalized)
    {
        normalized = string.Empty;
        var decision = ScanPathPolicy.Evaluate(path);
        if (!decision.IsAllowed)
        {
            return PipeReply.Fail(PipeStatus.InvalidPath, $"Path {index + 1}: {decision.Reason}");
        }

        normalized = decision.NormalizedPath!;
        string drive = Core.Hashing.ExactPath.StripPrefix(normalized)[..3];
        if (_driveType(drive) == PipeNative.DriveRemote)
        {
            return PipeReply.Fail(PipeStatus.InvalidPath, $"Path {index + 1}: network drives are not scanned.");
        }

        if (client.IsAdmin)
        {
            return null;
        }

        return ClientAccess.CanReadOrList(client, normalized) switch
        {
            AccessDecision.Granted => null,
            AccessDecision.NotFound => PipeReply.Fail(PipeStatus.NotFound, $"Path {index + 1} does not exist."),
            _ => PipeReply.Fail(PipeStatus.AccessDenied, $"Path {index + 1}: you don't have read access to it."),
        };
    }

    private PipeReply Start(PipeSession session, JobRequest request)
    {
        if (_registry.Find(session.Identity, request.JobId) is not { } job)
        {
            return JobNotFound();
        }

        return _jobs.Start(job.Id) switch
        {
            ScanJobStartResult.Started => PipeReply.Ok(new JobActionReply(job.Id, PipeMapping.Map(job.State))),
            ScanJobStartResult.AlreadyStarted => PipeReply.Fail(PipeStatus.InvalidState, "The job was already started or cancelled."),
            ScanJobStartResult.TooManyJobs => PipeReply.Fail(PipeStatus.LimitReached, "The engine is running its maximum number of scans; try again later."),
            _ => JobNotFound(),
        };
    }

    private PipeReply Control(PipeSession session, JobRequest request, Func<Guid, bool> action)
    {
        if (_registry.Find(session.Identity, request.JobId) is not { } job)
        {
            return JobNotFound();
        }

        return action(job.Id)
            ? PipeReply.Ok(new JobActionReply(job.Id, PipeMapping.Map(job.State)))
            : PipeReply.Fail(PipeStatus.InvalidState, $"Not possible while the job is {job.State}.");
    }

    private PipeReply Get(PipeSession session, ScanGetRequest request)
    {
        if (_registry.Find(session.Identity, request.JobId) is not { } job)
        {
            return JobNotFound();
        }

        var results = job.Results;
        int limit = request.ResultsLimit;
        while (true)
        {
            var page = results.Skip(request.ResultsOffset).Take(limit).Select((r, i) => PipeMapping.Result(request.ResultsOffset + i, r)).ToArray();
            int end = request.ResultsOffset + page.Length;
            var (links, unreadable) = job.Skipped;
            var details = new JobDetails(
                PipeMapping.Summary(job, _registry.IsOwner(session.Identity, job.Id)), PipeMapping.Progress(job.GetProgress()), page,
                end < results.Count ? end : null, job.ResultsOmitted,
                job.Warnings.Take(PipeMapping.MaxWarnings).Select(w => PipeMapping.Text(w.Message, 512)).ToArray(), links, unreadable);

            // Long paths can make a page big: halve it until the frame fits (one result always fits).
            if (limit <= 1 || JsonSerializer.SerializeToUtf8Bytes(details, PipeJson.Options).Length <= PipeProtocol.MaxServerFrameBytes - 4096)
            {
                return PipeReply.Ok(details);
            }

            limit /= 2;
        }
    }

    private PipeReply List(PipeSession session) =>
        PipeReply.Ok(new ScanListReply(_registry.Visible(session.Identity)
            .Select(j => PipeMapping.Summary(j, _registry.IsOwner(session.Identity, j.Id))).ToArray()));

    private PipeReply Subscribe(PipeSession session, JobRequest request)
    {
        if (_registry.Find(session.Identity, request.JobId) is not { } job)
        {
            return JobNotFound();
        }

        return session.Subscribe(job, _options.MaxSubscriptionsPerConnection)
            ? PipeReply.Ok()
            : PipeReply.Fail(PipeStatus.LimitReached, $"At most {_options.MaxSubscriptionsPerConnection} subscriptions per connection.");
    }

    private static PipeReply JobNotFound() => PipeReply.Fail(PipeStatus.NotFound, "No such scan job.");

    // ---- Quarantine ----

    private bool CanSeeItem(IClientIdentity client, QuarantineEntry entry) =>
        client.IsAdmin
        || (entry.Integrity == QuarantineEntryIntegrity.Valid && entry.OriginalPath is { } original
            && ClientAccess.ParentOf(original) is { } folder && ClientAccess.CanReadOrList(client, folder) == AccessDecision.Granted);

    private PipeReply QuarantineList(PipeSession session)
    {
        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return PipeReply.Fail(PipeStatus.Unavailable, "The quarantine is not available.");
        }

        return PipeReply.Ok(new QuarantineListReply(quarantine.List().Where(e => CanSeeItem(session.Identity, e)).Select(PipeMapping.Item).ToArray()));
    }

    private PipeReply QuarantineGet(PipeSession session, QuarantineItemRequest request)
    {
        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return PipeReply.Fail(PipeStatus.Unavailable, "The quarantine is not available.");
        }

        return quarantine.Get(request.ItemId) is { } entry && CanSeeItem(session.Identity, entry)
            ? PipeReply.Ok(PipeMapping.Item(entry))
            : PipeReply.Fail(PipeStatus.NotFound, "No such quarantine item.");
    }

    private async Task<PipeReply> RestoreAsync(PipeSession session, QuarantineItemRequest request, CancellationToken cancellationToken)
    {
        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return PipeReply.Fail(PipeStatus.Unavailable, "The quarantine is not available.");
        }

        var client = session.Identity;
        if (quarantine.Get(request.ItemId) is not { } entry || !CanSeeItem(client, entry))
        {
            return PipeReply.Fail(PipeStatus.NotFound, "No such quarantine item.");
        }

        if (!client.IsAdmin && (entry.OriginalPath is null || ClientAccess.CanAddFileNextTo(client, entry.OriginalPath) != AccessDecision.Granted))
        {
            return PipeReply.Fail(PipeStatus.AccessDenied, "You may not create files in the original folder; ask an administrator to restore it.");
        }

        var result = await quarantine.RestoreAsync(entry.Id, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Pipe: user {User} restored quarantine item {Item}: {Status}.", client.User.Value, entry.Id, result.Status);
        return PipeReply.Ok(PipeMapping.Restore(result));
    }

    private async Task<PipeReply> QuarantineFromResultAsync(PipeSession session, QuarantineFromResultRequest request, CancellationToken cancellationToken)
    {
        var client = session.Identity;
        if (_registry.Find(client, request.JobId) is not { } job || job.ResultAt(request.ResultId) is not { } result)
        {
            return PipeReply.Fail(PipeStatus.NotFound, "No such scan result.");
        }

        if (result.Report is not { } report)
        {
            return PipeReply.Fail(PipeStatus.InvalidState, "This result can't be quarantined (it is clean, not scanned, or already quarantined).");
        }

        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return PipeReply.Fail(PipeStatus.Unavailable, "The quarantine is not available.");
        }

        if (!client.IsAdmin)
        {
            switch (ClientAccess.CanDelete(client, report))
            {
                case AccessDecision.Granted:
                    break;
                case AccessDecision.NotFound:
                    return PipeReply.Ok(new QuarantineFromResultReply(QuarantineOutcome.NotFound, "The file is gone.", null));
                case AccessDecision.Mismatch:
                    return PipeReply.Ok(new QuarantineFromResultReply(QuarantineOutcome.IdentityMismatch,
                        "A different file is at that path now; scan it again.", null));
                default:
                    return PipeReply.Fail(PipeStatus.AccessDenied, "You may not delete this file, so you can't quarantine it; ask an administrator.");
            }
        }

        var outcome = await quarantine.QuarantineAsync(report, result.AlertId, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Pipe: user {User} asked to quarantine result {ResultId} of job {JobId}: {Status}.",
            client.User.Value, request.ResultId, job.Id, outcome.Status);
        return PipeReply.Ok(new QuarantineFromResultReply(PipeMapping.Map(outcome.Status), PipeMapping.Text(outcome.Reason), outcome.Entry?.Id));
    }
}
