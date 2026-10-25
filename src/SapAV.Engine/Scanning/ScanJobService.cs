using Microsoft.Extensions.Options;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Scanning;

/// <summary>Creates and controls scan jobs (B3). B4 maps pipe commands onto this; fake it in tests of callers.</summary>
public interface IScanJobService
{
    /// <summary>Raised for every new job (subscribe to its events here to stream them).</summary>
    event Action<ScanJob>? JobCreated;

    /// <exception cref="ArgumentException">The request is invalid.</exception>
    ScanJob Create(ScanJobRequest request);

    ScanJobStartResult Start(Guid jobId);

    bool Pause(Guid jobId);

    bool Resume(Guid jobId);

    bool Cancel(Guid jobId);

    ScanJob? Get(Guid jobId);

    IReadOnlyList<ScanJob> List();
}

/// <summary>
/// The engine's <see cref="IScanJobService"/>: at most <see cref="ScanJobOptions.MaxConcurrentJobs"/> running jobs, the last
/// <see cref="ScanJobOptions.MaxRetainedJobs"/> finished ones kept. Every job dispatches to the shared <see cref="IScanBroker"/>
/// (files are parsed only in the sandboxed worker) and shares one <see cref="IScanVerdictHandler"/> (alerts, quarantine).
/// </summary>
public sealed class ScanJobService : IScanJobService, IDisposable
{
    private readonly ScanJobOptions _options;
    private readonly ScanFilePipeline _pipeline;
    private readonly ScanTreeWalker _walker;
    private readonly IScanVerdictHandler? _handler;
    private readonly IScanJobPreflight? _preflight;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private readonly List<ScanJob> _jobs = [];
    private readonly ITimer _limits;

    /// <summary>Test convenience: <paramref name="excluded"/> always excluded (nothing verified).</summary>
    internal ScanJobService(
        ScanJobOptions options, IScanBroker broker, FolderSet excluded, IScanVerdictHandler? handler, IScanJobPreflight? preflight,
        TimeProvider time, ILogger logger, Func<string, uint?>? reparseTag = null)
        : this(options, broker, ExclusionSet.Always(excluded), handler, preflight, time, logger, reparseTag)
    {
    }

    internal ScanJobService(
        ScanJobOptions options, IScanBroker broker, ExclusionSet excluded, IScanVerdictHandler? handler, IScanJobPreflight? preflight,
        TimeProvider time, ILogger logger, Func<string, uint?>? reparseTag = null, IRemoteFileProbe? remoteProbe = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        ArgumentNullException.ThrowIfNull(broker);
        ArgumentNullException.ThrowIfNull(excluded);
        _options = options;
        _handler = handler;
        _preflight = preflight;
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _pipeline = new ScanFilePipeline(broker, excluded, handler, time, logger, remoteProbe);
        _walker = new ScanTreeWalker(excluded, reparseTag, remoteProbe);
        Excluded = excluded;
        // Review B H3: the pause limit is checked every minute (or more often for a shorter limit).
        var period = TimeSpan.FromTicks(Math.Min(TimeSpan.FromMinutes(1).Ticks, options.MaxPauseTime.Ticks));
        _limits = time.CreateTimer(_ => EnforceLimitsSafely(), null, period, period);
    }

    /// <summary>The engine's service, as registered in <see cref="EngineHost"/>.</summary>
    internal static ScanJobService Create(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<ScanJobOptions>>().Value;
        options.Validate();
        var sandbox = services.GetRequiredService<IOptions<SandboxOptions>>().Value;
        var time = services.GetRequiredService<TimeProvider>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.Scanning");
        var broker = services.GetRequiredService<IScanBroker>();
        var alerts = services.GetRequiredService<Alerts.IAlertDispatcher>();
        var handler = new ScanVerdictHandler(
            alerts,
            services.GetRequiredService<Quarantine.IQuarantineService>(),
            new AutoQuarantinePolicy(options.ProtectedFolders),
            new AutoQuarantineLimiter(time, options.AutoQuarantineMaxPerWindow, options.AutoQuarantineWindow),
            time, logger);
        var preflight = new RulesPreflight(broker, alerts, sandbox.ResolvedRulesDirectory, time);
        return new ScanJobService(options, broker, services.GetRequiredService<ExclusionSet>(), handler, preflight, time, logger);
    }

    /// <summary>What this service doesn't scan (engine folders only while verified, plus the configured exclusions).</summary>
    public ExclusionSet Excluded { get; }

    public event Action<ScanJob>? JobCreated;

    /// <summary>The engine's own folders (review B2 follow-up Medium); excluded only while verified (review B H1).</summary>
    internal static FolderSet EngineFolders(SandboxOptions sandbox, Quarantine.QuarantineOptions quarantine) =>
        new([
            .. EngineDataFolders.Defaults(),
            Path.GetDirectoryName(sandbox.ResolvedWorkerPath),
            sandbox.ResolvedRulesDirectory,
            Path.GetDirectoryName(sandbox.ResolvedBlocklistPath),
            quarantine.EffectiveRoot,
        ]);

    /// <summary>The engine's exclusions: verified engine folders, configured extras; an unverified engine folder raises a health alert.</summary>
    internal static ExclusionSet CreateExclusions(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<ScanJobOptions>>().Value;
        var sandbox = services.GetRequiredService<IOptions<SandboxOptions>>().Value;
        var quarantine = services.GetRequiredService<IOptions<Quarantine.QuarantineOptions>>().Value;
        var time = services.GetRequiredService<TimeProvider>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.Scanning");
        var alerts = services.GetRequiredService<Alerts.IAlertDispatcher>();
        return new ExclusionSet(EngineFolders(sandbox, quarantine), new FolderSet(options.ExcludedFolders), FolderTrust.Default, time, (folder, why) =>
        {
            logger.LogWarning("Engine folder {Folder} is scanned, not excluded: {Why}.", folder, why);
            alerts.Post(Alerts.ScanAlerts.EngineFolderUntrusted(folder, why, time.GetUtcNow()), health: true);
        });
    }

    public ScanJob Create(ScanJobRequest request)
    {
        var job = new ScanJob(Guid.NewGuid(), request, _options, _pipeline, _walker, _handler, _preflight, _time, _logger);
        lock (_lock)
        {
            _jobs.Add(job);
            while (_jobs.Count > _options.MaxRetainedJobs && _jobs.FirstOrDefault(j => ScanJobStateMachine.IsTerminal(j.State)) is { } old)
            {
                _jobs.Remove(old);
            }
        }

        _logger.LogInformation("Scan job {JobId} created ({Trigger}, {Count} path(s)).", job.Id, request.Trigger, request.Paths.Count);
        JobCreated?.Invoke(job);
        return job;
    }

    public ScanJobStartResult Start(Guid jobId)
    {
        lock (_lock)
        {
            var job = _jobs.FirstOrDefault(j => j.Id == jobId);
            if (job is null)
            {
                return ScanJobStartResult.NotFound;
            }

            if (job.State != ScanJobState.Created)
            {
                return ScanJobStartResult.AlreadyStarted;
            }

            // Review B H3: paused jobs still count (they hold threads and results), so standard users together get at most
            // MaxRunningStandardUserJobs of the slots and the rest stay free for administrator and engine jobs; a pause is
            // bounded by MaxPauseTime (EnforceLimits).
            var active = _jobs.Where(j => j.State is not ScanJobState.Created && !ScanJobStateMachine.IsTerminal(j.State)).ToArray();
            if (active.Length >= _options.MaxConcurrentJobs
                || (job.Request.Origin == ScanJobOrigin.StandardUser
                    && active.Count(j => j.Request.Origin == ScanJobOrigin.StandardUser) >= _options.MaxRunningStandardUserJobs))
            {
                return ScanJobStartResult.TooManyJobs;
            }

            return job.Start() ? ScanJobStartResult.Started : ScanJobStartResult.AlreadyStarted;
        }
    }

    /// <summary>Review B H3: cancels jobs paused for longer than <see cref="ScanJobOptions.MaxPauseTime"/>. Runs on a timer.</summary>
    /// <returns>The jobs cancelled.</returns>
    public int EnforceLimits()
    {
        int cancelled = 0;
        foreach (var job in List())
        {
            if (job.CancelIfPausedLongerThan(_options.MaxPauseTime))
            {
                cancelled++;
                _logger.LogWarning("Scan job {JobId} was paused for longer than {MaxPause}; cancelled.", job.Id, _options.MaxPauseTime);
            }
        }

        return cancelled;
    }

    public bool Pause(Guid jobId) => Get(jobId)?.Pause() ?? false;

    public bool Resume(Guid jobId) => Get(jobId)?.Resume() ?? false;

    public bool Cancel(Guid jobId) => Get(jobId)?.Cancel() ?? false;

    public ScanJob? Get(Guid jobId)
    {
        lock (_lock)
        {
            return _jobs.FirstOrDefault(j => j.Id == jobId);
        }
    }

    public IReadOnlyList<ScanJob> List()
    {
        lock (_lock)
        {
            return _jobs.ToArray();
        }
    }

    /// <summary>Cancels every job (service shutdown).</summary>
    public void Dispose()
    {
        _limits.Dispose();
        foreach (var job in List())
        {
            job.Cancel();
        }
    }

    private void EnforceLimitsSafely()
    {
        try
        {
            EnforceLimits();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(ex, "Checking the scan job limits failed.");
        }
    }
}
