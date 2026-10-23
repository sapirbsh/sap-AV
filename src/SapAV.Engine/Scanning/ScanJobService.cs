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

    internal ScanJobService(
        ScanJobOptions options, IScanBroker broker, FolderSet excluded, IScanVerdictHandler? handler, IScanJobPreflight? preflight,
        TimeProvider time, ILogger logger, Func<string, uint?>? reparseTag = null)
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
        _pipeline = new ScanFilePipeline(broker, excluded, handler, time, logger);
        _walker = new ScanTreeWalker(excluded, reparseTag);
        Excluded = excluded;
    }

    /// <summary>The engine's service, as registered in <see cref="EngineHost"/>.</summary>
    internal static ScanJobService Create(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<ScanJobOptions>>().Value;
        options.Validate();
        var sandbox = services.GetRequiredService<IOptions<SandboxOptions>>().Value;
        var quarantine = services.GetRequiredService<IOptions<Quarantine.QuarantineOptions>>().Value;
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
        return new ScanJobService(options, broker, ExcludedFolders(options, sandbox, quarantine), handler, preflight, time, logger);
    }

    /// <summary>The folders this service never scans.</summary>
    public FolderSet Excluded { get; }

    public event Action<ScanJob>? JobCreated;

    /// <summary>The engine's own folders plus the configured extras (review B2 follow-up Medium).</summary>
    internal static FolderSet ExcludedFolders(ScanJobOptions options, SandboxOptions sandbox, Quarantine.QuarantineOptions quarantine) =>
        new([
            .. EngineDataFolders.Defaults(),
            Path.GetDirectoryName(sandbox.ResolvedWorkerPath),
            sandbox.ResolvedRulesDirectory,
            Path.GetDirectoryName(sandbox.ResolvedBlocklistPath),
            quarantine.EffectiveRoot,
            .. options.ExcludedFolders,
        ]);

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

            if (_jobs.Count(j => j.State is not ScanJobState.Created && !ScanJobStateMachine.IsTerminal(j.State)) >= _options.MaxConcurrentJobs)
            {
                return ScanJobStartResult.TooManyJobs;
            }

            return job.Start() ? ScanJobStartResult.Started : ScanJobStartResult.AlreadyStarted;
        }
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
        foreach (var job in List())
        {
            job.Cancel();
        }
    }
}
