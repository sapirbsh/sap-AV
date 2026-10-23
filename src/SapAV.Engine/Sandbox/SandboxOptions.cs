namespace SapAV.Engine.Sandbox;

/// <summary>Where file parsing runs.</summary>
public enum SandboxMode
{
    /// <summary>In sandboxed worker processes (AppContainer, no capabilities, Job Object). The default and the only safe mode.</summary>
    AppContainer,

    /// <summary>
    /// <b>Debugging only:</b> in the engine process itself, as before B5. A crash or exploit in a parser then runs as the
    /// engine's account (SYSTEM as a service). Logged as a warning at startup.
    /// </summary>
    InProcess,
}

/// <summary>Scan worker sandbox settings (<c>appsettings.json</c> section <c>Sandbox</c>).</summary>
public sealed class SandboxOptions
{
    public const string SectionName = "Sandbox";

    public SandboxMode Mode { get; set; } = SandboxMode.AppContainer;

    /// <summary>Number of worker processes (1-8). Each scans one file at a time.</summary>
    public int WorkerCount { get; set; } = 2;

    /// <summary>Per-file time limit; a worker that takes longer is killed and restarted, the file is NotScanned.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Time limit for compiling a rule package in a worker.</summary>
    public TimeSpan RulesLoadTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Job Object memory limit per worker (64 MiB - 16 GiB).</summary>
    public int WorkerMemoryLimitMegabytes { get; set; } = 1024;

    /// <summary>Hard CPU cap per worker in percent of the whole machine (0 = no cap).</summary>
    public int WorkerCpuRatePercent { get; set; } = 50;

    /// <summary>A file that crashes or hangs a worker this many times is reported Suspicious instead of scanned again.</summary>
    public int MaxFailuresPerFile { get; set; } = 2;

    /// <summary>First restart delay after a worker failure; doubles per consecutive failure up to <see cref="RestartBackoffMax"/>.</summary>
    public TimeSpan RestartBackoffInitial { get; set; } = TimeSpan.FromMilliseconds(250);

    public TimeSpan RestartBackoffMax { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>A worker is replaced after scanning this many files (bounds how long anything it holds can live; review M1).</summary>
    public int MaxFilesPerWorker { get; set; } = 500;

    /// <summary>A worker is replaced after running this long (checked after each file; review M1).</summary>
    public TimeSpan MaxWorkerLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>The worker exe; default <c>ScanWorker\SapAV.ScanWorker.exe</c> next to the engine.</summary>
    public string? WorkerPath { get; set; }

    /// <summary>
    /// The AppContainer profile name. Null (the default) = <c>sap-AV.ScanWorker.&lt;per-install random suffix&gt;</c>
    /// (<see cref="Sandbox.AppContainerName"/>): the SID follows from the name alone, so a guessable name would let any
    /// user create a profile with the worker's SID.
    /// </summary>
    public string? AppContainerName { get; set; }

    /// <summary>YARA rules directory; default <c>data\rules</c> next to the engine (D3 moves it to the protected ProgramData folder).</summary>
    public string? RulesDirectory { get; set; }

    /// <summary>Blocklist file; default <c>data\hashes\blocklist.txt</c> next to the engine.</summary>
    public string? BlocklistPath { get; set; }

    // ---- Internal (never bound from configuration) ----

    /// <summary>Test only: lets the worker honor fault-injection and probe requests.</summary>
    internal bool EnableWorkerTestHooks { get; set; }

    /// <summary>Test only: run the worker without the AppContainer (still in the Job Object).</summary>
    internal WorkerIsolation Isolation { get; set; } = WorkerIsolation.AppContainer;

    internal WorkerMitigations Mitigations { get; set; } = WorkerMitigations.Default;

    internal string ResolvedWorkerPath => Path.GetFullPath(WorkerPath ?? Path.Combine(AppContext.BaseDirectory, "ScanWorker", "SapAV.ScanWorker.exe"));

    internal string ResolvedRulesDirectory => Path.GetFullPath(RulesDirectory ?? Path.Combine(AppContext.BaseDirectory, "data", "rules"));

    internal string ResolvedBlocklistPath => Path.GetFullPath(BlocklistPath ?? Path.Combine(AppContext.BaseDirectory, "data", "hashes", "blocklist.txt"));

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        if (!Enum.IsDefined(Mode))
        {
            throw new ArgumentOutOfRangeException(nameof(Mode), Mode, "Unknown sandbox mode.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(WorkerCount, 1, nameof(WorkerCount));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(WorkerCount, 8, nameof(WorkerCount));
        ArgumentOutOfRangeException.ThrowIfLessThan(RequestTimeout, TimeSpan.FromMilliseconds(100), nameof(RequestTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(RulesLoadTimeout, TimeSpan.FromSeconds(1), nameof(RulesLoadTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(WorkerMemoryLimitMegabytes, 64, nameof(WorkerMemoryLimitMegabytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(WorkerMemoryLimitMegabytes, 16 * 1024, nameof(WorkerMemoryLimitMegabytes));
        ArgumentOutOfRangeException.ThrowIfNegative(WorkerCpuRatePercent, nameof(WorkerCpuRatePercent));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(WorkerCpuRatePercent, 100, nameof(WorkerCpuRatePercent));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxFailuresPerFile, 1, nameof(MaxFailuresPerFile));
        ArgumentOutOfRangeException.ThrowIfNegative(RestartBackoffInitial.Ticks, nameof(RestartBackoffInitial));
        ArgumentOutOfRangeException.ThrowIfLessThan(RestartBackoffMax, RestartBackoffInitial, nameof(RestartBackoffMax));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxFilesPerWorker, 1, nameof(MaxFilesPerWorker));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxWorkerLifetime, TimeSpan.FromSeconds(1), nameof(MaxWorkerLifetime));
    }
}
