using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Alerts;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Alerts;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Monitoring;
using SapAV.Engine.Tests.RealTime;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>Registry watches the test fires by hand (no notification timing).</summary>
internal sealed class FakeRegistryWatchFactory : IRegistryWatchFactory
{
    private readonly List<FakeRegistryWatch> _all = [];

    public IReadOnlyList<FakeRegistryWatch> Live
    {
        get
        {
            lock (_all)
            {
                return [.. _all.Where(w => !w.Disposed)];
            }
        }
    }

    public IReadOnlyList<FakeRegistryWatch> All
    {
        get
        {
            lock (_all)
            {
                return [.. _all];
            }
        }
    }

    public IDisposable Watch(RegistryRoot root, string path, bool subtree, Action changed)
    {
        var watch = new FakeRegistryWatch(root, path, subtree, changed);
        lock (_all)
        {
            _all.Add(watch);
        }

        return watch;
    }

    /// <summary>Fires every live watch on exactly this key; false when none watches it.</summary>
    public bool Fire(RegistryRoot root, string path)
    {
        var hits = Live.Where(w => w.Root == root && string.Equals(w.Path, path, StringComparison.OrdinalIgnoreCase)).ToArray();
        foreach (var hit in hits)
        {
            hit.Changed();
        }

        return hits.Length > 0;
    }

    internal sealed class FakeRegistryWatch(RegistryRoot root, string path, bool subtree, Action changed) : IDisposable
    {
        public RegistryRoot Root { get; } = root;

        public string Path { get; } = path;

        public bool Subtree { get; } = subtree;

        public Action Changed { get; } = changed;

        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }
}

/// <summary>Records every scoped collection (which scopes were asked for) and passes it on.</summary>
internal sealed class RecordingCollector(PersistenceCollector inner) : IScopedPersistenceCollector
{
    public List<PersistenceScope[]> Calls { get; } = [];

    public PersistenceCollector Inner => inner;

    public IRegistryView Registry => inner.Registry;

    public PersistenceCollection Collect(CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null) =>
        inner.Collect(cancellationToken, options);

    public PersistenceScopedCollection CollectScoped(
        IReadOnlyCollection<PersistenceScope>? scopes, CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null)
    {
        lock (Calls)
        {
            Calls.Add([.. scopes ?? []]);
        }

        return inner.CollectScoped(scopes, cancellationToken, options);
    }

    public PersistenceWatchPlan Plan(CancellationToken cancellationToken = default) => inner.Plan(cancellationToken);
}

/// <summary>Records which entries each judgement got, around the real scanner.</summary>
internal sealed class RecordingScanner(IPersistenceScanner inner) : IPersistenceScanner
{
    public List<(PersistenceEntry[] Entries, PersistenceScanOptions Options)> Calls { get; } = [];

    public IEnumerable<string?> Judged => Calls.SelectMany(c => c.Entries).Select(e => e.ValueName);

    public Task<PersistenceScanResult> ScanAsync(PersistenceCollection collection, PersistenceScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        lock (Calls)
        {
            Calls.Add(([.. collection.Entries], options!));
        }

        return inner.ScanAsync(collection, options, cancellationToken);
    }
}

/// <summary>Records every alert with the budget it was posted against, and signals each one.</summary>
internal sealed class BudgetRecordingDispatcher : IAlertDispatcher
{
    private readonly List<(Alert Alert, AlertBudget? Budget)> _posts = [];
    private readonly SemaphoreSlim _posted = new(0);

    public IReadOnlyList<(Alert Alert, AlertBudget? Budget)> Posts
    {
        get
        {
            lock (_posts)
            {
                return [.. _posts];
            }
        }
    }

    public IEnumerable<Alert> Alerts => Posts.Select(p => p.Alert);

    public bool Post(Alert alert, bool health = false) => Record(alert, null);

    public bool Post(Alert alert, AlertBudget budget, bool health = false) => Record(alert, budget);

    public void FlushSummary()
    {
    }

    /// <summary>Waits for an alert matching <paramref name="match"/> (signalled, no polling).</summary>
    public Alert? WaitFor(Func<Alert, bool> match, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            if (Alerts.FirstOrDefault(match) is { } found)
            {
                return found;
            }

            var left = deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero || !_posted.Wait(left))
            {
                return Alerts.FirstOrDefault(match);
            }
        }
    }

    private bool Record(Alert alert, AlertBudget? budget)
    {
        lock (_posts)
        {
            _posts.Add((alert, budget));
        }

        _posted.Release();
        return true;
    }
}

/// <summary>Counts the definition files the parser really gets (around the in-process stand-in for the worker).</summary>
internal sealed class CountingParser : IPersistenceFileParser
{
    private int _files;

    public int Files => Volatile.Read(ref _files);

    public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _files);
        return WireTestParser.Instance.ParseAsync(file, kind, displayPath, cancellationToken);
    }
}

/// <summary>Everything admin-only, so only the target scan and the entry rules decide.</summary>
internal sealed class AdminOnlyWritability : IPathWritability
{
    public Writability FileModifiable(string filePath) => Writability.AdminOnly;

    public Writability FileCreatable(string filePath) => Writability.AdminOnly;
}

/// <summary>
/// One persistence-monitor test: a throwaway registry (fake HKLM / HKU under HKCU), temp Startup and Tasks folders, the real
/// collector (registry, Startup folder, scheduled tasks) and judgement with a fake broker (verdict by file name: <c>mal*</c>),
/// fake watches and a manual clock. Nothing real is touched.
/// </summary>
internal sealed class MonitorHarness : IDisposable
{
    public const string Alice = "S-1-5-21-1000-2000-3000-1001";
    public const string Bob = "S-1-5-21-1000-2000-3000-1002";
    public const string MachineRun = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string UserRun = @"Software\Microsoft\Windows\CurrentVersion\Run";

    private readonly TempDir _temp = new();
    private PersistenceMonitor? _monitor;

    public MonitorHarness(Action<PersistenceMonitorOptions>? configure = null, IPersistenceBaselineStore? store = null, bool realRegistryWatches = false)
    {
        Startup = Directory.CreateDirectory(Path.Combine(_temp.Path, "Startup")).FullName;
        Tasks = Directory.CreateDirectory(Path.Combine(_temp.Path, "Tasks")).FullName;
        Targets = Directory.CreateDirectory(Path.Combine(_temp.Path, "targets")).FullName;
        Options = new PersistenceMonitorOptions
        {
            StartDelay = TimeSpan.Zero,
            SettleDelay = TimeSpan.FromSeconds(2),
            MaxSettleDelay = TimeSpan.FromSeconds(10),
            MinInterval = TimeSpan.FromSeconds(10),
            ContinuationDelay = TimeSpan.FromSeconds(1),
            HiveCheckInterval = TimeSpan.FromSeconds(30),
            MaxLoggedChangesPerPass = 1000,
        };
        configure?.Invoke(Options);
        Store = store ?? new MemoryBaselineStore();
        Collector = new RecordingCollector(new PersistenceCollector(Registry.View, new SafePathProbe(),
            [new RegistryAutorunSource(), new StartupFolderSource([(Startup, null)]), new ScheduledTaskSource(Tasks)],
            parser: Parser, parsedFiles: new ParsedFileCache()));
        var judge = new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" });
        Scanner = new RecordingScanner(new PersistenceScanner(new FakeScanBroker(), Alerts, Time, NullLogger.Instance, judge, () => new AdminOnlyWritability()));
        RegistryWatches = realRegistryWatches ? new WindowsRegistryWatchFactory(Registry.MachineKey, Registry.UsersKey) : FakeRegistry;
    }

    public RegistryTestRoot Registry { get; } = new();

    public string Startup { get; }

    public string Tasks { get; }

    public string Targets { get; }

    public string Base => _temp.Path;

    public PersistenceMonitorOptions Options { get; }

    public IPersistenceBaselineStore Store { get; }

    public CountingParser Parser { get; } = new();

    public RecordingCollector Collector { get; }

    public RecordingScanner Scanner { get; }

    public BudgetRecordingDispatcher Alerts { get; } = new();

    public FakeRegistryWatchFactory FakeRegistry { get; } = new();

    public IRegistryWatchFactory RegistryWatches { get; }

    public FakeWatchFactory Folders { get; } = new();

    public ManualTime Time { get; } = new();

    public ListLogger<PersistenceMonitor> Log { get; } = new();

    public PersistenceMonitor Monitor => _monitor ??= Create();

    public PersistenceMonitor Create() =>
        new(Options, Collector, Scanner, Store, RegistryWatches, Folders, Time, Log);

    /// <summary>A target file whose verdict comes from its name (<c>mal*</c> = Malicious).</summary>
    public string Target(string name)
    {
        string path = Path.Combine(Targets, name);
        File.WriteAllText(path, "synthetic autostart target " + name);
        return path;
    }

    public void MachineRunValue(string name, string target) => Registry.Machine(MachineRun).SetValue(name, $"\"{target}\" /background");

    public void UserRunValue(string sid, string name, string target) => Registry.Users($@"{sid}\{UserRun}").SetValue(name, $"\"{target}\"");

    /// <summary>Initialize + every pass due now (the first collection of every scope).</summary>
    public void Baseline()
    {
        Monitor.Initialize();
        Monitor.RunDue();
    }

    /// <summary>Moves the clock and runs what is due then.</summary>
    public int Advance(TimeSpan by)
    {
        Time.Now += by;
        return Monitor.RunDue();
    }

    public IEnumerable<Alert> PersistenceAlerts(string valueName) =>
        Alerts.Alerts.Where(a => a.Autostart?.ValueName == valueName && a.Type is AlertType.MaliciousPersistence or AlertType.SuspiciousPersistence);

    public void Dispose()
    {
        _monitor?.Dispose();
        Registry.Dispose();
        TempDir.DeleteTree(_temp.Path);
    }
}
