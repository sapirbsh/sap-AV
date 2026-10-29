using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>A fixed process list.</summary>
internal sealed class FakeProcessSource(params ProcessImage[] processes) : IProcessSource
{
    public IReadOnlyList<ProcessImage> Snapshot(CancellationToken cancellationToken) => processes;
}

/// <summary>A fixed persistence collection.</summary>
internal sealed class FakeCollector(PersistenceCollection collection) : IPersistenceCollector
{
    public int Calls { get; private set; }

    public PersistenceCollection Collect(CancellationToken cancellationToken = default)
    {
        Calls++;
        return collection;
    }
}

/// <summary>A fixed folder set.</summary>
internal sealed class FakeFolders(ProfileFolderSet set) : IProfileFolderSource
{
    public ProfileFolderSet Resolve() => set;
}

/// <summary>Everything admin-only, so only the target scan and the entry rules decide.</summary>
internal sealed class AdminOnlyWritability : IPathWritability
{
    public Writability FileModifiable(string filePath) => Writability.AdminOnly;

    public Writability FileCreatable(string filePath) => Writability.AdminOnly;
}

/// <summary>Records what the job's verdict handler saw (path, verdict, scan handle still open).</summary>
internal sealed class RecordingVerdictHandler : IScanVerdictHandler
{
    public List<(string Path, Verdict? Verdict, bool HandleOpen)> Seen { get; } = [];

    public Task<ScanVerdictOutcome> HandleAsync(FileScanReport report, OpenedScanFile? opened, ScanBudget? budget, CancellationToken cancellationToken)
    {
        lock (Seen)
        {
            Seen.Add((report.Result.Item.Path, report.Result.Verdict, opened is not null && !opened.Handle.IsClosed));
        }

        return Task.FromResult(ScanVerdictOutcome.Nothing);
    }

    public void JobFinished(ScanJob job)
    {
    }
}

/// <summary>
/// A Quick Scan over a synthetic temp tree: fake processes, a fake persistence collection judged by the real scanner,
/// fake profile folders, the fake broker (verdict by file name). Records every file the broker scanned.
/// </summary>
internal sealed class QuickScanHarness : IDisposable
{
    public QuickScanHarness(TimeProvider? time = null)
    {
        Jobs = new ScanJobHarness(time) { Handler = Handler };
        Jobs.Options.ThreadsPerJob = 2;
        Profile = Dir(@"Users\alice");
        Downloads = Dir(@"Users\alice\Downloads");
        Desktop = Dir(@"Users\alice\Desktop");
        Temp = Dir(@"Users\alice\AppData\Local\Temp");
        Roaming = Dir(@"Users\alice\AppData\Roaming");
        Local = Dir(@"Users\alice\AppData\Local");
        ProgramData = Dir("ProgramData");
        MachineTemp = Dir(@"Windows\Temp");
        Jobs.Broker.OnScan = (item, _, _) =>
        {
            lock (Scanned)
            {
                Scanned.Add(item.Path);
            }

            return Task.FromResult<FileScanReport?>(null);
        };
    }

    public ScanJobHarness Jobs { get; }

    public RecordingVerdictHandler Handler { get; } = new();

    public RecordingAlertSink Alerts { get; } = new();

    public List<string> Scanned { get; } = [];

    public string Profile { get; }

    public string Downloads { get; }

    public string Desktop { get; }

    public string Temp { get; }

    public string Roaming { get; }

    public string Local { get; }

    public string ProgramData { get; }

    public string MachineTemp { get; }

    public List<ProcessImage> Processes { get; } = [];

    public List<PersistenceEntry> Entries { get; } = [];

    public QuickScanOptions Options { get; } = new();

    public List<IScanCheck> ExtraChecks { get; } = [];

    public FakeCollector? Collector { get; private set; }

    public string Write(string relative, string content = "synthetic test content")
    {
        var path = Path.Combine(Jobs.Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public static PersistenceEntry Run(string target, string value) =>
        new(PersistenceKind.RunKey, null, @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", value, $"\"{target}\"",
            ResolvedCommand.Resolved(target, "", null), enabled: true);

    public QuickScanFactory Factory()
    {
        Collector = new FakeCollector(new PersistenceCollection(Entries, [], TimeSpan.Zero));
        var scanner = new PersistenceScanner(Jobs.Broker, Alerts, Jobs.Time, NullLogger.Instance,
            new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" }), () => new AdminOnlyWritability());
        var users = new[] { new UserFolders("S-1-5-21-1-2-3-1001", Profile, Desktop, Downloads, Temp, Roaming, Local) };
        var folders = new FakeFolders(new ProfileFolderSet(users, MachineTemp, null, null, ProgramData, []));
        return new QuickScanFactory(Options, new FakeProcessSource([.. Processes]), Collector, scanner, folders, ExtraChecks);
    }

    public ScanJob Create(TimeSpan? budget = null)
    {
        var request = Factory().CreateRequest(ScanJobOrigin.Engine);
        return Jobs.Service.Create(budget is null ? request : request with { TimeBudget = budget });
    }

    public async Task<ScanJob> RunAsync(TimeSpan? budget = null)
    {
        var job = Create(budget);
        Assert.Equal(ScanJobStartResult.Started, Jobs.Service.Start(job.Id));
        await JobWait.Done(job);
        return job;
    }

    public void Dispose() => Jobs.Dispose();

    private string Dir(string relative) => Directory.CreateDirectory(Path.Combine(Jobs.Root, relative)).FullName;
}

/// <summary>
/// C4 Quick Scan as one job of pluggable checks: phases in order, persistence findings and alerts, dedupe across phases,
/// the recent-files filter, the time budget with an honest incomplete summary, pause / cancel across phases, and a check
/// that fails. Synthetic data only.
/// </summary>
public sealed class QuickScanJobTests(ITestOutputHelper output)
{
    private static readonly string[] PhaseNames = ["Running programs", "Autostart entries", "High-risk folders", "Recently changed files"];

    [Fact]
    public async Task QuickScan_RunsEveryPhaseInOrder_ScansEachFileOnce_AndReportsPersistenceFindings()
    {
        using var q = new QuickScanHarness();
        var running = q.Write(@"Program Files\Vendor\running.exe");
        var helper = q.Write(@"Users\alice\AppData\Roaming\app\helper.exe");
        var persisted = q.Write(@"Users\alice\AppData\Roaming\evil\mal-persist.exe");
        var downloaded = q.Write(@"Users\alice\Downloads\mal-download.exe");
        var script = q.Write(@"Users\alice\AppData\Local\Temp\setup.ps1");
        var document = q.Write(@"Users\alice\Documents\recent.docx");
        var vendor = q.Write(@"ProgramData\Vendor\new.dll");
        q.Processes.AddRange([new(10, "running", running), new(11, "running", running.ToUpperInvariant()), new(12, "helper", helper), new(4, "System", null, "none")]);
        q.Entries.AddRange([QuickScanHarness.Run(helper, "Helper"), QuickScanHarness.Run(persisted, "Updater")]);

        var job = await q.RunAsync();

        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.True(job.IsComplete);
        Assert.Equal(PhaseNames, job.Phases.Select(p => p.Name));
        Assert.All(job.Phases, p => Assert.Equal(ScanPhaseState.Completed, p.State));
        Assert.Equal(q.Scanned.Count, q.Scanned.Distinct(StringComparer.OrdinalIgnoreCase).Count()); // one scan per file
        Assert.Equal(new[] { running, helper, persisted, downloaded, script, document, vendor }.Order(StringComparer.OrdinalIgnoreCase),
            q.Scanned.Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);
        Assert.True(job.Duplicates >= 2); // helper (process → persistence → AppData), mal-persist (persistence → AppData)
        Assert.Equal(1, q.Collector!.Calls);

        var finding = Assert.Single(job.Findings);
        Assert.Equal(ScanFindingCategory.Persistence, finding.Category);
        Assert.Equal(Verdict.Malicious, finding.Verdict);
        Assert.Equal("Updater", finding.Persistence!.Entry.ValueName);
        Assert.Contains(q.Alerts.Snapshot(), a => a.Type == AlertType.MaliciousPersistence && a.AlertId == finding.AlertId);

        // The Malicious target went through the job's verdict handler (alert + auto-quarantine policy) with its scan handle open,
        // and is a normal job result too.
        Assert.Contains(q.Handler.Seen, s => s.Path.Equals(persisted, StringComparison.OrdinalIgnoreCase) && s.Verdict == Verdict.Malicious && s.HandleOpen);
        Assert.Contains(job.Results, r => r.Path.Equals(persisted, StringComparison.OrdinalIgnoreCase) && r.Verdict == Verdict.Malicious);
        Assert.Contains(job.Results, r => r.Path.Equals(downloaded, StringComparison.OrdinalIgnoreCase) && r.Verdict == Verdict.Malicious);
        Assert.Equal(2, job.Phases[1].Files); // the persistence phase handled its 2 targets inline; helper came back as phase 1's report
    }

    [Fact]
    public async Task PersistencePhase_ReusesTheRunningProgramsReport_InsteadOfScanningAgain()
    {
        using var q = new QuickScanHarness();
        var image = q.Write(@"Program Files\Vendor\mal-running.exe");
        q.Processes.Add(new(20, "mal-running", image));
        q.Entries.Add(QuickScanHarness.Run(image, "Autostart"));

        var job = await q.RunAsync();

        Assert.Single(q.Scanned, p => p.Equals(image, StringComparison.OrdinalIgnoreCase));
        var finding = Assert.Single(job.Findings); // judged from phase 1's report: Malicious carries over
        Assert.Equal(Verdict.Malicious, finding.Verdict);
        Assert.Single(job.Results, r => r.Path.Equals(image, StringComparison.OrdinalIgnoreCase)); // one result, not two
    }

    [Fact]
    public async Task WithAClockAWeekAhead_OnlyRiskyFilesAreQueued_AndOldDocumentsAreLeftToFullScan()
    {
        using var q = new QuickScanHarness(new ManualTime { Now = DateTimeOffset.UtcNow.AddDays(30) });
        var exe = q.Write(@"Users\alice\Downloads\tool.exe");
        q.Write(@"Users\alice\Downloads\readme.txt");
        q.Write(@"Users\alice\Documents\old.docx");
        q.Write(@"ProgramData\Vendor\old.dll");

        await q.RunAsync();

        Assert.Equal([exe], q.Scanned, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TimeBudget_EachFolderPhaseGetsItsShare_AndTheLastOneHitsTheBudget_WithAnIncompleteSummary()
    {
        using var q = new QuickScanHarness();
        for (int i = 0; i < 20; i++)
        {
            q.Write($@"Users\alice\Downloads\file{i}.exe");
            q.Write($@"Users\alice\Downloads\more{i}.exe");
            q.Write($@"Users\alice\Documents\recent{i}.docx");
        }

        q.Jobs.Broker.OnScan = async (item, _, token) =>
        {
            await Task.Delay(50, token);
            lock (q.Scanned)
            {
                q.Scanned.Add(item.Path);
            }

            return null;
        };

        var job = await q.RunAsync(TimeSpan.FromMilliseconds(800));

        Assert.Equal(ScanJobState.TimedOut, job.State);
        Assert.False(job.IsComplete);
        Assert.Equal([ScanPhaseState.Completed, ScanPhaseState.Completed, ScanPhaseState.Incomplete, ScanPhaseState.Incomplete], job.Phases.Select(p => p.State));
        Assert.Contains(job.Phases[2].Notes, n => n.Contains("share of the time budget", StringComparison.Ordinal)); // stopped to leave time for phase 4
        Assert.Contains(q.Scanned, p => p.EndsWith(".docx", StringComparison.OrdinalIgnoreCase)); // phase 4 did run
        Assert.Contains(job.Warnings, w => w.Message.Contains("time budget", StringComparison.Ordinal)
            && w.Message.Contains("High-risk folders (Incomplete)", StringComparison.Ordinal)
            && w.Message.Contains("Recently changed files (Incomplete)", StringComparison.Ordinal));
        Assert.True(job.GetProgress().FilesDone < 60);
    }

    [Fact]
    public void BudgetShares_FollowTheWeightsOfTheRemainingPhases_AndTheLastGetsEverythingLeft()
    {
        IScanCheck[] checks = [new WeightedCheck(1), new WeightedCheck(3), new WeightedCheck(4)];

        Assert.Equal(TimeSpan.FromSeconds(10), ScanJob.ShareOfRemaining(checks, 0, TimeSpan.FromSeconds(80)));
        Assert.Equal(TimeSpan.FromSeconds(30), ScanJob.ShareOfRemaining(checks, 1, TimeSpan.FromSeconds(70)));
        Assert.Equal(TimeSpan.FromSeconds(55), ScanJob.ShareOfRemaining(checks, 2, TimeSpan.FromSeconds(55)));
        Assert.Equal(TimeSpan.Zero, ScanJob.ShareOfRemaining(checks, 1, TimeSpan.FromSeconds(-1)));
    }

    private sealed class WeightedCheck(double weight) : IScanCheck
    {
        public string Name => "w";

        public double Weight => weight;

        public void Run(IScanCheckContext context)
        {
        }
    }

    [Fact]
    public async Task Pause_InTheFolderPhase_StopsProgress_AndResumeFinishesEveryPhase()
    {
        using var q = new QuickScanHarness();
        q.Write(@"Users\alice\Downloads\first.exe");
        q.Write(@"Users\alice\Downloads\second.exe");
        q.Write(@"Users\alice\Documents\recent.docx");
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        q.Jobs.Broker.OnScan = async (item, _, _) =>
        {
            if (item.Path.EndsWith("first.exe", StringComparison.OrdinalIgnoreCase))
            {
                reached.TrySetResult();
                await release.Task;
            }

            lock (q.Scanned)
            {
                q.Scanned.Add(item.Path);
            }

            return null;
        };
        var job = q.Create();
        q.Jobs.Service.Start(job.Id);
        await reached.Task.WaitAsync(JobWait.Timeout);

        Assert.True(job.Pause());
        Assert.Equal("High-risk folders", job.GetProgress().Phase!.Name);
        release.SetResult();
        await JobWait.ForState(job, ScanJobState.Paused);
        long done = job.GetProgress().FilesDone;
        await Task.Delay(100);
        Assert.Equal(done, job.GetProgress().FilesDone); // nothing moves while paused
        Assert.True(job.Resume());
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.All(job.Phases, p => Assert.Equal(ScanPhaseState.Completed, p.State));
        Assert.Contains(q.Scanned, p => p.EndsWith("recent.docx", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Cancel_DuringThePersistencePhase_KeepsWhatWasDone_AndLaterPhasesNeverRun()
    {
        using var q = new QuickScanHarness();
        var target = q.Write(@"Users\alice\AppData\Roaming\x\slow.exe");
        q.Write(@"Users\alice\Downloads\never.exe");
        q.Entries.Add(QuickScanHarness.Run(target, "Slow"));
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        q.Jobs.Broker.OnScan = async (item, _, token) =>
        {
            reached.TrySetResult();
            await Task.Delay(Timeout.Infinite, token);
            return null;
        };
        var job = q.Create();
        q.Jobs.Service.Start(job.Id);
        await reached.Task.WaitAsync(JobWait.Timeout);

        Assert.True(job.Cancel());
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Cancelled, job.State);
        Assert.Equal([ScanPhaseState.Completed, ScanPhaseState.Incomplete, ScanPhaseState.NotRun, ScanPhaseState.NotRun], job.Phases.Select(p => p.State));
        Assert.Contains(job.Warnings, w => w.Message.Contains("cancelled", StringComparison.Ordinal));
    }

    private sealed class ThrowingCheck : IScanCheck
    {
        public string Name => "Broken check";

        public double Weight => 1;

        public void Run(IScanCheckContext context) => throw new InvalidOperationException("synthetic failure");
    }

    [Fact]
    public async Task AFailingCheck_IsAnIncompletePhase_AndTheScanGoesOn()
    {
        using var q = new QuickScanHarness();
        var exe = q.Write(@"Users\alice\Downloads\tool.exe");
        q.ExtraChecks.Add(new ThrowingCheck());

        var job = await q.RunAsync();

        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.False(job.IsComplete);
        Assert.Equal(ScanPhaseState.Incomplete, Assert.Single(job.Phases, p => p.Name == "Broken check").State);
        Assert.Equal(ScanPhaseState.Completed, job.Phases.Single(p => p.Name == "High-risk folders").State);
        Assert.Contains(exe, q.Scanned, StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(0, 0.0, 180)] // nothing done yet: the whole budget is the honest answer
    [InlineData(1, 0.0, 100)] // phase 1 of weights 1,1,2 done after 10 s: 25 % → 30 s left
    [InlineData(2, 0.5, 100)] // 75 % after 10 s → 3.3 s left
    [InlineData(1, 0.0, 5)] // never more than the budget left
    public void EtaAcrossPhases_WeighsThePhases_AndIsCappedByTheBudget(int current, double fraction, int budgetLeftSeconds)
    {
        var eta = ScanJob.EstimateAcrossPhases([1, 1, 2], current, fraction, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(budgetLeftSeconds));

        var expected = current == 0 ? TimeSpan.FromSeconds(budgetLeftSeconds)
            : TimeSpan.FromSeconds(Math.Min(budgetLeftSeconds, 10 * (1 - Progress(current, fraction)) / Progress(current, fraction)));
        Assert.NotNull(eta);
        Assert.InRange(eta!.Value.TotalSeconds, expected.TotalSeconds - 0.01, expected.TotalSeconds + 0.01);

        static double Progress(int current, double fraction) => (new[] { 1.0, 1, 2 }.Take(current).Sum() + new[] { 1.0, 1, 2 }[current] * fraction) / 4;
    }

    [Fact]
    public void QuickScanRequests_AreEngineOrAdministratorOnly()
    {
        using var q = new QuickScanHarness();
        var factory = q.Factory();

        Assert.Throws<ArgumentException>(() => factory.CreateRequest(ScanJobOrigin.StandardUser));
        var request = factory.CreateRequest(ScanJobOrigin.Administrator);
        Assert.Equal(ScanTrigger.QuickScan, request.Trigger);
        Assert.Equal(TimeSpan.FromMinutes(3), request.TimeBudget);
        Assert.Equal(PhaseNames, request.Checks!.Select(c => c.Name));
    }

    /// <summary>
    /// Real-machine smoke test (opt-in, <c>SAPAV_TEST_SLOW=1</c>): a Quick Scan of this PC with the real process list,
    /// persistence collector, registry profile folders and the in-process scanner (test only; the engine uses the
    /// sandboxed worker). No verdict handler, so nothing is quarantined. Asserts only that it ends and reports phase timings.
    /// </summary>
    [RequiresFact(Requires.SlowTests)]
    public async Task RealMachine_QuickScan_CompletesWithinItsBudget_AndReportsPhaseTimings()
    {
        using var broker = new InProcessScanBroker(new FakeRulesSource(), NullLogger.Instance);
        var options = new ScanJobOptions { ThreadsPerJob = 2 };
        using var service = new ScanJobService(options, broker, ExclusionSet.Always(new FolderSet([])), null, null, TimeProvider.System, NullLogger.Instance);
        var scanner = new PersistenceScanner(broker, new RecordingAlertSink(), TimeProvider.System);
        var factory = new QuickScanFactory(new QuickScanOptions(), new WindowsProcessSource(), PersistenceCollector.CreateDefault(), scanner,
            new RegistryProfileFolders(new WindowsRegistryView()));
        var clock = Stopwatch.StartNew();

        var job = service.Create(factory.CreateRequest(ScanJobOrigin.Engine));
        service.Start(job.Id);
        await job.Completion.WaitAsync(TimeSpan.FromMinutes(6));

        foreach (var phase in job.Phases)
        {
            output.WriteLine($"{phase.Name}: {phase.State}, {phase.Duration.TotalSeconds:0.0} s, {phase.Files} files, {phase.Findings} findings; {string.Join(" | ", phase.Notes)}");
        }

        var progress = job.GetProgress();
        output.WriteLine($"Total: {job.State} in {clock.Elapsed.TotalSeconds:0.0} s, {progress.FilesDone} files, {job.Duplicates} duplicates skipped, "
            + $"{progress.Counters.NotScanned} not scanned.");
        Assert.True(job.State is ScanJobState.Completed or ScanJobState.TimedOut, job.State.ToString());
        Assert.Equal(ScanPhaseState.Completed, job.Phases[0].State);
    }
}
