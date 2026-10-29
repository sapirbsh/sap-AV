using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Cache;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>A fixed drive list.</summary>
internal sealed class FakeVolumes(IReadOnlyList<DriveInfoEntry> drives) : IVolumeSource
{
    public IReadOnlyList<DriveInfoEntry> List() => drives;
}

/// <summary>
/// A Full Scan over a temp tree that stands in for one fixed drive: fake processes and autostarts, the cache harness (real
/// SQLite cache, cacheable fake reports: verdict by file name). Records every file the broker scanned.
/// </summary>
internal sealed class FullScanHarness : IDisposable
{
    public FullScanHarness()
    {
        Jobs.Options.ThreadsPerJob = 2;
        var inner = Jobs.Broker.OnScan!;
        Jobs.Broker.OnScan = async (item, file, token) =>
        {
            lock (Scanned)
            {
                Scanned.Add(item.Path);
            }

            if (Delay > TimeSpan.Zero)
            {
                await Task.Delay(Delay, token);
            }

            return await inner(item, file, token);
        };
        Drives.Add(new DriveInfoEntry(Jobs.Root, FullScanVolumes.DriveFixed, @"\\?\Volume{test-1}\", 4096));
    }

    public CacheHarness Cached { get; } = new();

    public ScanJobHarness Jobs => Cached.Jobs;

    public FullScanOptions Options { get; } = new();

    public List<DriveInfoEntry> Drives { get; } = [];

    public List<string> Scanned { get; } = [];

    public TimeSpan Delay { get; set; }

    public FullScanFactory Factory()
    {
        var scanner = new PersistenceScanner(Jobs.Broker, new RecordingAlertSink(), Jobs.Time, NullLogger.Instance,
            new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" }), () => new AdminOnlyWritability());
        return new FullScanFactory(Options, new FakeProcessSource(), new FakeCollector(new PersistenceCollection([], [], TimeSpan.Zero)), scanner,
            new FakeVolumes([.. Drives]));
    }

    public ScanJob Start()
    {
        var job = Jobs.Service.Create(Factory().CreateRequest(ScanJobOrigin.Engine));
        Assert.Equal(ScanJobStartResult.Started, Jobs.Service.Start(job.Id));
        return job;
    }

    public async Task<ScanJob> RunAsync()
    {
        var job = Start();
        await JobWait.Done(job);
        return job;
    }

    public string Write(string relative, string content = "synthetic test content") => Jobs.Write(relative, content);

    public bool WasScanned(string path) => Scanned.Contains(path, StringComparer.OrdinalIgnoreCase);

    public void Dispose() => Cached.Dispose();
}

/// <summary>
/// C6 Full Scan: drive selection, a temp-tree scan end to end (all files, the cache on the repeat), the depth / entry caps,
/// cloud placeholders, system paging files and locked files, pause / resume / cancel, the C1 L2 / L4 follow-ups, and an
/// opt-in real-machine run. Synthetic files only.
/// </summary>
public sealed class FullScanTests(ITestOutputHelper output)
{
    [Fact]
    public void DriveSelection_TakesFixedVolumesOnce_AndLeavesOutRemovableNetworkOpticalAndSubstLetters()
    {
        var notes = new List<string>();
        var chosen = FullScanVolumes.Select(
        [
            new(@"E:\", 2, null, null), // removable
            new(@"D:\", 3, @"\\?\Volume{d}\", 10),
            new(@"C:\", 3, @"\\?\Volume{c}\", 20),
            new(@"Z:\", 4, null, null), // network
            new(@"F:\", 5, null, null), // optical
            new(@"S:\", 3, null, null), // SUBST alias of a folder: reports its target's type, but isn't a volume
            new(@"V:\", 3, @"\\?\Volume{c}\", 20), // the same volume under a second letter
        ], notes);

        Assert.Equal([@"C:\", @"D:\"], chosen.Select(d => d.Root));
        Assert.Contains(notes, n => n.StartsWith(@"S:\", StringComparison.Ordinal));
        Assert.Contains(notes, n => n.StartsWith(@"V:\", StringComparison.Ordinal));
        Assert.Contains(notes, n => n.Contains("3 removable, network, optical", StringComparison.Ordinal));
    }

    [Fact]
    public void RealDriveList_ReportsTheSystemDriveAsAFixedVolume()
    {
        string system = Path.GetPathRoot(Environment.SystemDirectory)!;
        var drive = Assert.Single(new WindowsVolumeSource().List(), d => d.Root.Equals(system, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(FullScanVolumes.DriveFixed, drive.DriveType);
        Assert.StartsWith(@"\\?\Volume{", drive.VolumeName, StringComparison.OrdinalIgnoreCase);
        Assert.True(drive.UsedBytes > 0);
    }

    [Fact]
    public async Task TempTreeFullScan_ScansEveryFile_SkipsSystemFiles_AndTheRepeatComesFromTheCache()
    {
        using var f = new FullScanHarness();
        var files = new[]
        {
            f.Write("readme.txt"), f.Write(@"photos\cat.jpg"), f.Write(@"a\b\c\d\e\deep.dat"), f.Write("noextension"),
            f.Write(@"Program Files\Tool\mal-tool.exe"),
        };
        var pagefile = f.Write("pagefile.sys");
        var snapshot = f.Write(@"System Volume Information\tracking.log");
        var nestedPagefile = f.Write(@"games\pagefile.sys"); // only the root's is the system's

        var first = await f.RunAsync();

        Assert.Equal(ScanJobState.Completed, first.State);
        Assert.True(first.IsComplete);
        Assert.Equal(ScanTrigger.FullScan, first.Request.Trigger);
        Assert.Equal(["Running programs", "Autostart entries", "Fixed drives"], first.Phases.Select(p => p.Name));
        Assert.All([.. files, nestedPagefile], p => Assert.True(f.WasScanned(p), p));
        Assert.False(f.WasScanned(pagefile));
        Assert.False(f.WasScanned(snapshot));
        Assert.Contains(first.Phases[2].Notes, n => n.Contains("1 system paging files", StringComparison.Ordinal));
        Assert.Equal(Verdict.Malicious, Assert.Single(first.Results).Verdict);
        Assert.Equal(100, first.GetProgress().PercentDone);
        Assert.Equal(FullScanOptions.NoBudget, first.Request.TimeBudget); // no time budget: runs to completion

        f.Scanned.Clear();
        var repeat = await f.RunAsync();

        Assert.Equal(5, repeat.GetProgress().Counters.Cached); // every clean file came from the cache
        Assert.Equal([files[4]], f.Scanned, StringComparer.OrdinalIgnoreCase); // only the Malicious file (never cached) is read again
        output.WriteLine($"first: {first.Elapsed.TotalMilliseconds:0} ms, repeat: {repeat.Elapsed.TotalMilliseconds:0} ms");
    }

    [Fact]
    public async Task DepthAndEntryCaps_StopAHugeTree_AndMarkThePhaseIncomplete()
    {
        using var deep = new FullScanHarness();
        deep.Options.MaxDepth = 2;
        var shallow = deep.Write(@"one\two\ok.txt");
        var tooDeep = deep.Write(@"one\two\three\hidden.txt");

        var job = await deep.RunAsync();

        Assert.True(deep.WasScanned(shallow));
        Assert.False(deep.WasScanned(tooDeep));
        Assert.Equal(ScanPhaseState.Incomplete, job.Phases[2].State);
        Assert.Contains(job.Phases[2].Notes, n => n.Contains("deeper than 2 levels", StringComparison.Ordinal));

        using var wide = new FullScanHarness();
        wide.Options.MaxEntries = 10;
        for (int i = 0; i < 6; i++)
        {
            wide.Write($@"d{i}\f1.txt");
            wide.Write($@"d{i}\f2.txt");
        }

        var capped = await wide.RunAsync();

        Assert.True(wide.Scanned.Count < 12);
        Assert.Equal(ScanPhaseState.Incomplete, capped.Phases[2].State);
        Assert.Contains(capped.Phases[2].Notes, n => n.Contains("entry limit", StringComparison.Ordinal));
        Assert.Equal(ScanJobState.Completed, capped.State);
        Assert.False(capped.IsComplete);
    }

    [Fact]
    public async Task CloudPlaceholders_FoldersArentListed_AndFilesArentQueued_CountedAsOffline()
    {
        using var f = new FullScanHarness();
        var local = f.Write(@"OneDrive\local.docx");
        var inside = f.Write(@"OneDrive\Unpopulated\remote.docx");
        var dehydrated = f.Write(@"OneDrive\dehydrated.xlsx");
        string folder = Path.GetDirectoryName(inside)!;
        File.SetAttributes(dehydrated, FileAttributes.Offline);
        File.SetAttributes(folder, FileAttributes.Directory | FileAttributes.Offline); // what an unpopulated placeholder folder reports
        try
        {
            var job = await f.RunAsync();

            Assert.True(f.WasScanned(local));
            Assert.False(f.WasScanned(inside));
            Assert.False(f.WasScanned(dehydrated));
            Assert.Contains(job.Phases[2].Notes, n => n.Contains("2 cloud placeholders", StringComparison.Ordinal));
        }
        finally
        {
            File.SetAttributes(folder, FileAttributes.Directory);
            File.SetAttributes(dehydrated, FileAttributes.Normal);
        }
    }

    [Fact]
    public async Task LockedFiles_TheRootPagefileIsSkipped_OtherLockedFilesAreReportedLocked_AndTheScanGoesOn()
    {
        using var f = new FullScanHarness();
        var pagefile = f.Write("pagefile.sys");
        var hive = f.Write(@"Windows\System32\config\SOFTWARE");
        var clean = f.Write("after.txt");
        using (new FileStream(pagefile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        using (new FileStream(hive, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var job = await f.RunAsync();

            Assert.Equal(ScanJobState.Completed, job.State);
            Assert.DoesNotContain(job.Results, r => r.Path.EndsWith("pagefile.sys", StringComparison.OrdinalIgnoreCase));
            var locked = Assert.Single(job.Results);
            Assert.EndsWith("SOFTWARE", locked.Path, StringComparison.Ordinal);
            Assert.Equal(ScanSkipReason.Locked, locked.SkipReason);
            Assert.True(f.WasScanned(clean));
        }
    }

    [Fact]
    public async Task PauseResumeCancel_WorkAcrossTheDriveWalk()
    {
        using var f = new FullScanHarness { Delay = TimeSpan.FromMilliseconds(30) };
        for (int i = 0; i < 60; i++)
        {
            f.Write($@"data\file{i}.bin", $"content {i}");
        }

        var job = f.Start();
        await WaitUntil(() => f.Scanned.Count >= 3);
        Assert.True(job.Pause());
        await JobWait.ForState(job, ScanJobState.Paused);
        long done = job.GetProgress().FilesDone;
        await Task.Delay(200);
        Assert.Equal(done, job.GetProgress().FilesDone); // no progress while paused
        Assert.Equal(ScanJobState.Paused, job.State);

        Assert.True(job.Resume());
        await WaitUntil(() => job.GetProgress().FilesDone > done);
        Assert.True(job.Cancel());
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Cancelled, job.State);
        Assert.True(job.GetProgress().FilesDone < 60);
        Assert.Equal(ScanPhaseState.Incomplete, job.Phases[2].State);
        Assert.Contains(job.Warnings, w => w.Message.Contains("cancelled", StringComparison.Ordinal));
    }

    [Fact]
    public void ProgressAcrossPhases_WeighsTheDriveWalkByItsShare()
    {
        double[] weights = [1, 1.5, 100];
        Assert.Equal(0, ScanJob.ProgressAcrossPhases(weights, 0, 0));
        Assert.Equal((2.5 + 50) / 102.5, ScanJob.ProgressAcrossPhases(weights, 2, 0.5), 6);
        Assert.Equal(1, ScanJob.ProgressAcrossPhases(weights, 2, 1));
    }

    [Fact]
    public async Task RestrictedFileRoot_TheSizeIsNotCounted_BeforeTheRequestersAccessCheck()
    {
        using var h = new ScanJobHarness();
        var secret = h.Write("secret.bin", new string('x', 5000));
        var job = h.Service.Create(new ScanJobRequest([secret], ScanTrigger.CustomScan) { Access = new DenyAll(), Origin = ScanJobOrigin.StandardUser });
        Assert.Equal(ScanJobStartResult.Started, h.Service.Start(job.Id));
        await JobWait.Done(job);

        Assert.Equal(0, job.GetProgress().BytesTotal); // review C1 L2: nothing about the file, not even its size
        Assert.Equal(ScanSkipReason.NoAccess, Assert.Single(job.Results).SkipReason);
    }

    [Fact]
    public void RemoteProbe_AnUnexpectedAnswer_IsUnknown_AndLoggedOncePerVolume()
    {
        var logger = new ListLogger<FullScanTests>();
        ulong volume = 1;
        var probe = new RemoteFileProbe(_ => (false, 5 /* ERROR_ACCESS_DENIED: not a known "local" answer */), _ => volume) { Logger = logger };
        using var handle = File.OpenHandle(Environment.ProcessPath!);

        Assert.Equal(FileLocation.Unknown, probe.Classify(handle));
        Assert.Equal(FileLocation.Unknown, probe.Classify(handle));
        volume = 2;
        Assert.Equal(FileLocation.Unknown, probe.Classify(handle));

        Assert.Equal(2, logger.Count(Microsoft.Extensions.Logging.LogLevel.Warning));
        Assert.Contains(logger.Lines, l => l.Message.Contains("Win32 error 5", StringComparison.Ordinal));
        Assert.Equal(5, probe.UnknownVolumes[1]);
        Assert.Equal(FileLocation.Local, new RemoteFileProbe(_ => (false, 87), _ => 1).Classify(handle));
    }

    /// <summary>
    /// Real-machine smoke test (opt-in, <c>SAPAV_TEST_SLOW=1</c>): the drive walk over this PC's real fixed drives with the
    /// in-process scanner (the shipped rules) and a temp cache, capped at 20,000 directory entries, run twice (cold, then
    /// from the cache). No verdict handler, so nothing is quarantined; nothing is written outside the temp folder.
    /// </summary>
    [RequiresFact(Requires.SlowTests)]
    public async Task RealMachine_FullScan_CappedRun_ReportsTimings_ColdAndCached()
    {
        using var temp = new TempDir();
        var sandbox = new SandboxOptions();
        using var broker = new InProcessScanBroker(new DirectoryScanRulesSource(sandbox), NullLogger.Instance);
        await broker.ReloadRulesAsync();
        var cache = ScanCache.TryCreate(new ScanCacheOptions { Folder = Path.Combine(temp.Path, "Cache") }, sandbox.ResolvedBlocklistPath, broker,
            new FixedKeyProvider(CacheHarness.Key), CacheHarness.Policy, TimeProvider.System, NullLogger.Instance, parentIsDataRoot: false)!;
        var service = new ScanJobService(new ScanJobOptions { ThreadsPerJob = 2 }, broker, ExclusionSet.Always(new FolderSet([])), null, null,
            TimeProvider.System, NullLogger.Instance, cache: cache);
        var scanner = new PersistenceScanner(broker, new RecordingAlertSink(), TimeProvider.System);
        var factory = new FullScanFactory(new FullScanOptions { MaxEntries = 20_000 }, new FakeProcessSource(),
            new FakeCollector(new PersistenceCollection([], [], TimeSpan.Zero)), scanner, new WindowsVolumeSource());
        try
        {
            foreach (string run in new[] { "cold", "cached" })
            {
                var clock = Stopwatch.StartNew();
                var job = service.Create(factory.CreateRequest(ScanJobOrigin.Engine));
                service.Start(job.Id);
                await job.Completion.WaitAsync(TimeSpan.FromMinutes(20));
                var p = job.GetProgress();
                output.WriteLine($"{run}: {job.State} in {clock.Elapsed.TotalSeconds:0.0} s; {p.FilesDone} files, {p.BytesDone / (1024 * 1024)} MiB, "
                    + $"{p.Counters.Cached} from the cache, {p.Counters.NotScanned} not scanned, {p.Counters.Suspicious} suspicious; "
                    + $"{(p.FilesDone / Math.Max(0.001, clock.Elapsed.TotalSeconds)):0} files/s; {string.Join(" | ", job.Phases[^1].Notes)}");
                Assert.True(job.State == ScanJobState.Completed, job.State.ToString());
            }
        }
        finally
        {
            service.Dispose();
            cache.Dispose();
            SqliteConnection.ClearAllPools();
        }
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + JobWait.Timeout;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "timed out waiting");
            await Task.Delay(10);
        }
    }

    private sealed class DenyAll : IScanAccessCheck
    {
        public bool CanList(Microsoft.Win32.SafeHandles.SafeFileHandle directory) => false;

        public bool CanRead(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => false;
    }
}
