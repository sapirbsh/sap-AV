using SapAV.Core.Models;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>B3 scan jobs with an in-memory broker: lifecycle, back-pressure, pause/resume/cancel, budget, robustness.</summary>
public sealed class ScanJobTests
{
    [Fact]
    public async Task Job_ScansEveryFileInTheTree_OnDedicatedBackgroundThreads_AndCompletes()
    {
        using var h = new ScanJobHarness();
        h.Options.ThreadsPerJob = 2;
        h.Write("a.txt");
        h.Write(@"sub\b.txt");
        h.Write(@"sub\deeper\mal-c.bin");
        h.Write(@"sub\sus-d.bin");

        var (job, states) = h.Start();
        await JobWait.Done(job);

        var progress = job.GetProgress();
        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.Equal(4, progress.FilesDone);
        Assert.Equal(4, progress.FilesTotal);
        Assert.Equal(new ScanJobCounters(2, 1, 1, 0, 0, 0, 0, 0), progress.Counters);
        Assert.Equal(2, job.Results.Count); // Clean files are only counted
        Assert.Equal([ScanJobState.Running, ScanJobState.Completed], states.Select(s => s.To));
        Assert.All(h.Broker.BackgroundModeSeen, Assert.True); // THREAD_MODE_BACKGROUND_BEGIN on the scanning thread
        Assert.All(h.Broker.ThreadPoolSeen, Assert.False);
        Assert.Null(progress.Eta); // finished: no estimate
    }

    [Fact]
    public async Task FullQueue_BlocksTheEnumerator_TotalUnknownMeanwhile()
    {
        using var h = new ScanJobHarness();
        h.Options.QueueCapacity = 2;
        for (int i = 0; i < 30; i++)
        {
            h.Write($"f{i:00}.txt");
        }

        var release = new TaskCompletionSource();
        h.Broker.OnScan = async (_, _, _) =>
        {
            await release.Task;
            return null;
        };
        var blocked = new TaskCompletionSource();
        var job = h.Service.Create(new ScanJobRequest([h.Root], ScanTrigger.CustomScan));
        job.EnumeratorBlocked = () => blocked.TrySetResult();
        h.Service.Start(job.Id);

        await blocked.Task.WaitAsync(JobWait.Timeout);
        var during = job.GetProgress();
        Assert.InRange(during.FilesFound, 2, 2 + 1); // queue capacity + the file the one scan thread holds
        Assert.Null(during.FilesTotal);
        Assert.Null(during.Eta);

        release.SetResult();
        await JobWait.Done(job);
        Assert.Equal(30, job.GetProgress().FilesDone);
    }

    [Fact]
    public async Task Pause_StopsProgress_ResumeContinues()
    {
        using var h = new ScanJobHarness();
        for (int i = 0; i < 6; i++)
        {
            h.Write($"f{i}.txt");
        }

        var firstStarted = new TaskCompletionSource();
        var releaseFirst = new TaskCompletionSource();
        h.Broker.OnScan = async (_, _, _) =>
        {
            if (firstStarted.TrySetResult())
            {
                await releaseFirst.Task;
            }

            return null;
        };

        var (job, states) = h.Start();
        await firstStarted.Task.WaitAsync(JobWait.Timeout);
        Assert.True(job.Pause());
        Assert.Equal(ScanJobState.Pausing, job.State); // the in-flight file still finishes
        releaseFirst.SetResult();
        await JobWait.ForState(job, ScanJobState.Paused);

        Assert.Equal(1, job.GetProgress().FilesDone);
        Assert.Equal(1, h.Broker.Calls); // every job thread is parked: nothing else started
        Assert.False(job.Pause());

        Assert.True(job.Resume());
        await JobWait.Done(job);
        Assert.Equal(6, job.GetProgress().FilesDone);
        Assert.Equal(
            [ScanJobState.Running, ScanJobState.Pausing, ScanJobState.Paused, ScanJobState.Running, ScanJobState.Completed],
            states.Select(s => s.To));
    }

    [Fact]
    public async Task Cancel_EndsCleanly_WithPartialResults()
    {
        using var h = new ScanJobHarness();
        h.Write("mal-1.bin");
        h.Write("x2.txt");
        h.Write("x3-hang.txt");
        h.Write("x4.txt");
        var hanging = new TaskCompletionSource();
        h.Broker.OnScan = async (item, _, token) =>
        {
            if (item.Path.EndsWith("hang.txt", StringComparison.Ordinal))
            {
                hanging.TrySetResult();
                await Task.Delay(Timeout.Infinite, token); // honours the job token only
            }

            return null;
        };

        var (job, states) = h.Start();
        await hanging.Task.WaitAsync(JobWait.Timeout);
        Assert.True(job.Cancel());
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Cancelled, job.State);
        Assert.Equal(2, job.GetProgress().FilesDone); // the hung file is not counted as done
        Assert.Single(job.Results); // the Malicious one before the cancel is kept
        Assert.Equal([ScanJobState.Cancelling, ScanJobState.Cancelled], states.TakeLast(2).Select(s => s.To));
        Assert.False(job.Resume());
    }

    [Fact]
    public async Task ExceptionInAStep_IsNotScannedError_AndTheJobContinues()
    {
        using var h = new ScanJobHarness();
        h.Write("1-throws.txt");
        h.Write("2-foreign-cancel.txt");
        h.Write("3-fine.txt");
        h.Broker.OnScan = (item, _, _) => Path.GetFileName(item.Path) switch
        {
            "1-throws.txt" => throw new InvalidOperationException("boom"),
            "2-foreign-cancel.txt" => throw new OperationCanceledException(new CancellationToken(canceled: true)), // not the job's token
            _ => Task.FromResult<SapAV.Core.Scanning.FileScanReport?>(null),
        };

        var (job, _) = h.Start();
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Completed, job.State);
        Assert.Equal(3, job.GetProgress().FilesDone);
        Assert.Equal(2, job.GetProgress().Counters.NotScanned);
        Assert.All(job.Results, r =>
        {
            Assert.Equal(ScanStatus.Error, r.Status);
            Assert.Null(r.Verdict); // never Clean
        });
    }

    [Fact]
    public async Task TimeBudget_RunningTimeOnly_EndsTimedOut_WithPartialResults()
    {
        var time = new ManualTime();
        using var h = new ScanJobHarness(time);
        for (int i = 0; i < 5; i++)
        {
            h.Write($"f{i}.txt");
        }

        h.Broker.OnScan = (_, _, _) =>
        {
            time.Now += TimeSpan.FromMinutes(10); // each file "takes" 10 minutes
            return Task.FromResult<SapAV.Core.Scanning.FileScanReport?>(null);
        };
        var job = h.Service.Create(new ScanJobRequest([h.Root], ScanTrigger.FullScan, TimeSpan.FromMinutes(15)));
        h.Service.Start(job.Id);
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.TimedOut, job.State);
        Assert.Equal(2, job.GetProgress().FilesDone); // 20 min > 15 min budget: the third file never starts
        Assert.Contains(job.Warnings, w => w.Message.Contains("time budget", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExcludedFolder_IsNeverScanned_RootOrNested()
    {
        using var h = new ScanJobHarness();
        h.Write("a.txt");
        h.Write(@"engine-data\rules\self-matching.yar", "rule x { condition: true }");
        h.Excluded.Add(Path.Combine(h.Root, "ENGINE-DATA")); // case-insensitive
        var excludedFile = Path.Combine(h.Root, "engine-data", "rules", "self-matching.yar");

        var (job, _) = h.Start(h.Root, excludedFile);
        await JobWait.Done(job);

        Assert.Equal(1, h.Broker.Calls);
        Assert.Equal(2, job.GetProgress().Counters.Excluded); // the folder in the walk + the explicit file root
    }

    [RequiresFact(Requires.Junctions)]
    public async Task Walk_DoesNotFollowJunctions()
    {
        using var h = new ScanJobHarness();
        h.Write("a.txt");
        var outside = Directory.CreateDirectory(Path.Combine(h.Base, "outside")).FullName;
        File.WriteAllText(Path.Combine(outside, "mal-outside.bin"), "x");
        Assert.Null(SapAV.Core.Tests.TestSupport.RawJunction.TryCreate(Path.Combine(h.Root, "link"), @"\??\" + outside));

        var (job, _) = h.Start();
        await JobWait.Done(job);

        Assert.Equal(1, h.Broker.Calls);
        Assert.Equal(1, job.Skipped.SkippedLinks);
    }

    [Fact]
    public void Walk_FollowsNonSurrogateReparseFolders_LikeOneDrive_ButNotUnknownTags()
    {
        using var temp = new TempDir();
        var cloud = Directory.CreateDirectory(Path.Combine(temp.Path, "cloud")).FullName;
        File.WriteAllText(Path.Combine(cloud, "f.txt"), "x");
        var walker = new ScanTreeWalker(new FolderSet([]), _ => 0x9000001A /* IO_REPARSE_TAG_CLOUD_1: not a name surrogate */);
        var unknown = new ScanTreeWalker(new FolderSet([]), _ => null);


        Assert.False(walker.IsLink(cloud, FileAttributes.Directory | FileAttributes.ReparsePoint));
        Assert.True(unknown.IsLink(cloud, FileAttributes.Directory | FileAttributes.ReparsePoint));
        Assert.True(SapAV.Engine.Scanning.Native.ScanNative.IsNameSurrogate(0xA0000003)); // mount point
        Assert.True(SapAV.Engine.Scanning.Native.ScanNative.IsNameSurrogate(0xA000000C)); // symlink
    }

    [Fact]
    public async Task Service_RefusesMoreThanMaxConcurrentJobs()
    {
        using var h = new ScanJobHarness();
        h.Options.MaxConcurrentJobs = 1;
        h.Write("a.txt");
        var release = new TaskCompletionSource();
        h.Broker.OnScan = async (_, _, _) =>
        {
            await release.Task;
            return null;
        };

        var (first, _) = h.Start();
        var second = h.Service.Create(new ScanJobRequest([h.Root], ScanTrigger.CustomScan));
        Assert.Equal(ScanJobStartResult.TooManyJobs, h.Service.Start(second.Id));
        Assert.Equal(ScanJobStartResult.AlreadyStarted, h.Service.Start(first.Id));
        Assert.Equal(ScanJobStartResult.NotFound, h.Service.Start(Guid.NewGuid()));

        release.SetResult();
        await JobWait.Done(first);
        Assert.Equal(ScanJobStartResult.Started, h.Service.Start(second.Id));
        await JobWait.Done(second);
    }

    [Fact]
    public void Request_RejectsEmptyAndRelativePaths()
    {
        using var h = new ScanJobHarness();
        Assert.Throws<ArgumentException>(() => h.Service.Create(new ScanJobRequest([], ScanTrigger.CustomScan)));
        Assert.Throws<ArgumentException>(() => h.Service.Create(new ScanJobRequest([@"relative\dir"], ScanTrigger.CustomScan)));
    }

    [Fact]
    public void StateMachine_AllowsOnlyTheDocumentedTransitions()
    {
        Assert.True(ScanJobStateMachine.CanTransition(ScanJobState.Paused, ScanJobState.Running));
        Assert.True(ScanJobStateMachine.CanTransition(ScanJobState.Paused, ScanJobState.Cancelling));
        Assert.False(ScanJobStateMachine.CanTransition(ScanJobState.Created, ScanJobState.Paused));
        Assert.False(ScanJobStateMachine.CanTransition(ScanJobState.Cancelling, ScanJobState.Running));
        Assert.All(new[] { ScanJobState.Completed, ScanJobState.Cancelled, ScanJobState.TimedOut, ScanJobState.Failed },
            s => Assert.True(ScanJobStateMachine.IsTerminal(s)));
    }
}
