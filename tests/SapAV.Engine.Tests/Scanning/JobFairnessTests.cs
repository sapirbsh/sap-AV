using SapAV.Core.Models;
using SapAV.Engine.Pipe;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// Review B H3: one standard user can't block all scanning. Standard-user jobs get at most one job slot (the rest stay for
/// administrator and engine jobs), pauses are bounded, a disconnected user's jobs are cancelled, and engine work gets the
/// next free scan worker first. Time is a fake clock throughout.
/// </summary>
public sealed class JobFairnessTests : IDisposable
{
    private readonly ManualTime _time = new();
    private readonly ScanJobHarness _h;
    private readonly TaskCompletionSource _userGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _hold = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly string _userTree;
    private readonly string _busyTree;

    public JobFairnessTests()
    {
        _h = new ScanJobHarness(_time);
        _userTree = Path.GetDirectoryName(_h.Write(@"user\a.txt"))!;
        _h.Write(@"user\b.txt");
        _busyTree = Path.GetDirectoryName(_h.Write(@"busy\c.txt"))!;
        _h.Broker.OnScan = async (item, _, ct) =>
        {
            // "busy" jobs stay busy until the test ends; the user job's first file waits until it was asked to pause
            await (item.Path.StartsWith(_busyTree, StringComparison.Ordinal) ? _hold.Task : _userGate.Task).WaitAsync(ct);
            return null;
        };
    }

    public void Dispose()
    {
        _userGate.TrySetResult();
        _hold.TrySetResult();
        _h.Dispose();
    }

    private ScanJob Create(ScanJobOrigin origin, string? root = null) =>
        _h.Service.Create(new ScanJobRequest([root ?? _busyTree], ScanTrigger.CustomScan) { Origin = origin });

    private async Task<ScanJob> PausedUserJobAsync()
    {
        var job = Create(ScanJobOrigin.StandardUser, _userTree);
        Assert.Equal(ScanJobStartResult.Started, _h.Service.Start(job.Id));
        var paused = JobWait.ForState(job, ScanJobState.Paused);
        Assert.True(job.Pause());
        _userGate.TrySetResult(); // the file in flight finishes, then the job parks
        await paused;
        return job;
    }

    [Fact]
    public async Task APausedStandardUserJob_DoesNotBlockAnAdminJob_AndStandardUsersShareOneSlot()
    {
        await PausedUserJobAsync();

        var secondUserJob = Create(ScanJobOrigin.StandardUser); // the same or another standard user
        var adminJob = Create(ScanJobOrigin.Administrator);
        var engineJob = Create(ScanJobOrigin.Engine);

        Assert.Equal(ScanJobStartResult.TooManyJobs, _h.Service.Start(secondUserJob.Id));
        Assert.Equal(ScanJobStartResult.Started, _h.Service.Start(adminJob.Id)); // the reserved slot
        Assert.Equal(ScanJobStartResult.TooManyJobs, _h.Service.Start(engineJob.Id)); // MaxConcurrentJobs = 2 in total
    }

    [Fact]
    public async Task AJobPausedLongerThanTheLimit_IsCancelled_AndItsSlotIsFreed()
    {
        var job = await PausedUserJobAsync();

        _time.Now += _h.Options.MaxPauseTime - TimeSpan.FromMinutes(1);
        Assert.Equal(0, _h.Service.EnforceLimits());
        _time.Now += TimeSpan.FromMinutes(2);
        Assert.Equal(1, _h.Service.EnforceLimits());
        await JobWait.Done(job);

        Assert.Equal(ScanJobState.Cancelled, job.State);
        Assert.Contains(job.Warnings, w => w.Message.Contains("paused for longer than", StringComparison.Ordinal));
        Assert.Equal(ScanJobStartResult.Started, _h.Service.Start(Create(ScanJobOrigin.StandardUser).Id));
    }

    [Fact]
    public void Options_KeepAtLeastOneSlotForAdministratorAndEngineJobs()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScanJobOptions { MaxConcurrentJobs = 2, MaxRunningStandardUserJobs = 2 }.Validate());
        new ScanJobOptions { MaxConcurrentJobs = 4, MaxRunningStandardUserJobs = 3 }.Validate();
        new ScanJobOptions { MaxConcurrentJobs = 1, MaxRunningStandardUserJobs = 1 }.Validate(); // nothing to reserve
    }

    [Fact]
    public async Task AStandardUsersRunningJob_IsCancelled_OnceThatUserHasBeenGoneForTheOrphanTimeout()
    {
        var options = new PipeServerOptions();
        var registry = new JobRegistry(_h.Service, options, _time);
        var user = new FakeClientIdentity();
        var admin = new FakeClientIdentity(isAdmin: true);
        var userSession = new object();
        var (userJob, _, _) = registry.TryCreate(user, userSession, Request(ScanJobOrigin.StandardUser), null);
        var adminSession = new object();
        var (adminJob, _, _) = registry.TryCreate(admin, adminSession, Request(ScanJobOrigin.Administrator), null);
        Assert.Equal(ScanJobStartResult.Started, _h.Service.Start(userJob!.Id));
        Assert.Equal(ScanJobStartResult.Started, _h.Service.Start(adminJob!.Id));

        registry.CancelPendingOf(userSession); // the user's GUI went away; the running job is not cancelled yet
        registry.CancelPendingOf(adminSession);
        _time.Now += options.OrphanJobTimeout - TimeSpan.FromMinutes(1);
        registry.Prune();
        Assert.Equal(ScanJobState.Running, userJob.State);

        _time.Now += TimeSpan.FromMinutes(2);
        registry.Prune();
        await JobWait.Done(userJob);

        Assert.Equal(ScanJobState.Cancelled, userJob.State);
        Assert.Equal(ScanJobState.Running, adminJob.State); // administrators' jobs keep running
    }

    [Fact]
    public void AStandardUserWhoReconnected_KeepsTheirJob()
    {
        var options = new PipeServerOptions();
        var registry = new JobRegistry(_h.Service, options, _time);
        var user = new FakeClientIdentity();
        var first = new object();
        var (job, _, _) = registry.TryCreate(user, first, Request(ScanJobOrigin.StandardUser), null);
        Assert.Equal(ScanJobStartResult.Started, _h.Service.Start(job!.Id));

        registry.CancelPendingOf(first);
        registry.Seen(new object(), user.User); // a new connection of the same user
        _time.Now += options.OrphanJobTimeout * 2;
        registry.Prune();

        Assert.Equal(ScanJobState.Running, job.State);
    }

    private ScanJobRequest Request(ScanJobOrigin origin) => new([_busyTree], ScanTrigger.CustomScan) { Origin = origin };

    [Fact]
    public void EngineJobsGetHighPriority_StandardUsersLow()
    {
        Assert.Equal(ScanPriority.High, ScanJob.PriorityOf(ScanJobOrigin.Engine));
        Assert.Equal(ScanPriority.Normal, ScanJob.PriorityOf(ScanJobOrigin.Administrator));
        Assert.Equal(ScanPriority.Low, ScanJob.PriorityOf(ScanJobOrigin.StandardUser));
    }
}

/// <summary>Review B H3: the broker's worker pool hands a free worker to engine work first and keeps one from user jobs.</summary>
public sealed class PrioritySlotPoolTests
{
    [Fact]
    public async Task AReturnedWorker_GoesToTheHighestPriorityWaiter()
    {
        var pool = new PrioritySlotPool<string>(["w1"]);
        var held = await pool.RentAsync(ScanPriority.Normal, CancellationToken.None);
        var low = pool.RentAsync(ScanPriority.Low, CancellationToken.None);
        var normal = pool.RentAsync(ScanPriority.Normal, CancellationToken.None);
        var high = pool.RentAsync(ScanPriority.High, CancellationToken.None);

        pool.Return(held, ScanPriority.Normal);
        Assert.Equal("w1", await high.WaitAsync(JobWait.Timeout));
        Assert.False(low.IsCompleted || normal.IsCompleted);

        pool.Return("w1", ScanPriority.High);
        Assert.Equal("w1", await normal.WaitAsync(JobWait.Timeout));
        pool.Return("w1", ScanPriority.Normal);
        Assert.Equal("w1", await low.WaitAsync(JobWait.Timeout));
    }

    [Fact]
    public async Task StandardUserScans_NeverHoldTheLastWorker()
    {
        var pool = new PrioritySlotPool<string>(["w1", "w2"]);
        var first = await pool.RentAsync(ScanPriority.Low, CancellationToken.None);
        var second = pool.RentAsync(ScanPriority.Low, CancellationToken.None);

        Assert.False(second.IsCompleted); // one worker is kept free
        var engine = await pool.RentAsync(ScanPriority.High, CancellationToken.None).WaitAsync(JobWait.Timeout);
        pool.Return(engine, ScanPriority.High);
        Assert.False(second.IsCompleted);

        pool.Return(first, ScanPriority.Low);
        Assert.Equal(first, await second.WaitAsync(JobWait.Timeout));
    }

    [Fact]
    public async Task ACancelledWaiter_IsSkipped()
    {
        var pool = new PrioritySlotPool<string>(["w1"]);
        var held = await pool.RentAsync(ScanPriority.Normal, CancellationToken.None);
        using var cts = new CancellationTokenSource();
        var cancelled = pool.RentAsync(ScanPriority.High, cts.Token);
        var waiting = pool.RentAsync(ScanPriority.Low, CancellationToken.None);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        pool.Return(held, ScanPriority.Normal);

        Assert.Equal("w1", await waiting.WaitAsync(JobWait.Timeout));
    }
}
