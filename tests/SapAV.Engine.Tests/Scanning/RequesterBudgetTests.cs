using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Alerts;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Alerts;
using SapAV.Engine.Tests.Pipe;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// Section B M1 / M2 (C1): per-requester budgets. A user's quarantine requests have a quota and a rate limit, and a
/// user's own scans have their own alert and auto-quarantine budgets, so they can't use up the engine's.
/// </summary>
public sealed class RequesterBudgetTests
{
    private static readonly AlertBudget Alice = AlertBudget.ForRequester(FakeClientIdentity.NewUserSid());

    private static AlertDispatcher Dispatcher(IAlertSink sink, int maxPerWindow = 100, int capacity = 64) =>
        new(sink, new ManualTime(), NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), maxPerWindow, capacity);

    private static string Sha(int i) => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(BitConverter.GetBytes(i)));

    private static Alert Malicious(int i, ScanTrigger trigger = ScanTrigger.CustomScan) =>
        new(Guid.NewGuid(), DateTimeOffset.UnixEpoch, AlertType.MaliciousFile, Verdict.Malicious, $@"C:\Users\alice\flood\{i}.exe", Sha(i), null, null,
            "T1204.002", [], ["YARA rule matched"], null, AlertAction.None, trigger, EngineInfo.Version);

    [Fact]
    public void AUserFloodOfMaliciousAlerts_UsesOnlyThatUsersKeys_TheEngineAlertStillGoesThrough()
    {
        var sink = new RecordingAlertSink();
        using var dispatcher = Dispatcher(sink, capacity: 4096);

        int accepted = Enumerable.Range(0, AlertDispatcher.MaxKeysPerRequesterWindow + 50).Count(i => dispatcher.Post(Malicious(i), Alice));
        bool engine = dispatcher.Post(Malicious(-1, ScanTrigger.RealTime)); // the engine's own (real-time) budget

        Assert.Equal(AlertDispatcher.MaxKeysPerRequesterWindow, accepted);
        Assert.True(engine);
    }

    [Fact]
    public void AUsersSuspiciousFlood_HitsOnlyTheirOwnCap()
    {
        var sink = new RecordingAlertSink();
        using var dispatcher = Dispatcher(sink, maxPerWindow: 5);

        var suspicious = Enumerable.Range(0, 10).Select(i => SampleAlerts.Create(AlertType.SuspiciousFile, path: $@"C:\x\{i}.exe")).ToArray();
        int user = suspicious.Count(a => dispatcher.Post(a, Alice));
        bool engine = dispatcher.Post(SampleAlerts.Create(AlertType.SuspiciousFile, path: @"C:\x\engine.exe"));

        Assert.Equal(5, user);
        Assert.True(engine);
    }

    [Fact]
    public async Task UserAlerts_FillAtMostHalfTheQueue_TheEngineKeepsTheRest()
    {
        using var sink = new BlockingAlertSink();
        using var dispatcher = Dispatcher(sink, capacity: 4);
        Assert.True(dispatcher.Post(SampleAlerts.Create(path: @"C:\x\first.exe")));
        await sink.Entered.Task.WaitAsync(JobWait.Timeout); // the writer is stuck; the queue (4) is empty

        int user = Enumerable.Range(0, 6).Count(i => dispatcher.Post(Malicious(i), Alice));
        int engine = Enumerable.Range(0, 3).Count(i => dispatcher.Post(SampleAlerts.Create(path: $@"C:\x\engine{i}.exe")));

        Assert.Equal(2, user);
        Assert.Equal(2, engine); // the engine's half was free; only a full queue stops it
        sink.Release();
        Assert.True(dispatcher.Drain(JobWait.Timeout));
    }

    [Fact]
    public void TheSummary_ListsDistinctHashes_Capped()
    {
        var sink = new RecordingAlertSink();
        using var dispatcher = Dispatcher(sink, maxPerWindow: 1);

        for (int i = 0; i < 30; i++)
        {
            dispatcher.Post(SampleAlerts.Create(AlertType.SuspiciousFile, path: $@"C:\x\{i}.exe") is var a
                ? new Alert(a.AlertId, a.Timestamp, a.Type, a.Verdict, a.FilePath, Sha(i % 20), null, null, a.TechniqueId, [], a.Reasons, null, a.Action, a.Trigger, a.EngineVersion)
                : null!, Alice);
        }

        dispatcher.FlushSummary();
        Assert.True(dispatcher.Drain(JobWait.Timeout));

        var summary = Assert.Single(sink.Alerts, a => a.Type == AlertType.AlertsSuppressed);
        Assert.Contains("29 from scans a user requested", summary.Reasons[0], StringComparison.Ordinal);
        var hashes = summary.Reasons[1];
        Assert.Contains($"({AlertDispatcher.MaxSummaryHashes} distinct, more not listed)", hashes, StringComparison.Ordinal);
        Assert.Equal(AlertDispatcher.MaxSummaryHashes, hashes.Split(':')[1].Split(',').Length);
    }

    [Fact]
    public void AutoQuarantineLimiter_EachRequesterHasItsOwnWindow_TheEngineKeepsItsOwn()
    {
        var limiter = new AutoQuarantineLimiter(new ManualTime(), 2, TimeSpan.FromMinutes(10));
        var bob = AlertBudget.ForRequester(FakeClientIdentity.NewUserSid()).Key;

        var alice = Enumerable.Range(0, 3).Select(i => limiter.TryAcquire(Alice.Key, out _)).ToArray();

        Assert.Equal([true, true, false], alice);
        Assert.True(limiter.TryAcquire(bob, out _));
        Assert.True(limiter.TryAcquire(AlertBudget.ForEngine(ScanTrigger.RealTime).Key, out _));
    }

    [Fact]
    public async Task AUsersMaliciousScan_DoesNotUseUpTheEnginesAutoQuarantineSlots()
    {
        var quarantine = new RecordingQuarantine();
        using var h = new HandlerHarness(setup: j => j.Handler = new ScanVerdictHandler(new RecordingAlertSink(), quarantine, new AutoQuarantinePolicy([]),
            new AutoQuarantineLimiter(TimeProvider.System, 2, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance));
        for (int i = 0; i < 4; i++)
        {
            h.Jobs.Write($@"user\mal-{i}.bin", $"user content {i}");
        }

        string engineFile = h.Jobs.Write(@"engine\mal-engine.bin", "engine content");
        var user = h.Session(new FakeClientIdentity());

        var userJob = await h.RunAsync(user, Path.Combine(h.Jobs.Root, "user"));
        var engineJob = h.Jobs.Service.Create(new ScanJobRequest([engineFile], ScanTrigger.CustomScan));
        h.Jobs.Service.Start(engineJob.Id);
        await JobWait.Done(engineJob);

        Assert.Equal(2, userJob.Results.Count(r => r.Action == ScanFileAction.Quarantined));
        Assert.Equal(2, userJob.Results.Count(r => r.Action == ScanFileAction.NeedsUserConfirmation));
        Assert.Equal(ScanFileAction.Quarantined, Assert.Single(engineJob.Results).Action);
        Assert.Equal(user.Identity.User, quarantine.Requesters[0]!.User); // a standard user's auto-quarantines count against their quota
        Assert.Null(quarantine.Requesters[^1]);
    }

    [Fact]
    public async Task QuarantineFromResult_IsRateLimitedPerUser_AndCarriesTheRequester_AdminsAreNot()
    {
        using var h = new HandlerHarness(configure: o => o.QuarantineRequestBurst = 2);
        for (int i = 0; i < 3; i++)
        {
            h.Jobs.Write($"sus-{i}.bin", $"content {i}");
        }

        var user = h.Session(new FakeClientIdentity());
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));
        var job = await h.RunAsync(user);
        var adminJob = await h.RunAsync(admin);

        var replies = new List<PipeStatus>();
        for (int i = 0; i < 3; i++)
        {
            replies.Add((await h.SendAsync(user, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, i))).Status);
        }

        var byAdmin = await h.SendAsync(admin, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(adminJob.Id, 2));

        Assert.Equal([PipeStatus.Ok, PipeStatus.Ok, PipeStatus.RateLimited], replies);
        Assert.Equal(PipeStatus.Ok, byAdmin.Status);
        Assert.Equal([user.Identity.User, user.Identity.User, null], h.Quarantine.Requesters.Select(r => r?.User));
    }

    [Fact]
    public async Task PerUserQuota_ItemsAndBytes_EngineQuarantinesUseOnlyTheGlobalQuota()
    {
        using var ctx = new QuarantineTestContext(configure: o =>
        {
            o.MaxItemsPerRequester = 2;
            o.MaxBytesPerRequester = 25_000;
        });
        var alice = new QuarantineRequester(FakeClientIdentity.NewUserSid());
        var bob = new QuarantineRequester(FakeClientIdentity.NewUserSid());

        async Task<QuarantineStatus> Quarantine(string name, int size, QuarantineRequester? who)
        {
            var content = QuarantineTestContext.SampleContent(size, seed: name.GetHashCode(StringComparison.Ordinal));
            var path = ctx.WriteFile(name, content);
            return (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content), requester: who)).Status;
        }

        var first = await Quarantine("a1.bin", 1_000, alice);
        var second = await Quarantine("a2.bin", 1_000, alice);
        var third = await Quarantine("a3.bin", 1_000, alice);
        var bobsBig = await Quarantine("b1.bin", 30_000, bob);
        var bobsSmall = await Quarantine("b2.bin", 1_000, bob);
        var engine = await Quarantine("e1.bin", 30_000, null);

        Assert.Equal([QuarantineStatus.Quarantined, QuarantineStatus.Quarantined, QuarantineStatus.QuotaExceeded], new[] { first, second, third });
        Assert.Equal(QuarantineStatus.QuotaExceeded, bobsBig); // over the byte quota
        Assert.Equal(QuarantineStatus.Quarantined, bobsSmall);
        Assert.Equal(QuarantineStatus.Quarantined, engine);
        Assert.True(File.Exists(Path.Combine(ctx.Files, "a3.bin"))); // left in place
    }
}
