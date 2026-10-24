using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>Records the events a session would stream.</summary>
internal sealed class RecordingSink : IPipeEventSink
{
    public List<(PipeEventKind Kind, object Body)> Events { get; } = [];

    public bool TryPost(PipeEventKind kind, object body)
    {
        lock (Events)
        {
            Events.Add((kind, body));
        }

        return true;
    }
}

/// <summary>The request handler around a fake-broker job service, without a pipe.</summary>
internal sealed class HandlerHarness : IDisposable
{
    /// <summary>A SID put into an allow ACE to mark objects the simulated requester may not access.</summary>
    public static readonly SecurityIdentifier Marker = new("S-1-5-21-9-9-9-777");

    private readonly List<PipeSession> _sessions = [];

    public HandlerHarness(TimeProvider? time = null, Action<PipeServerOptions>? configure = null, Func<string, int>? driveType = null)
    {
        Jobs = new ScanJobHarness(time);
        configure?.Invoke(Options);
        Handler = new PipeRequestHandler(Jobs.Service, Quarantine, Options, Jobs.Time, NullLogger.Instance, driveType ?? (_ => 3));
    }

    public ScanJobHarness Jobs { get; }

    public RecordingQuarantine Quarantine { get; } = new();

    public PipeServerOptions Options { get; } = new();

    public PipeRequestHandler Handler { get; }

    public PipeSession Session(IClientIdentity identity, RecordingSink? sink = null)
    {
        var session = new PipeSession(identity, sink ?? new RecordingSink()) { HelloDone = true };
        _sessions.Add(session);
        return session;
    }

    /// <summary>A standard user whose access is the process's own, except objects carrying <see cref="Marker"/> (denied).</summary>
    public static FakeClientIdentity MarkedUser(SecurityIdentifier? user = null, uint deniedAccess = uint.MaxValue) =>
        new(user, isAdmin: false, realAccess: false)
        {
            Grant = (sd, access) =>
                (access & deniedAccess) == 0
                || !new RawSecurityDescriptor(sd, 0).DiscretionaryAcl!.Cast<GenericAce>().OfType<KnownAce>().Any(a => a.SecurityIdentifier == Marker),
        };

    public static void Mark(string path)
    {
        var rule = new FileSystemAccessRule(Marker, FileSystemRights.ReadAttributes, AccessControlType.Allow);
        if (Directory.Exists(path))
        {
            var dir = new DirectoryInfo(path);
            var acl = dir.GetAccessControl();
            acl.AddAccessRule(rule);
            dir.SetAccessControl(acl);
        }
        else
        {
            var file = new FileInfo(path);
            var acl = file.GetAccessControl();
            acl.AddAccessRule(rule);
            file.SetAccessControl(acl);
        }
    }

    public Task<PipeReply> SendAsync(PipeSession session, PipeRequestKind kind, object? body = null) =>
        Handler.HandleAsync(session, new PipeRequest(1, kind, body is null ? null : PipeJson.ToElement(body)), CancellationToken.None);

    public async Task<Guid> CreateAsync(PipeSession session, params string[] paths)
    {
        var reply = await SendAsync(session, PipeRequestKind.ScanCreate, new ScanCreateRequest(paths.Length == 0 ? [Jobs.Root] : paths));
        Assert.True(reply.Status == PipeStatus.Ok, reply.Error);
        return ((ScanCreateReply)reply.Body!).JobId;
    }

    public async Task<ScanJob> RunAsync(PipeSession session, params string[] paths)
    {
        var id = await CreateAsync(session, paths);
        Assert.Equal(PipeStatus.Ok, (await SendAsync(session, PipeRequestKind.ScanStart, new JobRequest(id))).Status);
        var job = Jobs.Service.Get(id)!;
        await JobWait.Done(job);
        return job;
    }

    public void Dispose()
    {
        foreach (var session in _sessions)
        {
            session.Dispose();
        }

        Jobs.Dispose();
    }
}

public sealed class PipeAuthorizationTests
{
    [Theory]
    [InlineData(@"\\server\share\x")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\x")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"C:\x\file.txt:stream")]
    [InlineData(@"C:\x\NUL")]
    public async Task PolicyRefusedPaths_AreInvalidPath_ForAdminsToo(string path)
    {
        using var h = new HandlerHarness();
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        var reply = await h.SendAsync(admin, PipeRequestKind.ScanCreate, new ScanCreateRequest([path]));

        Assert.Equal(PipeStatus.InvalidPath, reply.Status);
        Assert.Empty(h.Jobs.Service.List());
    }

    [Fact]
    public async Task NetworkDrive_IsInvalidPath()
    {
        using var h = new HandlerHarness(driveType: _ => PipeNative.DriveRemote);
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        var reply = await h.SendAsync(admin, PipeRequestKind.ScanCreate, new ScanCreateRequest([h.Jobs.Root]));

        Assert.Equal(PipeStatus.InvalidPath, reply.Status);
    }

    [Fact]
    public async Task AUserCantScanAFolderTheyCantRead_RealToken_AdminCan()
    {
        using var h = new HandlerHarness();
        string secret = Directory.CreateDirectory(Path.Combine(h.Jobs.Root, "secret")).FullName;
        using var me = WindowsIdentity.GetCurrent();
        var user = h.Session(new FakeClientIdentity(me.User, isAdmin: false)); // real AccessCheck with this process's token
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));
        using var deny = new DenyAce(secret, FileSystemRights.ListDirectory | FileSystemRights.ReadData);

        var refused = await h.SendAsync(user, PipeRequestKind.ScanCreate, new ScanCreateRequest([secret]));
        var missing = await h.SendAsync(user, PipeRequestKind.ScanCreate, new ScanCreateRequest([Path.Combine(h.Jobs.Root, "nope")]));
        var allowed = await h.SendAsync(admin, PipeRequestKind.ScanCreate, new ScanCreateRequest([secret]));

        Assert.Equal(PipeStatus.AccessDenied, refused.Status);
        Assert.Equal(PipeStatus.NotFound, missing.Status);
        Assert.Equal(PipeStatus.Ok, allowed.Status);
    }

    [Fact]
    public async Task AUsersJob_NeverListsOrScansWhatTheUserCantRead()
    {
        using var h = new HandlerHarness();
        string open = h.Jobs.Write("mal-visible.bin");
        string hiddenFile = h.Jobs.Write("mal-hidden.bin");
        h.Jobs.Write(Path.Combine("private", "mal-inside.bin"));
        HandlerHarness.Mark(hiddenFile);
        HandlerHarness.Mark(Path.Combine(h.Jobs.Root, "private"));
        var user = h.Session(HandlerHarness.MarkedUser());

        var job = await h.RunAsync(user);

        var results = job.Results;
        Assert.Contains(results, r => r.Path == open && r.Verdict == Verdict.Malicious);
        var hidden = Assert.Single(results, r => r.Path.EndsWith("mal-hidden.bin", StringComparison.Ordinal));
        Assert.Equal(ScanStatus.AccessDenied, hidden.Status);
        Assert.Null(hidden.Sha256);
        Assert.Null(hidden.Verdict);
        Assert.DoesNotContain(results, r => r.Path.Contains("mal-inside", StringComparison.Ordinal));
        Assert.Equal(1, job.Skipped.UnreadableFolders);
    }

    [Fact]
    public async Task JobsAreIsolatedBetweenUsers_AdminsSeeAll()
    {
        using var h = new HandlerHarness();
        var alice = h.Session(new FakeClientIdentity());
        var bob = h.Session(new FakeClientIdentity());
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));
        var id = await h.CreateAsync(alice);
        var job = new JobRequest(id);

        foreach (var kind in new[] { PipeRequestKind.ScanStart, PipeRequestKind.ScanPause, PipeRequestKind.ScanResume, PipeRequestKind.ScanCancel,
                     PipeRequestKind.Subscribe })
        {
            Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(bob, kind, job)).Status);
        }

        Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(bob, PipeRequestKind.ScanGet, new ScanGetRequest(id))).Status);
        Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(bob, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(id, 0))).Status);
        Assert.Empty(((ScanListReply)(await h.SendAsync(bob, PipeRequestKind.ScanList)).Body!).Jobs);
        Assert.Equal(ScanJobState.Created, h.Jobs.Service.Get(id)!.State);

        var seen = Assert.Single(((ScanListReply)(await h.SendAsync(admin, PipeRequestKind.ScanList)).Body!).Jobs);
        Assert.False(seen.OwnedByCaller);
        Assert.True(Assert.Single(((ScanListReply)(await h.SendAsync(alice, PipeRequestKind.ScanList)).Body!).Jobs).OwnedByCaller);
        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(admin, PipeRequestKind.ScanCancel, job)).Status);
    }

    [Fact]
    public async Task EngineCreatedJobs_AreVisibleToAdminsOnly()
    {
        using var h = new HandlerHarness();
        var engineJob = h.Jobs.Service.Create(new ScanJobRequest([h.Jobs.Root], ScanTrigger.QuickScan));
        var user = h.Session(new FakeClientIdentity());
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(user, PipeRequestKind.ScanGet, new ScanGetRequest(engineJob.Id))).Status);
        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(admin, PipeRequestKind.ScanGet, new ScanGetRequest(engineJob.Id))).Status);
    }

    [Fact]
    public async Task PendingJobs_AreCappedPerUserAndInTotal()
    {
        using var h = new HandlerHarness(configure: o =>
        {
            o.MaxPendingJobsPerUser = 2;
            o.MaxPendingJobsTotal = 3;
        });
        var alice = h.Session(new FakeClientIdentity());
        var bob = h.Session(new FakeClientIdentity());
        var carol = h.Session(new FakeClientIdentity());

        await h.CreateAsync(alice);
        await h.CreateAsync(alice);
        var third = await h.SendAsync(alice, PipeRequestKind.ScanCreate, new ScanCreateRequest([h.Jobs.Root]));
        await h.CreateAsync(bob);
        var overTotal = await h.SendAsync(carol, PipeRequestKind.ScanCreate, new ScanCreateRequest([h.Jobs.Root]));

        Assert.Equal(PipeStatus.LimitReached, third.Status);
        Assert.Equal(PipeStatus.LimitReached, overTotal.Status);
    }

    [Fact]
    public async Task ActiveJobs_AreCappedPerUser_AndExpiredPendingJobsAreCancelled()
    {
        var time = new ManualTime();
        using var h = new HandlerHarness(time, o =>
        {
            o.MaxPendingJobsPerUser = 1;
            o.PendingJobExpiry = TimeSpan.FromMinutes(10);
        });
        var alice = h.Session(new FakeClientIdentity());
        var old = await h.CreateAsync(alice);
        Assert.Equal(PipeStatus.LimitReached, (await h.SendAsync(alice, PipeRequestKind.ScanCreate, new ScanCreateRequest([h.Jobs.Root]))).Status);

        time.Now += TimeSpan.FromMinutes(11);
        var fresh = await h.SendAsync(alice, PipeRequestKind.ScanCreate, new ScanCreateRequest([h.Jobs.Root]));

        Assert.Equal(PipeStatus.Ok, fresh.Status);
        Assert.Equal(ScanJobState.Cancelled, h.Jobs.Service.Get(old)!.State);
    }

    [Fact]
    public async Task QuarantineFromResult_UsesTheEnginesOwnReport_AndNeedsDeleteForStandardUsers()
    {
        using var h = new HandlerHarness();
        string file = h.Jobs.Write("mal-target.bin");
        HandlerHarness.Mark(file);
        HandlerHarness.Mark(h.Jobs.Root); // no FILE_DELETE_CHILD on the folder either
        var mayNotDelete = HandlerHarness.MarkedUser(deniedAccess: PipeNative.Delete | PipeNative.FileDeleteChild);
        var user = h.Session(mayNotDelete);
        var job = await h.RunAsync(user);
        var result = Assert.Single(job.Results);
        Assert.True(result.CanQuarantine);

        var denied = await h.SendAsync(user, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, 0));
        Assert.Equal(PipeStatus.AccessDenied, denied.Status);
        Assert.Empty(h.Quarantine.Quarantined);

        var mayDelete = h.Session(HandlerHarness.MarkedUser(mayNotDelete.User, deniedAccess: 0));
        var done = await h.SendAsync(mayDelete, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, 0));
        var missing = await h.SendAsync(mayDelete, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, 7));

        Assert.Equal(PipeStatus.Ok, done.Status);
        Assert.Equal(QuarantineOutcome.Quarantined, ((QuarantineFromResultReply)done.Body!).Status);
        Assert.Same(result.Report, Assert.Single(h.Quarantine.Quarantined));
        Assert.Equal(PipeStatus.NotFound, missing.Status);
    }

    [Fact]
    public async Task QuarantineFromResult_RealToken_DenyAceOnDeleteAndDeleteChild_IsAccessDenied()
    {
        using var h = new HandlerHarness();
        string folder = Directory.CreateDirectory(Path.Combine(h.Jobs.Root, "d")).FullName;
        string file = h.Jobs.Write(Path.Combine("d", "mal-x.bin"));
        using var me = WindowsIdentity.GetCurrent();
        var user = h.Session(new FakeClientIdentity(me.User));
        var job = await h.RunAsync(user, folder);

        using (new DenyAce(file, FileSystemRights.Delete))
        using (new DenyAce(folder, FileSystemRights.DeleteSubdirectoriesAndFiles))
        {
            var denied = await h.SendAsync(user, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, 0));
            Assert.Equal(PipeStatus.AccessDenied, denied.Status);
        }

        var allowed = await h.SendAsync(user, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, 0));
        Assert.Equal(PipeStatus.Ok, allowed.Status);
    }

    [Fact]
    public async Task NotScannedResults_CantBeQuarantined()
    {
        using var h = new HandlerHarness();
        h.Jobs.Write("mal-error.bin");
        h.Jobs.Broker.OnScan = (_, _, _) => throw new InvalidOperationException("worker broke");
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));
        var job = await h.RunAsync(admin);

        var reply = await h.SendAsync(admin, PipeRequestKind.QuarantineFromResult, new QuarantineFromResultRequest(job.Id, 0));

        Assert.Equal(PipeStatus.InvalidState, reply.Status);
        Assert.Empty(h.Quarantine.Quarantined);
    }

    [Fact]
    public async Task Restore_NeedsAdminOrAddFileOnTheOriginalFolder_RealToken()
    {
        using var h = new HandlerHarness();
        h.Quarantine.Entries.Add(RecordingQuarantine.Entry(Path.Combine(h.Jobs.Root, "restored.bin")));
        using var me = WindowsIdentity.GetCurrent();
        var user = h.Session(new FakeClientIdentity(me.User));
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        using (new DenyAce(h.Jobs.Root, FileSystemRights.CreateFiles))
        {
            Assert.Equal(PipeStatus.AccessDenied, (await h.SendAsync(user, PipeRequestKind.QuarantineRestore, new QuarantineItemRequest("item1"))).Status);
            Assert.Empty(h.Quarantine.Restored);
            Assert.Equal(PipeStatus.Ok, (await h.SendAsync(admin, PipeRequestKind.QuarantineRestore, new QuarantineItemRequest("item1"))).Status);
        }

        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(user, PipeRequestKind.QuarantineRestore, new QuarantineItemRequest("item1"))).Status);
        Assert.Equal(["item1", "item1"], h.Quarantine.Restored);
    }

    [Fact]
    public async Task QuarantineItems_AreVisibleOnlyToUsersWhoCanListTheOriginalFolder()
    {
        using var h = new HandlerHarness();
        string hidden = Directory.CreateDirectory(Path.Combine(h.Jobs.Root, "other-user")).FullName;
        HandlerHarness.Mark(hidden);
        h.Quarantine.Entries.Add(RecordingQuarantine.Entry(Path.Combine(h.Jobs.Root, "mine.bin"), "mine"));
        h.Quarantine.Entries.Add(RecordingQuarantine.Entry(Path.Combine(hidden, "theirs.bin"), "theirs"));
        h.Quarantine.Entries.Add(QuarantineEntry.Invalid("broken"));
        var user = h.Session(HandlerHarness.MarkedUser());
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        var userList = (QuarantineListReply)(await h.SendAsync(user, PipeRequestKind.QuarantineList)).Body!;
        var adminList = (QuarantineListReply)(await h.SendAsync(admin, PipeRequestKind.QuarantineList)).Body!;

        Assert.Equal(["mine"], userList.Items.Select(i => i.Id));
        Assert.Equal(3, adminList.Items.Count);
        Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(user, PipeRequestKind.QuarantineGet, new QuarantineItemRequest("theirs"))).Status);
        Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(user, PipeRequestKind.QuarantineRestore, new QuarantineItemRequest("theirs"))).Status);
    }

    [Fact]
    public async Task Events_StreamOnlyToTheOwnersSubscription_AndEndWithTheJob()
    {
        using var h = new HandlerHarness();
        h.Jobs.Write("mal-1.bin");
        h.Jobs.Write("sus-2.bin");
        var aliceSink = new RecordingSink();
        var bobSink = new RecordingSink();
        var alice = h.Session(new FakeClientIdentity(), aliceSink);
        var bob = h.Session(new FakeClientIdentity(), bobSink);
        var id = await h.CreateAsync(alice);

        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(alice, PipeRequestKind.Subscribe, new JobRequest(id))).Status);
        Assert.Equal(PipeStatus.NotFound, (await h.SendAsync(bob, PipeRequestKind.Subscribe, new JobRequest(id))).Status);
        await h.SendAsync(alice, PipeRequestKind.ScanStart, new JobRequest(id));
        await JobWait.Done(h.Jobs.Service.Get(id)!);

        Assert.Empty(bobSink.Events);
        var files = aliceSink.Events.Where(e => e.Kind == PipeEventKind.JobFileResult).Select(e => (JobFileResultEvent)e.Body).ToArray();
        Assert.Equal([0, 1], files.Select(f => f.Result.ResultId).Order());
        Assert.Contains(aliceSink.Events, e => e.Body is JobStateEvent { To: JobState.Completed });
        Assert.False(alice.HasSubscriptions);
    }

    [Fact]
    public async Task Subscriptions_AreCappedPerConnection()
    {
        using var h = new HandlerHarness(configure: o =>
        {
            o.MaxSubscriptionsPerConnection = 1;
            o.MaxPendingJobsPerUser = 4;
        });
        var alice = h.Session(new FakeClientIdentity());
        var first = await h.CreateAsync(alice);
        var second = await h.CreateAsync(alice);

        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(alice, PipeRequestKind.Subscribe, new JobRequest(first))).Status);
        Assert.Equal(PipeStatus.LimitReached, (await h.SendAsync(alice, PipeRequestKind.Subscribe, new JobRequest(second))).Status);
    }
}
