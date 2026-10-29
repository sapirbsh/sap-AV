using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>C6 over the pipe: FullScanCreate is administrator-only like Quick Scan; results come through ScanGet / ScanGetFindings.</summary>
public sealed class FullScanPipeTests : IDisposable
{
    private readonly FullScanHarness _f = new();
    private readonly List<PipeSession> _sessions = [];
    private PipeRequestHandler? _handler;

    public void Dispose()
    {
        _handler?.Dispose();
        foreach (var session in _sessions)
        {
            session.Dispose();
        }

        _f.Dispose();
    }

    private PipeRequestHandler Handler => _handler ??= new PipeRequestHandler(_f.Jobs.Service, null, new PipeServerOptions(), _f.Jobs.Time,
        NullLogger.Instance, _ => 3, fullScan: _f.Factory());

    private PipeSession Session(bool admin)
    {
        var session = new PipeSession(new FakeClientIdentity(isAdmin: admin), new RecordingSink()) { HelloDone = true };
        _sessions.Add(session);
        return session;
    }

    private Task<PipeReply> SendAsync(PipeSession session, PipeRequestKind kind, object? body = null) =>
        Handler.HandleAsync(session, new PipeRequest(1, kind, body is null ? null : PipeJson.ToElement(body)), CancellationToken.None);

    [Fact]
    public async Task StandardUser_CantCreateAFullScan_AdminCan_AndGetsResultsThroughScanGet()
    {
        _f.Write(@"Users\bob\Downloads\mal-thing.exe");
        _f.Write("clean.txt");
        var user = Session(admin: false);
        var admin = Session(admin: true);

        var refused = await SendAsync(user, PipeRequestKind.FullScanCreate);
        Assert.Equal(PipeStatus.AccessDenied, refused.Status);
        Assert.Empty(_f.Jobs.Service.List());
        Assert.Equal(PipeStatus.BadRequest, (await SendAsync(admin, PipeRequestKind.FullScanCreate, new { Paths = new[] { @"C:\" } })).Status); // no body

        var created = await SendAsync(admin, PipeRequestKind.FullScanCreate);
        Assert.True(created.Status == PipeStatus.Ok, created.Error);
        var id = ((ScanCreateReply)created.Body!).JobId;
        Assert.Equal(PipeStatus.Ok, (await SendAsync(admin, PipeRequestKind.ScanStart, new JobRequest(id))).Status);
        var job = _f.Jobs.Service.Get(id)!;
        await JobWait.Done(job);

        Assert.Equal(ScanTrigger.FullScan, job.Request.Trigger);
        Assert.Equal(ScanJobOrigin.Administrator, job.Request.Origin);
        Assert.Equal(FullScanOptions.NoBudget, job.Request.TimeBudget);
        var details = (JobDetails)(await SendAsync(admin, PipeRequestKind.ScanGet, new ScanGetRequest(id))).Body!;
        Assert.Equal(Verdict.Malicious, Assert.Single(details.Results).Verdict);
        Assert.Equal(100, details.Progress.PercentDone);
        var findings = (JobFindingsReply)(await SendAsync(admin, PipeRequestKind.ScanGetFindings, new ScanFindingsRequest(id))).Body!;
        Assert.Equal(["Running programs", "Autostart entries", "Fixed drives"], findings.Phases.Select(p => p.Name));
        Assert.Equal(PipeStatus.NotFound, (await SendAsync(user, PipeRequestKind.ScanGet, new ScanGetRequest(id))).Status); // admins only
        var json = JsonSerializer.Serialize(details, PipeJson.Options);
        Assert.NotNull(JsonSerializer.Deserialize<JobDetails>(json, PipeJson.Options));
    }
}
