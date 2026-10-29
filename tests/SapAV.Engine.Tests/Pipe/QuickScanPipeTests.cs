using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>
/// C4 over the pipe: Quick Scan is administrator-only (QuickScanCreate), and ScanGetFindings returns phases and findings
/// with the B4 output rules (visibility, SafeText / WirePath, templates and no command line for non-admins, caps, paging).
/// </summary>
public sealed class QuickScanPipeTests : IDisposable
{
    private readonly QuickScanHarness _q = new();
    private readonly List<PipeSession> _sessions = [];
    private PipeRequestHandler? _handler;

    public void Dispose()
    {
        _handler?.Dispose();
        foreach (var session in _sessions)
        {
            session.Dispose();
        }

        _q.Dispose();
    }

    private PipeRequestHandler Handler => _handler ??= new PipeRequestHandler(_q.Jobs.Service, null, new PipeServerOptions(), _q.Jobs.Time,
        NullLogger.Instance, _ => 3, _q.Factory());

    private PipeSession Session(bool admin)
    {
        var session = new PipeSession(new FakeClientIdentity(isAdmin: admin), new RecordingSink()) { HelloDone = true };
        _sessions.Add(session);
        return session;
    }

    private Task<PipeReply> SendAsync(PipeSession session, PipeRequestKind kind, object? body = null) =>
        Handler.HandleAsync(session, new PipeRequest(1, kind, body is null ? null : PipeJson.ToElement(body)), CancellationToken.None);

    private async Task<ScanJob> RunQuickScanAsync(PipeSession admin)
    {
        var created = await SendAsync(admin, PipeRequestKind.QuickScanCreate);
        Assert.True(created.Status == PipeStatus.Ok, created.Error);
        var id = ((ScanCreateReply)created.Body!).JobId;
        Assert.Equal(PipeStatus.Ok, (await SendAsync(admin, PipeRequestKind.ScanStart, new JobRequest(id))).Status);
        var job = _q.Jobs.Service.Get(id)!;
        await JobWait.Done(job);
        return job;
    }

    /// <summary>A Malicious autostart target whose value name and command line carry a right-to-left override.</summary>
    private string AddMaliciousRunEntry()
    {
        var target = _q.Write(@"Users\alice\AppData\Roaming\evil\mal-run.exe");
        _q.Entries.Add(new PersistenceEntry(PersistenceKind.RunKey, null, @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Upd‮exe.txt",
            $"\"{target}\" --token=secret‮", ResolvedCommand.Resolved(target, "--token=secret", null), enabled: true));
        return target;
    }

    [Fact]
    public async Task StandardUser_CantCreateAQuickScan_AdminCan_AsAnAdministratorJob()
    {
        var user = Session(admin: false);
        var admin = Session(admin: true);

        var refused = await SendAsync(user, PipeRequestKind.QuickScanCreate);
        Assert.Equal(PipeStatus.AccessDenied, refused.Status);
        Assert.Empty(_q.Jobs.Service.List());

        var job = await RunQuickScanAsync(admin);

        Assert.Equal(ScanTrigger.QuickScan, job.Request.Trigger);
        Assert.Equal(ScanJobOrigin.Administrator, job.Request.Origin);
        Assert.Equal(admin.Identity.User, job.Request.Requester);
        Assert.Null(job.Request.Access);
        Assert.Equal(ScanJobState.Completed, job.State);
    }

    [Fact]
    public async Task QuickScanCreate_TakesNoBody_AndIsUnavailableWithoutAFactory()
    {
        var admin = Session(admin: true);
        Assert.Equal(PipeStatus.BadRequest, (await SendAsync(admin, PipeRequestKind.QuickScanCreate, new JobRequest(Guid.NewGuid()))).Status);

        using var bare = new PipeRequestHandler(_q.Jobs.Service, null, new PipeServerOptions(), _q.Jobs.Time, NullLogger.Instance, _ => 3);
        var reply = await bare.HandleAsync(admin, new PipeRequest(2, PipeRequestKind.QuickScanCreate), CancellationToken.None);
        Assert.Equal(PipeStatus.Unavailable, reply.Status);
    }

    [Fact]
    public async Task Findings_ForTheAdmin_CarryPhasesTechniquesAndSanitisedText_AndOtherUsersSeeNothing()
    {
        var target = AddMaliciousRunEntry();
        var admin = Session(admin: true);
        var other = Session(admin: false);
        var job = await RunQuickScanAsync(admin);

        var reply = await SendAsync(admin, PipeRequestKind.ScanGetFindings, new ScanFindingsRequest(job.Id));
        var hidden = await SendAsync(other, PipeRequestKind.ScanGetFindings, new ScanFindingsRequest(job.Id));

        Assert.Equal(PipeStatus.NotFound, hidden.Status); // an administrator's job, invisible to a standard user
        var body = Assert.IsType<JobFindingsReply>(reply.Body);
        Assert.True(body.Complete);
        Assert.Equal(4, body.Phases.Count);
        Assert.All(body.Phases, p => Assert.Equal(PhaseState.Completed, p.State));
        var finding = Assert.Single(body.Findings);
        Assert.Equal(FindingCategory.Persistence, finding.Category);
        Assert.Equal(Verdict.Malicious, finding.Verdict);
        Assert.NotNull(finding.AlertId);
        Assert.NotEmpty(finding.TechniqueIds);
        Assert.All(finding.Reasons, r => Assert.DoesNotContain('‮', r)); // SafeText.Display
        var entry = finding.Persistence!;
        Assert.True(entry.ValueName!.HasHiddenCharacters); // exact, flagged for the UI to isolate
        Assert.NotNull(entry.CommandLine);
        Assert.Equal(target, entry.TargetPath!.Value, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(Verdict.Malicious, entry.TargetVerdict);
        Assert.All(entry.RuleIds, r => Assert.True(PipeMapping.IsRuleId(r)));
    }

    [Fact]
    public async Task Findings_ForANonAdmin_AreTemplates_WithoutCommandLineOrUserSid()
    {
        AddMaliciousRunEntry();
        var job = await RunQuickScanAsync(Session(admin: true));
        var finding = Assert.Single(job.Findings);

        var forUser = PipeMapping.Finding(0, finding, forAdmin: false);

        Assert.Null(forUser.Persistence!.CommandLine);
        Assert.Null(forUser.Persistence.UserSid);
        Assert.NotEmpty(forUser.Reasons);
        Assert.All(forUser.Reasons, r =>
        {
            Assert.DoesNotContain("secret", r, StringComparison.Ordinal);
            Assert.DoesNotContain("mal-run", r, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith("Malicious:", r, StringComparison.Ordinal);
        });
        Assert.False(PipeMapping.IsRuleId("Rule With Spaces"));
        Assert.False(PipeMapping.IsRuleId(new string('a', 65)));
    }

    [Fact]
    public async Task Findings_ArePaged_AndTheReplyRoundTripsThroughTheStrictJson()
    {
        for (int i = 0; i < 3; i++)
        {
            var target = _q.Write($@"Users\alice\AppData\Roaming\evil\mal-{i}.exe");
            _q.Entries.Add(QuickScanHarness.Run(target, $"Entry{i}"));
        }

        var admin = Session(admin: true);
        var job = await RunQuickScanAsync(admin);

        var first = (JobFindingsReply)(await SendAsync(admin, PipeRequestKind.ScanGetFindings, new ScanFindingsRequest(job.Id, 0, 2))).Body!;
        var rest = (JobFindingsReply)(await SendAsync(admin, PipeRequestKind.ScanGetFindings, new ScanFindingsRequest(job.Id, 2, 2))).Body!;

        Assert.Equal([0, 1], first.Findings.Select(f => f.FindingId));
        Assert.Equal(2, first.NextOffset);
        Assert.Equal([2], rest.Findings.Select(f => f.FindingId));
        Assert.Null(rest.NextOffset);
        var json = JsonSerializer.Serialize(first, PipeJson.Options);
        var back = JsonSerializer.Deserialize<JobFindingsReply>(json, PipeJson.Options)!;
        Assert.Equal(first.Findings.Count, back.Findings.Count);
        Assert.Equal(first.Phases.Select(p => p.State), back.Phases.Select(p => p.State));
        Assert.Equal(PipeStatus.BadRequest, (await SendAsync(admin, PipeRequestKind.ScanGetFindings,
            JsonDocument.Parse($"{{\"JobId\":\"{job.Id}\",\"Offset\":0,\"Limit\":500}}").RootElement)).Status);

        // Review C4 L5: a zero page is refused (it would look like the end of the list).
        Assert.Equal(PipeStatus.BadRequest, (await SendAsync(admin, PipeRequestKind.ScanGetFindings,
            JsonDocument.Parse($"{{\"JobId\":\"{job.Id}\",\"Offset\":0,\"Limit\":0}}").RootElement)).Status);
    }

    [Fact]
    public async Task Progress_CarriesTheRunningPhase()
    {
        var admin = Session(admin: true);
        var job = await RunQuickScanAsync(admin);

        var details = (JobDetails)(await SendAsync(admin, PipeRequestKind.ScanGet, new ScanGetRequest(job.Id))).Body!;

        Assert.Equal(ScanTrigger.QuickScan, details.Summary.Trigger);
        Assert.Empty(details.Summary.Paths);
        Assert.Equal(new ScanPhaseProgressInfo("Recently changed files", 3, 4), details.Progress.Phase);
    }
}
