using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.VirusTotal;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.Pipe;
using SapAV.Engine.Tests.TestSupport;
using SapAV.Engine.VirusTotal;

namespace SapAV.Engine.Tests.VirusTotal;

/// <summary>
/// D3: when the engine asks VirusTotal, how an answer becomes a detection, and the pipe settings. A fake HTTP handler stands in
/// for VirusTotal (no test ever talks to the real API) and a temp root for <c>%ProgramData%\sap-AV</c>. Keys are obviously fake.
/// </summary>
public sealed class VirusTotalWiringTests : IDisposable
{
    private const string FakeKey = "FAKE-test-key-not-real-0123456789abcdef";
    private static readonly string Sha = new('a', 64);

    private readonly TempDir _temp = new();
    private readonly FakeClock _clock = new();
    private readonly FakeHandler _handler = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        _temp.Dispose();
    }

    private string Folder => Path.Combine(_temp.Path, "sap-AV", "VirusTotal");

    private VirusTotalService Service(bool protectedMode = true, bool allowEnvironmentKey = false)
    {
        var service = new VirusTotalService(new VirusTotalOptions { Folder = Folder }, NullLogger.Instance, _clock, protectedMode, allowEnvironmentKey,
            new QuarantineAccessPolicy([QuarantineTestContext.CurrentUser]), () => new HttpClient(_handler, disposeHandler: false), parentIsDataRoot: true);
        _owned.Add(service);
        return service;
    }

    private VirusTotalService Active()
    {
        var service = Service();
        Assert.Equal(VirusTotalChange.Done, service.SetKey(FakeKey));
        Assert.Equal(VirusTotalChange.Done, service.SetEnabled(true));
        return service;
    }

    private static VirusTotalOnlineLookup Lookup(IVirusTotalService service) => new(service, new VirusTotalOptions(), noteWhenUnavailable: true);

    private static OnlineLookupRequest Request(string path = @"C:\Users\u\Downloads\setup.exe", ScanTrigger trigger = ScanTrigger.RealTime,
        SignatureStatus? signature = SignatureStatus.UnsignedOrInvalid, Verdict local = Verdict.Clean) =>
        new(new ScanItem(path, trigger), Sha, signature, local);

    // ---- Policy ----

    [Theory]
    [InlineData(SignatureStatus.Microsoft, ScanTrigger.RealTime, Verdict.Clean)]
    [InlineData(SignatureStatus.OtherTrusted, ScanTrigger.RealTime, Verdict.Suspicious)]
    [InlineData(SignatureStatus.OtherTrusted, ScanTrigger.FullScan, Verdict.Suspicious)]
    public async Task TrustedSignedFiles_AreNeverQueried_EvenWithTheFeatureOnAndAKey(SignatureStatus signature, ScanTrigger trigger, Verdict local)
    {
        var outcome = await Lookup(Active()).LookupAsync(Request(trigger: trigger, signature: signature, local: local));

        Assert.Equal(OnlineLookupDecision.TrustedSignature, OnlineLookupPolicy.Decide(Request(trigger: trigger, signature: signature, local: local)));
        Assert.Same(OnlineLookupOutcome.None, outcome);
        Assert.Equal(0, _handler.Calls);
    }

    [Theory]
    [InlineData(@"C:\Users\u\Downloads\setup.exe", true)]
    [InlineData(@"C:\Users\u\Downloads\invoice.pdf.EXE. ", true)] // trailing dots / spaces ignored, any case
    [InlineData(@"\\?\C:\Users\u\Desktop\macro.docm", true)]
    [InlineData(@"C:\Users\u\Downloads\photo.jpg", false)]
    [InlineData(@"C:\Users\u\Downloads\readme", false)]
    public void RealTime_QueriesOnlyRiskyExtensions(string path, bool query)
    {
        Assert.Equal(query ? OnlineLookupDecision.Query : OnlineLookupDecision.NotRiskyExtension, OnlineLookupPolicy.Decide(Request(path)));
    }

    [Theory]
    [InlineData(ScanTrigger.FullScan, Verdict.Clean, OnlineLookupDecision.NotSuspicious)]
    [InlineData(ScanTrigger.CustomScan, Verdict.Suspicious, OnlineLookupDecision.Query)]
    [InlineData(ScanTrigger.Persistence, Verdict.Suspicious, OnlineLookupDecision.Query)]
    [InlineData(ScanTrigger.QuickScan, Verdict.Malicious, OnlineLookupDecision.AlreadyMalicious)]
    [InlineData(ScanTrigger.RealTime, Verdict.Malicious, OnlineLookupDecision.AlreadyMalicious)]
    public void Scans_QueryOnlySuspiciousFiles_WhateverTheExtension(ScanTrigger trigger, Verdict local, OnlineLookupDecision expected)
    {
        Assert.Equal(expected, OnlineLookupPolicy.Decide(Request(@"C:\data\file.bin", trigger, local: local)));
    }

    [Fact]
    public async Task FeatureOff_OrOnWithoutAKey_SendsNothing_OffIsSilent_NoKeyIsANote()
    {
        var service = Service();
        Assert.Equal(VirusTotalChange.Done, service.SetKey(FakeKey)); // a key, but off (the default)

        Assert.Same(OnlineLookupOutcome.None, await Lookup(service).LookupAsync(Request()));

        service.SetEnabled(true);
        service.ClearKey();
        var noKey = await Lookup(service).LookupAsync(Request());
        Assert.Null(noKey.Detection);
        Assert.Contains("no API key", noKey.Note!.Message, StringComparison.Ordinal);
        Assert.Equal(0, _handler.Calls);
    }

    [Fact]
    public async Task ANonElevatedDebugRun_NeverTouchesTheDataFolder_AndAddsNoNote()
    {
        var service = Service(protectedMode: false);

        Assert.Equal(VirusTotalActivity.Unavailable, service.Activity);
        Assert.Same(OnlineLookupOutcome.None, await new VirusTotalOnlineLookup(service, new VirusTotalOptions(), noteWhenUnavailable: false).LookupAsync(Request()));
        Assert.Equal(VirusTotalChange.Unavailable, service.SetKey(FakeKey));
        Assert.False(service.GetStatus().Available);
        Assert.False(Directory.Exists(Path.GetDirectoryName(Folder)));
    }

    // ---- Lookup and mapping ----

    [Fact]
    public async Task Active_SendsOnlyTheHash_AndManyEnginesMakeTheFileMalicious_WithT1204()
    {
        _handler.Respond = r => Report(r, malicious: 12, suspicious: 1);

        var outcome = await Lookup(Active()).LookupAsync(Request());

        var sent = Assert.Single(_handler.Sent);
        Assert.Equal(HttpMethod.Get, sent.Method);
        Assert.Equal("https://www.virustotal.com/api/v3/files/" + Sha, sent.Uri);
        Assert.False(sent.HasContent); // never the file
        Assert.DoesNotContain("setup", sent.Uri, StringComparison.OrdinalIgnoreCase); // never the name or path
        var detection = outcome.Detection!;
        Assert.Equal((Verdict.Malicious, DetectionSource.VirusTotal, MitreTechniqueIds.MaliciousFile), (detection.Verdict, detection.Source, detection.TechniqueId));
        Assert.Contains("12 of", detection.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(5, 0, "trojan.fake/test", Verdict.Malicious)]
    [InlineData(4, 9, "trojan.fake/test", Verdict.Suspicious)]
    [InlineData(3, 0, null, Verdict.Suspicious)]
    [InlineData(2, 20, "trojan.fake/test", null)] // review D3 L2: "suspicious" engines don't count
    [InlineData(40, 0, "hacktool.fake/keygen", Verdict.Suspicious)] // review D3 L2: PUP / HackTool is never Malicious (never auto-quarantined)
    [InlineData(30, 0, "Not-A-Virus:RiskWare.Fake", Verdict.Suspicious)]
    [InlineData(25, 0, "adware.fake/bundle", Verdict.Suspicious)]
    [InlineData(0, 0, null, null)]
    public void FoundReports_MapByMaliciousEngineCount_AndPupLabelsAreSuspiciousAtMost(int malicious, int suspicious, string? label, Verdict? expected)
    {
        var report = new VirusTotalReport(malicious, suspicious, 60, 0, 70, null, [], label);
        var result = new VirusTotalLookupResult(VirusTotalOrigin.Live, VirusTotalStatus.Found, report, DateTimeOffset.UnixEpoch, null, "VirusTotal: x (live).");

        var outcome = VirusTotalVerdict.Map(result, new VirusTotalOptions());

        Assert.Equal(expected, outcome.Detection?.Verdict);
        Assert.NotNull(outcome.Note);
    }

    [Fact]
    public void TheOptions_RefuseAMaliciousThresholdBelowTheSuspiciousOne()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new VirusTotalOnlineLookup(Service(), new VirusTotalOptions { MaliciousThreshold = 2, SuspiciousThreshold = 3 }, true));
    }

    [Fact]
    public async Task NonAnswers_AreNotes_NeverCleanOrAFailure_AndARefusedKeyIsReportedUntilANewKeyIsSet()
    {
        var service = Active();
        var lookup = Lookup(service);

        _handler.Respond = _ => new HttpResponseMessage(HttpStatusCode.NotFound);
        var unknown = await lookup.LookupAsync(Request());
        Assert.Null(unknown.Detection);
        Assert.Contains("does not know", unknown.Note!.Message, StringComparison.Ordinal);

        _handler.Respond = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var error = await lookup.LookupAsync(Request(@"C:\Users\u\Downloads\b.exe") with { Sha256 = new string('b', 64) });
        Assert.Equal((null, ScanNoteLevel.Warning), (error.Detection, error.Note!.Level));

        _handler.Respond = _ => new HttpResponseMessage(HttpStatusCode.Unauthorized);
        var refused = await lookup.LookupAsync(Request() with { Sha256 = new string('c', 64) });
        Assert.Null(refused.Detection);
        Assert.True(service.GetStatus().KeyRejected);
        int calls = _handler.Calls;
        await lookup.LookupAsync(Request() with { Sha256 = new string('d', 64) });
        Assert.Equal(calls, _handler.Calls); // nothing more is sent with a refused key

        Assert.Equal(VirusTotalChange.Done, service.SetKey(FakeKey)); // the administrator re-enters (or fixes) the key
        Assert.False(service.GetStatus().KeyRejected);
    }

    [Fact]
    public async Task TheMinuteBudget_IsRespected_TheFifthLookupIsAnUncheckedNote_AndTheCounterShowsUsage()
    {
        var service = Active();
        _handler.Respond = r => Report(r, malicious: 0, suspicious: 0);
        for (int i = 0; i < 4; i++)
        {
            await Lookup(service).LookupAsync(Request() with { Sha256 = i.ToString("x64") });
        }

        var fifth = await Lookup(service).LookupAsync(Request() with { Sha256 = 9.ToString("x64") });

        Assert.Equal(4, _handler.Calls);
        Assert.Contains("per-minute", fifth.Note!.Message, StringComparison.Ordinal);
        Assert.Equal((4, 500), (service.GetStatus().UsedToday, service.GetStatus().PerDay));
    }

    [Fact]
    public void TheDevelopmentKey_IsUsedOnlyWhenAllowed_AndAStoredKeyWins()
    {
        string? before = Environment.GetEnvironmentVariable(VirusTotalApiKey.EnvironmentVariable);
        Environment.SetEnvironmentVariable(VirusTotalApiKey.EnvironmentVariable, "FAKE-environment-key-not-real-000000");
        try
        {
            Assert.False(Service(allowEnvironmentKey: false).GetStatus().HasKey); // the service / SYSTEM never reads it

            var console = Service(allowEnvironmentKey: true);
            Assert.Equal((true, true), (console.GetStatus().HasKey, console.GetStatus().KeyFromEnvironment));
            console.SetKey(FakeKey);
            Assert.Equal((true, false), (console.GetStatus().HasKey, console.GetStatus().KeyFromEnvironment));
        }
        finally
        {
            Environment.SetEnvironmentVariable(VirusTotalApiKey.EnvironmentVariable, before);
        }
    }

    // ---- Pipe ----

    private (PipeRequestHandler Handler, ScanJobHarness Harness) PipeHandler(IVirusTotalService service)
    {
        var harness = new ScanJobHarness();
        var handler = new PipeRequestHandler(harness.Service, null, new PipeServerOptions(), harness.Time, NullLogger.Instance, _ => 3, virusTotal: service);
        _owned.Add(handler);
        _owned.Add(harness);
        return (handler, harness);
    }

    private PipeSession Session(bool admin)
    {
        var session = new PipeSession(new FakeClientIdentity(isAdmin: admin), new RecordingSink()) { HelloDone = true };
        _owned.Add(session);
        return session;
    }

    private static Task<PipeReply> SendAsync(PipeRequestHandler handler, PipeSession session, PipeRequestKind kind, object? body = null) =>
        handler.HandleAsync(session, new PipeRequest(1, kind, body is null ? null : PipeJson.ToElement(body)), CancellationToken.None);

    [Fact]
    public async Task Pipe_AStandardUser_CantSetClearOrToggle_AnAdministratorCan_AndNoReplyEverCarriesTheKey()
    {
        var service = Service();
        var (handler, _) = PipeHandler(service);
        var user = Session(admin: false);
        var admin = Session(admin: true);

        Assert.Equal(PipeStatus.AccessDenied, (await SendAsync(handler, user, PipeRequestKind.VirusTotalSetKey, new VirusTotalSetKeyRequest(FakeKey))).Status);
        Assert.Equal(PipeStatus.AccessDenied, (await SendAsync(handler, user, PipeRequestKind.VirusTotalSetEnabled, new VirusTotalSetEnabledRequest(true))).Status);
        Assert.False(service.GetStatus().HasKey);
        Assert.False(File.Exists(Path.Combine(Folder, VirusTotalKeyStore.FileName)));

        var set = await SendAsync(handler, admin, PipeRequestKind.VirusTotalSetKey, new VirusTotalSetKeyRequest(FakeKey));
        Assert.Equal(PipeStatus.Ok, set.Status);
        Assert.Equal(PipeStatus.Ok, (await SendAsync(handler, admin, PipeRequestKind.VirusTotalSetEnabled, new VirusTotalSetEnabledRequest(true))).Status);
        Assert.Equal(PipeStatus.AccessDenied, (await SendAsync(handler, user, PipeRequestKind.VirusTotalClearKey)).Status);
        Assert.True(service.GetStatus().HasKey); // still set: the standard user couldn't clear it

        // Everyone may read the status; it says "key set", never the key.
        foreach (var reply in new[]
        {
            set,
            await SendAsync(handler, user, PipeRequestKind.VirusTotalGetStatus),
            await SendAsync(handler, user, PipeRequestKind.GetStatus),
        })
        {
            Assert.Equal(PipeStatus.Ok, reply.Status);
            string json = JsonSerializer.Serialize(reply.Body, reply.Body!.GetType(), PipeJson.Options);
            Assert.DoesNotContain(FakeKey, json, StringComparison.Ordinal);
            Assert.Contains("\"HasKey\":true", json, StringComparison.Ordinal);
        }

        Assert.Equal(PipeStatus.Ok, (await SendAsync(handler, admin, PipeRequestKind.VirusTotalClearKey)).Status);
        Assert.False(service.GetStatus().HasKey);
    }

    [Fact]
    public async Task Pipe_AMalformedKey_IsBadRequest_NothingIsStored_AndTheRequestNeverPrintsTheKey()
    {
        var service = Service();
        var (handler, _) = PipeHandler(service);

        var bad = await SendAsync(handler, Session(admin: true), PipeRequestKind.VirusTotalSetKey, new VirusTotalSetKeyRequest("short\r\nx-apikey: injected"));

        Assert.Equal(PipeStatus.BadRequest, bad.Status);
        Assert.False(service.GetStatus().HasKey);
        Assert.DoesNotContain(FakeKey, new VirusTotalSetKeyRequest(FakeKey).ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheEngineHost_WiresTheVirusTotalLookup_WithoutCreatingAnythingOnResolve()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        Assert.IsType<VirusTotalOnlineLookup>(host.Services.GetRequiredService<IOnlineHashLookup>());
        Assert.Same(host.Services.GetRequiredService<VirusTotalService>(), host.Services.GetRequiredService<IVirusTotalService>());
        // RealDataRootGuard checks after the run that %ProgramData%\sap-AV was not created or changed.
    }

    // ---- Fakes ----

    private static HttpResponseMessage Report(HttpRequestMessage request, int malicious, int suspicious) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($$"""
            {"data": {"id": "{{request.RequestUri!.Segments[^1]}}", "type": "file", "attributes": {
                "last_analysis_date": 1760000000,
                "last_analysis_stats": {"malicious": {{malicious}}, "suspicious": {{suspicious}}, "undetected": 60, "harmless": 0},
                "last_analysis_results": {},
                "popular_threat_classification": {"suggested_threat_label": "trojan.fake/test"}
            } } }
            """, Encoding.UTF8, "application/json"),
    };

    private sealed class FakeHandler : HttpMessageHandler
    {
        public sealed record Request(HttpMethod Method, string Uri, bool HasContent);

        private int _calls;

        public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; } = r => Report(r, 0, 0);

        public List<Request> Sent { get; } = [];

        public int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            lock (Sent)
            {
                Sent.Add(new Request(request.Method, request.RequestUri!.ToString(), request.Content is not null));
            }

            return Task.FromResult(Respond(request));
        }
    }

    private sealed class FakeClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
