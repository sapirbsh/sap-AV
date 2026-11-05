using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Alerts;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Core.VirusTotal;
using SapAV.Engine.Alerts;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Remediation;
using SapAV.Engine.RealTime;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.RealTime;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;
using SapAV.Engine.VirusTotal;

namespace SapAV.Engine.Tests.CrossStep;

/// <summary>
/// Section D, across the steps: real-time file (D1) → real scan broker → VirusTotal wiring (D2/D3, fake HTTP, never the real API)
/// → verdict handler → auto-quarantine; the same lookup behind a persistence entry (D4); and the data folders that must fail
/// safe together (D3/D4/D5). The "malware" is a plain text file: only the fake VirusTotal answer says it is bad.
/// </summary>
public sealed class SectionDCrossStepTests : IDisposable
{
    private const string FakeKey = "FAKE-test-key-not-real-0123456789abcdef";

    private readonly TempDir _vt = new();
    private readonly ManualTime _clock = new();
    private readonly FakeVtHandler _http = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        _vt.Dispose();
    }

    private T Use<T>(T owned)
        where T : IDisposable
    {
        _owned.Add(owned);
        return owned;
    }

    private VirusTotalOnlineLookup ActiveLookup(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        _http.Respond = respond;
        var service = Use(new VirusTotalService(new VirusTotalOptions { Folder = Path.Combine(_vt.Path, "sap-AV", "VirusTotal") }, NullLogger.Instance, _clock,
            protectedMode: true, allowEnvironmentKey: false, new QuarantineAccessPolicy([QuarantineTestContext.CurrentUser]),
            () => new HttpClient(_http, disposeHandler: false), parentIsDataRoot: true));
        Assert.Equal(VirusTotalChange.Done, service.SetKey(FakeKey));
        Assert.Equal(VirusTotalChange.Done, service.SetEnabled(true));
        return new VirusTotalOnlineLookup(service, new VirusTotalOptions(), noteWhenUnavailable: true);
    }

    private InProcessScanBroker Broker(IOnlineHashLookup lookup, string? suspiciousMarkerRule = null) =>
        Use(new InProcessScanBroker(new FakeRulesSource(suspiciousMarkerRule), NullLogger.Instance, lookup));

    /// <summary>A file owned by an ordinary user (what a download is), so the auto-quarantine policy is the same on every machine.</summary>
    private sealed class UserOwned : IFileSecurityReader
    {
        public RawSecurityDescriptor? Read(SafeFileHandle handle) =>
            new($"O:{QuarantineTestContext.CurrentUser.Value}D:(A;;FA;;;{QuarantineTestContext.CurrentUser.Value})");
    }

    private static HttpResponseMessage Found(HttpRequestMessage request, int malicious) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($$"""
            {"data": {"id": "{{request.RequestUri!.Segments[^1]}}", "type": "file", "attributes": {
                "last_analysis_date": 1760000000,
                "last_analysis_stats": {"malicious": {{malicious}}, "suspicious": 0, "undetected": 60, "harmless": 0},
                "last_analysis_results": {},
                "popular_threat_classification": {"suggested_threat_label": "trojan.fake/test"}
            } } }
            """, Encoding.UTF8, "application/json"),
    };

    // ---- D1 + D2/D3: a new download, the online verdict, auto-quarantine ----

    [Fact]
    public void RealTime_AnUnsignedDownload_VirusTotalSaysMalicious_IsQuarantined_AndOnlyItsHashWasSent()
    {
        var sink = new RecordingAlertSink();
        using var dispatcher = new AlertDispatcher(sink, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 64);
        using var quarantine = new QuarantineTestContext();
        using var rt = new RealTimeHarness();
        rt.RealBroker = Broker(ActiveLookup(r => Found(r, malicious: 14)));
        rt.Handler = new ScanVerdictHandler(dispatcher, quarantine.Manager, new AutoQuarantinePolicy([], new UserOwned()),
            new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);
        rt.Start();

        string path = rt.Write("update.exe", "plain text that only the fake VirusTotal answer calls bad");
        string sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
        rt.Events.Added(rt.Watched, "update.exe");
        var result = rt.WaitFor("update.exe");

        Assert.Equal((Verdict.Malicious, ScanFileAction.Quarantined), (result.Scan!.Verdict!.Value, result.Scan.Action));
        Assert.False(File.Exists(path));
        var request = Assert.Single(_http.Sent);
        Assert.EndsWith("/files/" + sha, request.Uri, StringComparison.Ordinal);
        Assert.False(request.HasContent); // never the file
        Assert.DoesNotContain("update", request.Uri, StringComparison.OrdinalIgnoreCase); // never the name or path
        Assert.True(dispatcher.Drain(RealTimeHarness.Timeout));
        var alert = Assert.Single(sink.Alerts, a => a.Type == AlertType.MaliciousFile);
        Assert.Contains("VirusTotal", string.Join(" ", alert.Reasons), StringComparison.Ordinal);
        Assert.Equal((ScanTrigger.RealTime, AlertAction.Quarantined, MitreTechniqueIds.MaliciousFile), (alert.Trigger, alert.Action, alert.TechniqueId));
    }

    [Fact]
    public void RealTime_WhenVirusTotalIsDownOrOffline_TheFileIsNeverQuarantinedOrCalledClean_AndNonRiskyFilesAreNeverAsked()
    {
        using var quarantine = new QuarantineTestContext();
        using var rt = new RealTimeHarness();
        int attempt = 0;
        rt.RealBroker = Broker(ActiveLookup(r => Interlocked.Increment(ref attempt) == 1
            ? throw new HttpRequestException("offline")
            : new HttpResponseMessage(HttpStatusCode.InternalServerError)));
        rt.Handler = new ScanVerdictHandler(new RecordingAlertSink(), quarantine.Manager, new AutoQuarantinePolicy([], new UserOwned()),
            new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);
        rt.Start();

        string offline = rt.Write("one.exe", "first");
        string failing = rt.Write("two.exe", "second");
        string picture = rt.Write("photo.jpg", "third");
        rt.Events.Added(rt.Watched, "one.exe", "two.exe", "photo.jpg");
        var results = new[] { rt.WaitFor("one.exe"), rt.WaitFor("two.exe"), rt.WaitFor("photo.jpg") };

        Assert.All(results, r =>
        {
            Assert.Equal(RealTimeOutcome.Scanned, r.Outcome);
            Assert.NotEqual(Verdict.Malicious, r.Scan!.Verdict);
            Assert.NotEqual(ScanFileAction.Quarantined, r.Scan.Action);
        });
        Assert.True(File.Exists(offline) && File.Exists(failing) && File.Exists(picture));
        Assert.Equal(2, _http.Calls); // the .jpg was never sent
    }

    [Fact]
    public void RealTime_AVirusTotalOnlyDetection_OfAFileOnlySystemMayChange_IsNeverMovedOnItsOwn()
    {
        using var quarantine = new QuarantineTestContext();
        using var rt = new RealTimeHarness();
        rt.RealBroker = Broker(ActiveLookup(r => Found(r, malicious: 40)));
        rt.Handler = new ScanVerdictHandler(new RecordingAlertSink(), quarantine.Manager,
            new AutoQuarantinePolicy([], new FixedSecurity("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)")),
            new AutoQuarantineLimiter(TimeProvider.System, 20, TimeSpan.FromMinutes(10)), TimeProvider.System, NullLogger.Instance);
        rt.Start();

        string path = rt.Write("service-helper.exe", "owned by SYSTEM in this test");
        rt.Events.Added(rt.Watched, "service-helper.exe");
        var result = rt.WaitFor("service-helper.exe");

        Assert.Equal(Verdict.Malicious, result.Scan!.Verdict);
        Assert.NotEqual(ScanFileAction.Quarantined, result.Scan.Action); // the user decides
        Assert.True(File.Exists(path));
    }

    private sealed class FixedSecurity(string sddl) : IFileSecurityReader
    {
        public RawSecurityDescriptor? Read(SafeFileHandle handle) => new(sddl);
    }

    // ---- D4 + D2/D3: an autostart entry whose target VirusTotal knows ----

    [Fact]
    public void Persistence_ANewRunValue_WhoseSuspiciousTargetVirusTotalCallsMalicious_RaisesAMaliciousAlert_ACleanTargetIsNeverAsked()
    {
        const string rule = "rule D_Marker { meta: verdict = \"suspicious\" strings: $a = \"sapav-d-marker\" condition: $a }";
        var lookup = ActiveLookup(r => Found(r, malicious: 20));
        var broker = Broker(lookup, rule);
        using var m = new MonitorHarness();
        m.Broker.OnScan = async (item, file, ct) => await broker.ScanOpenedAsync(item, file, [], ct);
        m.Baseline();

        string flagged = m.Target("flagged.exe");
        File.WriteAllText(flagged, "x sapav-d-marker x"); // the local rule alone: Suspicious
        m.UserRunValue(MonitorHarness.Alice, "Flagged", flagged);
        m.UserRunValue(MonitorHarness.Alice, "Plain", m.Target("plain.exe")); // Clean locally: a scan only asks about Suspicious files
        m.MarkAndRun(new PersistenceScope("registry autoruns", MonitorHarness.Alice));

        var alert = Assert.Single(m.PersistenceAlerts("Flagged"));
        Assert.Equal(AlertType.MaliciousPersistence, alert.Type);
        Assert.Single(_http.Sent);
        Assert.DoesNotContain(m.PersistenceAlerts("Plain"), a => a.Type == AlertType.MaliciousPersistence);
    }

    // ---- D3 + D4 + D5: a data root a user prepared fails safe, everywhere at once ----

    [Fact]
    public async Task AUserPreparedDataRoot_VirusTotalAndTheBackupStore_BothRefuseIt_NothingIsSentOrSaved_AndTheUsersFilesStay()
    {
        // A user made %ProgramData%\sap-AV\VirusTotal and \PersistenceBackups first, with a planted file and an open DACL.
        string root = Directory.CreateDirectory(Path.Combine(_vt.Path, "planted", "sap-AV")).FullName;
        var planted = new List<string>();
        foreach (var name in new[] { "VirusTotal", "PersistenceBackups" })
        {
            var dir = Directory.CreateDirectory(Path.Combine(root, name));
            var security = dir.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            dir.SetAccessControl(security);
            string file = Path.Combine(dir.FullName, "planted.db");
            File.WriteAllText(file, "planted before the engine ran");
            planted.Add(file);
        }

        var policy = QuarantineAccessPolicy.Default;
        _http.Respond = r => Found(r, malicious: 30);
        var service = Use(new VirusTotalService(new VirusTotalOptions { Folder = Path.Combine(root, "VirusTotal") }, NullLogger.Instance, _clock,
            protectedMode: true, allowEnvironmentKey: false, policy, () => new HttpClient(_http, disposeHandler: false), parentIsDataRoot: false));
        var store = FilePersistenceBackupStore.TryCreate(Path.Combine(root, "PersistenceBackups"), new ThrowingKeys(), policy, NullLogger.Instance);

        Assert.Equal(VirusTotalChange.Unavailable, service.SetKey(FakeKey));
        Assert.Equal(VirusTotalActivity.Unavailable, service.Activity);
        Assert.Null(store); // Block & remove is unavailable, not "backed up into a folder a user controls"
        var outcome = await new VirusTotalOnlineLookup(service, new VirusTotalOptions(), noteWhenUnavailable: true)
            .LookupAsync(new OnlineLookupRequest(new ScanItem(@"C:\Users\u\Downloads\setup.exe", ScanTrigger.RealTime), new string('a', 64),
                SapAV.Core.Signatures.SignatureStatus.UnsignedOrInvalid, Verdict.Clean));
        Assert.Null(outcome.Detection);
        Assert.NotNull(outcome.Note); // "not checked", never Clean
        Assert.Equal(0, _http.Calls);
        Assert.All(planted, p => Assert.Equal("planted before the engine ran", File.ReadAllText(p))); // never deleted or rewritten
        Assert.Equal(["planted.db"], Directory.GetFiles(Path.Combine(root, "VirusTotal")).Select(Path.GetFileName)); // nothing added
    }

    private sealed class ThrowingKeys : IQuarantineKeyProvider
    {
        public byte[] GetOrCreateKey(string storeRoot, QuarantineAccessPolicy policy) => throw new InvalidOperationException("must not be reached");
    }

    private sealed class FakeVtHandler : HttpMessageHandler
    {
        private int _calls;

        public sealed record Request(string Uri, bool HasContent);

        public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; } = r => new HttpResponseMessage(HttpStatusCode.NotFound);

        public List<Request> Sent { get; } = [];

        public int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            lock (Sent)
            {
                Sent.Add(new Request(request.RequestUri!.ToString(), request.Content is not null));
            }

            return Task.FromResult(Respond(request));
        }
    }
}
