using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Alerts;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.Alerts;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Alerts;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>B3 per-file pipeline after the scan: alerts and the auto-quarantine policy, with the real quarantine.</summary>
public sealed class ScanVerdictHandlerTests : IDisposable
{
    private readonly QuarantineTestContext _quarantine = new();
    private readonly ScanJobHarness _jobs = new();
    private readonly RecordingAlertSink _sink = new();
    private readonly AlertDispatcher _dispatcher;

    public ScanVerdictHandlerTests()
    {
        _dispatcher = new AlertDispatcher(_sink, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 64);
    }

    public void Dispose()
    {
        _jobs.Dispose();
        _dispatcher.Dispose();
        _quarantine.Dispose();
    }

    private void UseHandler(IEnumerable<string>? protectedFolders = null, IFileOwnerReader? owners = null, int maxPerWindow = 20,
        IQuarantineService? quarantine = null, IAlertDispatcher? alerts = null)
    {
        _jobs.Handler = new ScanVerdictHandler(alerts ?? _dispatcher, quarantine ?? _quarantine.Manager,
            new AutoQuarantinePolicy(protectedFolders ?? [], owners), new AutoQuarantineLimiter(TimeProvider.System, maxPerWindow, TimeSpan.FromMinutes(10)),
            TimeProvider.System, NullLogger.Instance);
    }

    private async Task<ScanJob> RunAsync()
    {
        var (job, _) = _jobs.Start();
        await JobWait.Done(job);
        Assert.True(_dispatcher.Drain(JobWait.Timeout));
        return job;
    }

    [Fact]
    public async Task Malicious_IsQuarantinedThroughTheScanHandle_AndAlertedOnce_WithTheQuarantinedAction()
    {
        UseHandler();
        var path = _jobs.Write("mal-dropper.bin", "synthetic marker content");

        var job = await RunAsync();

        var result = Assert.Single(job.Results);
        Assert.Equal(ScanFileAction.Quarantined, result.Action);
        Assert.False(File.Exists(path));
        var entry = Assert.Single(_quarantine.Manager.List());
        Assert.Equal(result.QuarantineItemId, entry.Id);
        Assert.Equal(result.AlertId, entry.AlertId); // the quarantine metadata points at the alert
        var alert = Assert.Single(_sink.Alerts);
        Assert.Equal((AlertType.MaliciousFile, AlertAction.Quarantined, result.AlertId), (alert.Type, alert.Action, (Guid?)alert.AlertId));
        Assert.Equal(1, job.GetProgress().Counters.Quarantined);
    }

    [Fact]
    public async Task Malicious_WhileAnotherProgramHasItOpenForWriting_IsNotMoved()
    {
        UseHandler();
        var path = _jobs.Write("mal-being-written.bin", "content");
        using var writer = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);

        var job = await RunAsync();

        Assert.True(File.Exists(path)); // the reopen for quarantine demands Read|Delete sharing only: a writer blocks it
        Assert.Empty(_quarantine.Manager.List());
        Assert.DoesNotContain(job.Results, r => r.Action == ScanFileAction.Quarantined);
    }

    [Fact]
    public async Task Malicious_InAProtectedFolder_IsNotAutoQuarantined_ButFlagged()
    {
        UseHandler(protectedFolders: [Path.Combine(_jobs.Root, "Program Files")]);
        var path = _jobs.Write(@"Program Files\Vendor\mal-tool.exe", "x");

        var job = await RunAsync();

        var result = Assert.Single(job.Results);
        Assert.Equal(ScanFileAction.NeedsUserConfirmation, result.Action);
        Assert.Contains("protected system folder", result.Detail, StringComparison.Ordinal);
        Assert.True(File.Exists(path));
        Assert.Equal(AlertAction.NeedsUserConfirmation, Assert.Single(_sink.Alerts).Action);
        Assert.Equal(1, job.GetProgress().Counters.NeedsUserConfirmation);
    }

    [Theory]
    [InlineData("S-1-5-18")] // SYSTEM
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")] // TrustedInstaller
    public async Task Malicious_OwnedBySystemOrTrustedInstaller_IsNotAutoQuarantined(string ownerSid)
    {
        UseHandler(owners: new FixedOwner(new SecurityIdentifier(ownerSid)));
        var path = _jobs.Write("mal-system-owned.dll", "x");

        var job = await RunAsync();

        Assert.Equal(ScanFileAction.NeedsUserConfirmation, Assert.Single(job.Results).Action);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Policy_RealWindowsBinary_IsProtected_AndOwnerReadsFromTheHandle()
    {
        var policy = new AutoQuarantinePolicy([]);
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        using var opened = ScanFileOpener.Open(new ScanItem(cmd, ScanTrigger.CustomScan), [], TimeProvider.System, out _)!;
        var report = FakeScanBroker.Judge(new ScanItem(cmd, ScanTrigger.CustomScan), opened, TimeProvider.System);

        Assert.Contains("protected system folder", policy.ProtectedReason(report, opened), StringComparison.Ordinal);
        Assert.Equal(AutoQuarantinePolicy.TrustedInstaller, HandleOwnerReader.Instance.GetOwner(opened.Handle));

        var mine = _jobs.Write("mine.txt");
        using var own = ScanFileOpener.Open(new ScanItem(mine, ScanTrigger.CustomScan), [], TimeProvider.System, out _)!;
        Assert.Null(policy.ProtectedReason(FakeScanBroker.Judge(new ScanItem(mine, ScanTrigger.CustomScan), own, TimeProvider.System), own));
    }

    [Fact]
    public void OnlyMalicious_IsEligible_EveryOtherVerdictIncludingFuturePupNever()
    {
        var item = new ScanItem(@"C:\x\f.exe", ScanTrigger.RealTime);
        foreach (var verdict in Enum.GetValues<Verdict>())
        {
            var detections = verdict == Verdict.Clean ? [] : new[] { new Detection(verdict, "r", "T1204.002", DetectionSource.Yara) };
            var report = new FileScanReport(new ScanResult(item, detections, DateTimeOffset.UnixEpoch, SampleAlerts.Sha),
                HashResult.Hashed(SampleAlerts.Sha, 1), null, null, null, null, []);
            Assert.Equal(verdict == Verdict.Malicious, AutoQuarantinePolicy.IsEligibleVerdict(report));
        }
    }

    [Fact]
    public async Task Suspicious_IsAlertedButNeverQuarantined()
    {
        UseHandler();
        var path = _jobs.Write("sus-invoice.pdf.exe", "x");

        var job = await RunAsync();

        Assert.Equal(ScanFileAction.None, Assert.Single(job.Results).Action);
        Assert.True(File.Exists(path));
        Assert.Empty(_quarantine.Manager.List());
        Assert.Equal((AlertType.SuspiciousFile, AlertAction.None), (Assert.Single(_sink.Alerts).Type, _sink.Alerts[0].Action));
    }

    [Fact]
    public async Task AutoQuarantine_IsRateLimited_WithOneBurstAlert()
    {
        UseHandler(maxPerWindow: 1);
        for (int i = 0; i < 3; i++)
        {
            _jobs.Write($"mal-{i}.bin", $"synthetic {i}");
        }

        var job = await RunAsync();

        Assert.Equal(1, job.Results.Count(r => r.Action == ScanFileAction.Quarantined));
        Assert.Equal(2, job.Results.Count(r => r.Action == ScanFileAction.NeedsUserConfirmation));
        Assert.Single(_sink.Alerts, a => a.Type == AlertType.AutoQuarantineBurst);
        Assert.Equal(3, _sink.Alerts.Count(a => a.Type == AlertType.MaliciousFile));
    }

    [Fact]
    public async Task BlockedAlertSink_DoesNotBlockScanning()
    {
        using var blocked = new BlockingAlertSink();
        using var dispatcher = new AlertDispatcher(blocked, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 2);
        UseHandler(quarantine: new UnavailableQuarantine(), alerts: dispatcher);
        for (int i = 0; i < 10; i++)
        {
            _jobs.Write($"sus-{i}.bin", $"content {i}");
        }

        var (job, _) = _jobs.Start();
        await JobWait.Done(job); // completes while the sink is still hung

        Assert.Equal(10, job.GetProgress().Counters.Suspicious);
        blocked.Release();
        Assert.True(dispatcher.Drain(JobWait.Timeout));
        Assert.Contains(blocked.Alerts, a => a.Type == AlertType.AlertsSuppressed); // what didn't fit is summarised
    }

    private sealed class FixedOwner(SecurityIdentifier owner) : IFileOwnerReader
    {
        public SecurityIdentifier? GetOwner(SafeFileHandle handle) => owner;
    }

    private sealed class UnavailableQuarantine : IQuarantineService
    {
        public bool IsAvailable => false;

        public Task<QuarantineResult> QuarantineAsync(FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<QuarantineResult> QuarantineHandleAsync(SafeFileHandle handle, FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<RestoreResult> RestoreAsync(string itemId, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public IReadOnlyList<QuarantineEntry> List() => [];

        public QuarantineEntry? Get(string itemId) => null;
    }
}
