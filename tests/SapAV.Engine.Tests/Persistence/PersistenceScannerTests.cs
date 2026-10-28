using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Engine.Alerts;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// C3 engine glue: each distinct target / host is scanned once through SafeScanOpen + the broker, entries are judged and
/// Suspicious / Malicious findings are alerted. Synthetic entries and temp files only; nothing under HKLM is touched.
/// </summary>
public sealed class PersistenceScannerTests : IDisposable
{
    private const string MachineRun = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private readonly TempDir _temp = new();
    private readonly RecordingAlertSink _alerts = new();

    public void Dispose() => TempDir.DeleteTree(_temp.Path);

    private string Write(string name, string content = "plain")
    {
        var path = Path.Combine(_temp.Path, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static PersistenceEntry Run(string? target, string value = "App", string? host = null, params ResolutionFlag[] flags) =>
        new(PersistenceKind.RunKey, null, MachineRun, value, target ?? "x",
            target is null ? ResolvedCommand.Unresolved(TargetUnresolvedReason.InlineCommand, host, "", flags) : ResolvedCommand.Resolved(target, "", host, flags),
            enabled: true);

    private static PersistenceCollection Collection(params PersistenceEntry[] entries) => new(entries, [], TimeSpan.Zero);

    /// <summary>Everything admin-only, so only the target scan and the entry rules decide.</summary>
    private sealed class AdminOnlyAcl : IPathWritability
    {
        public Writability FileModifiable(string filePath) => Writability.AdminOnly;

        public Writability FileCreatable(string filePath) => Writability.AdminOnly;
    }

    private PersistenceScanner Scanner(IScanBroker broker, IScanVerdictHandler? handler = null, IPathWritability? acl = null) =>
        new(broker, _alerts, TimeProvider.System, NullLogger.Instance, new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" }),
            () => acl ?? new AdminOnlyAcl(), handler);

    [Fact]
    public void DistinctFiles_DedupesTargetsAndHosts_CaseInsensitively_AndSkipsKnownMissingTargets()
    {
        var host = @"C:\Windows\System32\rundll32.exe";
        var files = PersistenceScanner.DistinctFiles(
        [
            Run(@"C:\Apps\a.dll", host: host, flags: ResolutionFlag.InterpreterHost),
            Run(@"C:\APPS\A.DLL", "Again"),
            Run(@"C:\Apps\b.dll", "B", host, ResolutionFlag.InterpreterHost),
            Run(@"C:\Gone\old.exe", "Gone", flags: ResolutionFlag.TargetNotFound),
            Run(null, "Inline", host: host, flags: ResolutionFlag.InlineCommand),
        ]);

        Assert.Equal([@"C:\Apps\a.dll", host, @"C:\Apps\b.dll"], files);
    }

    [Fact]
    public async Task EachDistinctFileIsScannedOnce_EveryEntryIsJudged_AndOnlyDetectionsAreAlerted()
    {
        var broker = new FakeScanBroker();
        var bad = Write("malware.exe");
        var good = Write("tool.exe");
        var collection = Collection(Run(bad, "One"), Run(bad.ToUpperInvariant(), "Two"), Run(good, "Three"));

        var result = await Scanner(broker).ScanAsync(collection);

        Assert.Equal(2, broker.Calls);
        Assert.Equal((2, 0), (result.FilesScanned, result.FilesSkipped));
        Assert.Equal([Verdict.Malicious, Verdict.Malicious, Verdict.Clean], result.Findings.Select(f => f.Verdict));
        Assert.Equal(2, result.Detections.Count());
        var alerts = _alerts.Snapshot();
        Assert.Equal(2, alerts.Length); // two entries running the same file are two incidents
        Assert.All(alerts, a => Assert.Equal((AlertType.MaliciousPersistence, AlertAction.None), (a.Type, a.Action)));
        Assert.Equal(["One", "Two"], alerts.Select(a => a.Autostart!.ValueName).Order());
        Assert.Equal(result.Findings[0].AlertId, alerts.Single(a => a.Autostart!.ValueName == "One").AlertId);
        Assert.Null(result.Findings[2].AlertId);
    }

    [Fact]
    public async Task MissingTarget_IsJudgedFromTheFailedOpen_AndNothingIsScanned()
    {
        var broker = new FakeScanBroker();
        var missing = Path.Combine(_temp.Path, "deleted.exe");

        var result = await Scanner(broker).ScanAsync(Collection(Run(missing)));

        Assert.Equal(0, broker.Calls);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(Verdict.Clean, finding.Verdict);
        Assert.Contains(finding.Judgement.Signals, s => s.Rule == PersistenceRuleIds.MissingTarget);
    }

    [Fact]
    public async Task Budgets_LeaveTheRestUnscanned_ButStillJudged_WithIssues()
    {
        var broker = new FakeScanBroker();
        var collection = Collection(Run(Write("a.exe"), "A"), Run(Write("b.exe"), "B"), Run(Write("c.exe"), "C"));

        var capped = await Scanner(broker).ScanAsync(collection, new PersistenceScanOptions { MaxTargets = 1 });
        Assert.Equal((1, 2, 3), (capped.FilesScanned, capped.FilesSkipped, capped.Findings.Count));
        Assert.Contains(capped.Issues, i => i.Reason == PersistenceIssueReason.LimitReached);

        var timedOut = await Scanner(broker).ScanAsync(collection, new PersistenceScanOptions { TimeBudget = TimeSpan.Zero, Parallelism = 1 });
        Assert.Equal(0, timedOut.FilesScanned);
        Assert.Contains(timedOut.Issues, i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded);
        Assert.All(timedOut.Findings, f => Assert.Contains(f.Judgement.Signals, s => s.Rule == PersistenceRuleIds.TargetNotScanned));
    }

    private sealed class RecordingHandler : IScanVerdictHandler
    {
        public List<(string Path, bool HandleOpen)> Seen { get; } = [];

        public Task<ScanVerdictOutcome> HandleAsync(FileScanReport report, OpenedScanFile? opened, ScanBudget? budget, CancellationToken cancellationToken)
        {
            lock (Seen)
            {
                Seen.Add((report.Result.Item.Path, opened is not null && !opened.Handle.IsClosed));
            }

            return Task.FromResult(ScanVerdictOutcome.Nothing);
        }

        public void JobFinished(ScanJob job)
        {
        }
    }

    [Fact]
    public async Task TargetHandler_SeesEachScannedTarget_WhileItsHandleIsOpen()
    {
        var handler = new RecordingHandler();
        var target = Write("mal-target.exe");

        await Scanner(new FakeScanBroker(), handler).ScanAsync(Collection(Run(target)));

        Assert.Equal([(target, true)], handler.Seen);
    }

    /// <summary>The real broker and worker (test-only unsandboxed isolation, same protocol) with the B5 marker rule.</summary>
    private static SandboxedScanBroker RealBroker() => new(new SandboxOptions
    {
        WorkerPath = TestAppContainer.WorkerExe,
        WorkerCount = 1,
        EnableWorkerTestHooks = true,
        Isolation = WorkerIsolation.UnsandboxedForTests,
        RequestTimeout = TimeSpan.FromSeconds(60),
        RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
        RestartBackoffMax = TimeSpan.FromMilliseconds(100),
    }, new FakeRulesSource(ScanBrokerSupervisionTests.MarkerRule), NullLogger.Instance);

    [Fact]
    public async Task EndToEnd_ARunEntryInAFakeRegistry_PointingAtAMarkerFile_IsAMaliciousFinding_WithAnAlert()
    {
        using var registry = new RegistryTestRoot();
        var dropper = Write("dropper.exe", "sapav-b5-marker plus some padding text");
        using (var run = registry.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
        {
            run.SetValue("Updater", $"\"{dropper}\" /silent");
        }

        var collection = registry.Collect(new SetProbe(), new RegistryAutorunSource());
        using var broker = RealBroker();
        using var dispatcher = new AlertDispatcher(_alerts, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 100, 64);
        var scanner = new PersistenceScanner(broker, dispatcher, TimeProvider.System, NullLogger.Instance); // real judge + real ACL check

        var result = await scanner.ScanAsync(collection, new PersistenceScanOptions { Trigger = ScanTrigger.QuickScan });
        Assert.True(dispatcher.Drain(TimeSpan.FromSeconds(30)));

        var finding = Assert.Single(result.Findings);
        Assert.Equal((Verdict.Malicious, PersistencePriority.High), (finding.Verdict, finding.Judgement.Priority));
        Assert.Equal(ScanStatus.Scanned, finding.Target!.Status);
        Assert.Contains(MitreTechniqueIds.RegistryRunKeysStartupFolder, finding.Judgement.SecondaryTechniqueIds);
        // The temp file is the test user's own, so a machine-wide Run entry pointing at it is also a privilege-escalation path.
        Assert.Contains(finding.Judgement.Signals, s => s.Rule == PersistenceRuleIds.TargetUserModifiable);

        var alert = Assert.Single(_alerts.Snapshot(), a => a.Type == AlertType.MaliciousPersistence);
        Assert.Equal(AlertEventCatalog.MaliciousPersistenceEventId, AlertEventCatalog.For(alert.Type).EventId);
        Assert.Equal((dropper, MachineRun, "Updater", ScanTrigger.QuickScan), (alert.FilePath, alert.Autostart!.Location, alert.Autostart.ValueName, alert.Trigger));
        Assert.Equal(finding.Target.Sha256, alert.Sha256);
        Assert.Contains(alert.Reasons, r => r.StartsWith("Autostart target: ", StringComparison.Ordinal));
        Assert.Equal(alert, System.Text.Json.JsonSerializer.Deserialize<Alert>(AlertEventMessage.Format(alert)));
    }

    [Fact]
    public async Task EndToEnd_AMicrosoftSignedSystem32Target_IsClean_WithNoSignals()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        using var broker = RealBroker();
        var scanner = new PersistenceScanner(broker, _alerts, TimeProvider.System, NullLogger.Instance);

        var result = await scanner.ScanAsync(Collection(Run(cmd)));

        var finding = Assert.Single(result.Findings);
        Assert.Equal(SignatureStatus.Microsoft, finding.Target!.SignatureStatus);
        Assert.Equal(Verdict.Clean, finding.Verdict);
        Assert.Empty(finding.Judgement.Signals);
        Assert.Empty(_alerts.Snapshot());
    }

    [Fact]
    public void PersistenceAlerts_HaveFixedEventIds_InTheSystemChangeRange()
    {
        Assert.Equal((2001, System.Diagnostics.EventLogEntryType.Error), (AlertEventCatalog.For(AlertType.MaliciousPersistence).EventId, AlertEventCatalog.For(AlertType.MaliciousPersistence).EntryType));
        Assert.Equal((2002, System.Diagnostics.EventLogEntryType.Warning), (AlertEventCatalog.For(AlertType.SuspiciousPersistence).EventId, AlertEventCatalog.For(AlertType.SuspiciousPersistence).EntryType));
    }

    [Fact]
    public async Task PersistenceAlerts_KeepTheRulesReasons_AndCapTheCarriedWorkerText()
    {
        var target = Write("mal-long.exe");
        var broker = new FakeScanBroker
        {
            OnScan = (item, file, _) =>
            {
                var report = FakeScanBroker.Judge(item, file, TimeProvider.System);
                var long_ = new Detection(Verdict.Malicious, "YARA " + new string('w', 900), MitreTechniqueIds.MaliciousFile, DetectionSource.Yara);
                return Task.FromResult<FileScanReport?>(report with { Result = new ScanResult(item, [long_], report.Result.Timestamp, report.Result.Sha256) });
            },
        };
        var acl = new UserWritableAcl();

        await Scanner(broker, acl: acl).ScanAsync(Collection(Run(target)));

        var alert = Assert.Single(_alerts.Snapshot());
        Assert.Equal(ScanAlerts.MaxWorkerReasonLength, alert.Reasons[0].Length);
        Assert.Contains(alert.Reasons, r => r.Contains("Standard users can modify", StringComparison.Ordinal));
    }

    private sealed class UserWritableAcl : IPathWritability
    {
        public Writability FileModifiable(string filePath) => Writability.UserWritable;

        public Writability FileCreatable(string filePath) => Writability.UserWritable;
    }
}
