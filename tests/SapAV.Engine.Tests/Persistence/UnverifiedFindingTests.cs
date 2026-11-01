using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Persistence;
using SapAV.Engine.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section C review H4, through the engine: every candidate and chain command is scanned; a target that can't be reached is
/// Unverified (or Suspicious, never silently Clean), recorded as a finding, reported over the pipe, and the phase is Incomplete.
/// </summary>
public sealed class UnverifiedFindingTests : IDisposable
{
    private const string MachineRun = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private readonly TempDir _temp = new();
    private readonly RecordingAlertSink _alerts = new();

    public void Dispose() => TempDir.DeleteTree(_temp.Path);

    private string Write(string name)
    {
        var path = Path.Combine(_temp.Path, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "plain");
        return path;
    }

    private PersistenceScanner Scanner(FakeScanBroker broker) =>
        new(broker, _alerts, TimeProvider.System, NullLogger.Instance, new PersistenceJudge(new PersistenceJudgeOptions { SystemRoot = @"C:\Windows" }),
            () => new AdminOnlyWritability());

    private static PersistenceCollection Collection(params PersistenceEntry[] entries) => new(entries, [], TimeSpan.Zero);

    private static PersistenceEntry Run(ResolvedCommand resolution, string value = "App") =>
        new(PersistenceKind.RunKey, null, MachineRun, value, "command", resolution, enabled: true);

    [Fact]
    public void DistinctFiles_IncludesEveryAdditionalTarget_ButNotMissingOnes()
    {
        var entry = Run(ResolvedCommand.Resolved(@"C:\Apps\a.exe").WithAdditional(
        [
            ResolvedCommand.Resolved(@"C:\Apps\b.exe"),
            ResolvedCommand.Resolved(@"C:\Apps\gone.exe", flags: [ResolutionFlag.TargetNotFound]),
            ResolvedCommand.Unresolved(TargetUnresolvedReason.InlineCommand),
        ]));

        Assert.Equal([@"C:\Apps\a.exe", @"C:\Apps\b.exe"], PersistenceScanner.DistinctFiles([entry]));
    }

    [Fact]
    public async Task ALaterCommandOfAChain_IsScanned_AndItsDetectionAlerted()
    {
        var benign = Write("benign.exe");
        var malware = Write("malware.exe"); // the fake broker judges by name
        var entry = Run(ResolvedCommand.Resolved(benign).WithAdditional([ResolvedCommand.Resolved(malware)]));
        var broker = new FakeScanBroker();

        var result = await Scanner(broker).ScanAsync(Collection(entry));

        Assert.Equal(2, broker.Calls);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(Verdict.Malicious, finding.Verdict);
        Assert.Single(_alerts.Snapshot());
    }

    [RequiresFact(Requires.Junctions)]
    public async Task ATargetBehindAJunction_IsUnverified_NeverClean()
    {
        var real = Directory.CreateDirectory(Path.Combine(_temp.Path, "real")).FullName;
        File.WriteAllText(Path.Combine(real, "app.exe"), "plain");
        var link = Directory.CreateDirectory(Path.Combine(_temp.Path, "link")).FullName;
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + real));
        try
        {
            var broker = new FakeScanBroker();

            var result = await Scanner(broker).ScanAsync(Collection(Run(ResolvedCommand.Resolved(Path.Combine(link, "app.exe")))));

            Assert.Equal(0, broker.Calls); // the hardened open refused it
            var finding = Assert.Single(result.Findings);
            Assert.True(finding.Judgement.IsUnverified); // and in a Temp folder it also reaches Suspicious
            Assert.NotEqual(PersistenceOutcome.Clean, finding.Outcome);
            Assert.Contains(finding.Judgement.Signals, s => s.Rule == PersistenceRuleIds.TargetUnreadable && s.Score > 0);
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [RequiresFact(Requires.Junctions)]
    public void TheRealProbe_TellsMissingFromUnknown()
    {
        var real = Directory.CreateDirectory(Path.Combine(_temp.Path, "real")).FullName;
        File.WriteAllText(Path.Combine(real, "app.exe"), "plain");
        var link = Directory.CreateDirectory(Path.Combine(_temp.Path, "link")).FullName;
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + real));
        try
        {
            var probe = new SafePathProbe();

            Assert.Equal(PathProbeResult.Exists, probe.Probe(Path.Combine(real, "app.exe")));
            Assert.Equal(PathProbeResult.Missing, probe.Probe(Path.Combine(real, "nope.exe")));
            Assert.Equal(PathProbeResult.Unknown, probe.Probe(Path.Combine(link, "app.exe")));
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public async Task ALockedTarget_IsUnverified()
    {
        var locked = Write("locked.exe");
        using var holder = new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var result = await Scanner(new FakeScanBroker()).ScanAsync(Collection(Run(ResolvedCommand.Resolved(locked))));

        Assert.Equal(PersistenceOutcome.Unverified, Assert.Single(result.Findings).Outcome);
    }

    [Fact]
    public async Task TheBudgetRunningOut_LeavesTargetsUnverified()
    {
        var file = Write("tool.exe");

        var result = await Scanner(new FakeScanBroker()).ScanAsync(Collection(Run(ResolvedCommand.Resolved(file))), new PersistenceScanOptions { TimeBudget = TimeSpan.Zero, Parallelism = 1 });

        Assert.Equal(PersistenceOutcome.Unverified, Assert.Single(result.Findings).Outcome);
    }

    [Fact]
    public async Task AQuickScan_RecordsUnverifiedFindings_WithNoVerdict_AndThePhaseIsIncomplete_AndThePipeSaysSo()
    {
        using var q = new QuickScanHarness();
        q.Entries.Add(new PersistenceEntry(PersistenceKind.RunKey, null, MachineRun, "Nested", "cmd /c ...",
            ResolvedCommand.Unresolved(TargetUnresolvedReason.NestingTooDeep), enabled: true));

        var job = await q.RunAsync();

        var phase = job.Phases.Single(p => p.Name == "Autostart entries");
        Assert.Equal(ScanPhaseState.Incomplete, phase.State);
        Assert.Contains(phase.Notes, n => n.Contains("could not be scanned", StringComparison.Ordinal));
        var finding = Assert.Single(job.Findings);
        Assert.Null(finding.Verdict); // never "Clean"
        Assert.DoesNotContain(q.Alerts.Snapshot(), a => a.Autostart is not null);

        var admin = PipeMapping.Finding(0, finding, forAdmin: true);
        Assert.Null(admin.Verdict);
        Assert.Equal(PersistenceOutcome.Unverified, admin.Persistence!.Outcome);
        Assert.Contains("NestingTooDeep", Assert.Single(admin.Persistence.UnverifiedReasons));
        var user = PipeMapping.Finding(0, finding, forAdmin: false);
        Assert.Equal(PersistenceOutcome.Unverified, user.Persistence!.Outcome);
        Assert.Empty(user.Persistence.UnverifiedReasons);
    }

    [Fact]
    public void AMismatchedShortcut_IsResolvedToEveryCandidate()
    {
        using var root = new RegistryTestRoot();
        using var folder = new TempDir();
        File.WriteAllBytes(Path.Combine(folder.Path, "mixed.lnk"), new ShellLinkBuilder
        {
            IdListPath = @"C:\Windows\System32\notepad.exe",
            LocalBasePath = @"C:\Users\u\evil.exe",
            Arguments = "/x",
        }.Build());

        var entry = root.Collect(new SetProbe(), new StartupFolderSource([(folder.Path, null)])).Single("mixed.lnk");

        Assert.Equal(@"C:\Windows\System32\notepad.exe", entry.Resolution.TargetPath);
        Assert.Contains(ResolutionFlag.ShortcutTargetMismatch, entry.Resolution.Flags);
        Assert.Equal(@"C:\Users\u\evil.exe", Assert.Single(entry.Resolution.Additional).TargetPath);
    }

    [Fact]
    public void ATaskWorkingDirectory_ReachesTheResolver()
    {
        using var root = new RegistryTestRoot();
        using var tasks = new TempDir();
        File.WriteAllText(Path.Combine(tasks.Path, "Rel"), """
            <Task><Actions><Exec><Command>evil.exe</Command><WorkingDirectory>C:\Users\u</WorkingDirectory></Exec></Actions></Task>
            """);

        var entry = root.Collect(new SetProbe(@"C:\Users\u\evil.exe"), new ScheduledTaskSource(tasks.Path)).Single("Exec[0]");

        Assert.Equal(@"C:\Users\u\evil.exe", entry.Resolution.TargetPath);
        Assert.Contains(ResolutionFlag.ResolvedFromWorkingDirectory, entry.Resolution.Flags);
    }
}
