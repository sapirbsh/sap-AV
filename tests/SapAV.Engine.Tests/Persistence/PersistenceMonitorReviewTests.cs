using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SapAV.Core.Alerts;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Monitoring;
using SapAV.Engine.RealTime;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// D4 immediate review (H1–H5, M4, M5): ways a user's autostart could go unjudged. Fake HKLM / HKU under
/// <c>HKCU\Software\sap-AV-tests\…</c>, temp folders, fake watches and a manual clock.
/// </summary>
public sealed class PersistenceMonitorReviewTests
{
    private const string Alice = MonitorHarness.Alice;

    [Fact]
    public void H1_ATargetThatCouldntBeScanned_IsRetriedWithBackoff_NotMarkedJudged()
    {
        using var h = new MonitorHarness(o => o.CoverageWarnAfter = 2);
        int failures = 2;
        h.Broker.OnScan = (_, _, _) => Interlocked.Decrement(ref failures) >= 0 ? throw new IOException("the scan failed") : Task.FromResult<FileScanReport?>(null);
        h.MachineRunValue("Late", h.Target("mal-late.exe"));

        h.Baseline();
        Assert.Empty(h.PersistenceAlerts("Late"));
        Assert.Equal((1, 1L), (h.Monitor.Status.Unjudged, h.Monitor.Status.Retries));

        Assert.Equal(0, h.Advance(TimeSpan.FromSeconds(10))); // not before the 30 s backoff
        h.Advance(TimeSpan.FromSeconds(21));
        Assert.Contains(h.Log.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("still can't be verified after 2 attempts", StringComparison.Ordinal));
        Assert.Empty(h.PersistenceAlerts("Late"));

        h.Advance(TimeSpan.FromSeconds(61)); // the doubled backoff; now the scan works
        Assert.Single(h.PersistenceAlerts("Late"));
        Assert.Equal(0, h.Monitor.Status.Unjudged);
    }

    [Fact]
    public void H2_ATargetOverwrittenAfterItWasJudgedClean_IsJudgedAgain_AtTheNextCollection()
    {
        using var h = new MonitorHarness();
        h.Broker.OnScan = (item, file, _) => Task.FromResult<FileScanReport?>(ByContent(item, file, h.Time));
        string updater = h.Target("upd.exe");
        File.WriteAllText(updater, "benign updater");
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.UserRunValue(Alice, "Updater", updater);
        h.Baseline();
        Assert.Empty(h.PersistenceAlerts("Updater"));

        File.WriteAllText(updater, "evil payload, same name, same command line");
        h.Time.Now += h.Options.SafetyRescanInterval; // nothing watches %APPDATA%: the safety rescan (or any re-collection) notices
        h.Monitor.Tick();
        h.Monitor.RunDue();

        var alert = Assert.Single(h.PersistenceAlerts("Updater"));
        Assert.Equal(AlertType.MaliciousPersistence, alert.Type);
        Assert.Equal(1, h.Monitor.Status.Changed);
    }

    [Fact]
    public void H3_AUserKeyDeniedToTheEngine_IsAHiddenLocationAlert_OnceUntilItIsReadableAgain()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.UserRunValue(Alice, "Hidden", h.Target("mal-hidden.exe"));
        string runPath = $@"{Alice}\{MonitorHarness.UserRun}";
        using var run = h.Registry.Users(runPath);
        var me = WindowsIdentity.GetCurrent().User!;
        var deny = new RegistryAccessRule(me, RegistryRights.QueryValues | RegistryRights.EnumerateSubKeys | RegistryRights.Notify, AccessControlType.Deny);
        var security = run.GetAccessControl();
        security.AddAccessRule(deny);
        run.SetAccessControl(security);
        try
        {
            // The real watch tells denied apart from missing.
            using (var watch = new WindowsRegistryWatchFactory(h.Registry.MachineKey, h.Registry.UsersKey).Watch(RegistryRoot.Users, runPath, false, () => { }))
            {
                Assert.True(watch.Denied);
                Assert.True(watch.Active); // an ancestor stands in
            }

            h.Baseline();
            h.MarkAndRun(new PersistenceScope("registry autoruns", Alice));

            var alert = Assert.Single(h.Alerts.Alerts, a => a.Reasons.Any(r => r.Contains("hidden from SYSTEM", StringComparison.Ordinal)));
            Assert.Equal((AlertType.SuspiciousPersistence, MitreTechniqueIds.HideArtifacts), (alert.Type, alert.TechniqueId));
            Assert.Equal(Alice, alert.Autostart!.UserSid);
            Assert.Equal($"engine:Persistence:{Alice}", h.Alerts.Posts.Single(p => p.Alert == alert).Budget!.Key);
            Assert.Contains(h.Log.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("AccessDenied at", StringComparison.Ordinal));
            Assert.Equal(1, h.Monitor.Status.HiddenLocations);
        }
        finally
        {
            security.RemoveAccessRule(deny);
            run.SetAccessControl(security);
        }

        h.MarkAndRun(new PersistenceScope("registry autoruns", Alice));
        Assert.Equal(0, h.Monitor.Status.HiddenLocations); // readable again: a new denial alerts anew
        Assert.Single(h.PersistenceAlerts("Hidden")); // and the entry it hid is judged now
    }

    [Fact]
    public void H4_KeysRewrittenOverAndOver_CantStarveAnOlderEntry_AndAreRateLimited()
    {
        using var h = new MonitorHarness(o => o.MaxJudgedPerPass = 10);
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.Baseline();
        string junk = h.Target("junk.exe");
        void Rewrite(int round)
        {
            for (int i = 0; i < 15; i++)
            {
                h.UserRunValue(Alice, $"Junk{i:D2}", $"{junk} /round {round}");
            }
        }

        Rewrite(0);
        h.FakeRegistry.Fire(RegistryRoot.Users, $@"{Alice}\{MonitorHarness.UserRun}");
        h.Advance(TimeSpan.FromSeconds(11)); // 10 of the 15 junk values judged
        h.UserRunValue(Alice, "Payload", h.Target("mal-payload.exe"));

        for (int round = 1; round <= 5 && !h.PersistenceAlerts("Payload").Any(); round++)
        {
            Rewrite(round);
            h.FakeRegistry.Fire(RegistryRoot.Users, $@"{Alice}\{MonitorHarness.UserRun}");
            h.Advance(TimeSpan.FromSeconds(11));
        }

        Assert.Single(h.PersistenceAlerts("Payload")); // first in, first out: its turn came after the 5 older junk values
        Assert.InRange(h.Scanner.Judged.Count(v => v == "Junk00"), 1, 2); // rewritten every pass, judged at most once a minute
    }

    [Fact]
    public void H5_UntrustedTaskFiles_AreParsedAfterTheSystemsOwn_AndCapped_TaskCacheListedOnesCountAsTheSystems()
    {
        using var h = new MonitorHarness(limits: new PersistenceLimits { MaxUntrustedTaskFiles = 5 }, trustedTask: (_, path) => !path.Contains("junk", StringComparison.Ordinal));
        for (int i = 0; i < 20; i++)
        {
            WriteTask(h.Tasks, $"junk{i:D2}", $@"C:\Junk\j{i}.exe");
        }

        WriteTask(h.Tasks, "Real", @"C:\Tools\real.exe");
        h.Registry.Machine(ScheduledTaskSource.TaskCacheTree + @"\junk17").Dispose(); // registered with the Task Scheduler

        var result = h.Collector.Inner.Collect();

        var tasks = result.Entries.Where(e => e.Kind == PersistenceKind.ScheduledTask).Select(e => e.Location).ToArray();
        Assert.Equal(7, tasks.Length); // Real + junk17 (TaskCache) + 5 untrusted under the cap
        Assert.Equal([@"\Real", @"\junk17"], tasks.Take(2).Order(StringComparer.Ordinal)); // the system's own first
        Assert.Contains(result.Issues, i => i.Reason == PersistenceIssueReason.LimitReached && i.Message.Contains("over the cap of 5", StringComparison.Ordinal));
        Assert.Equal(7, h.Parser.Files); // the 14 over the cap never reach the worker
    }

    [Fact]
    public void H5_ATasksPass_OpensOnlyTheFilesTheWatchReported_AtNormalPriority_AndAnOverflowMakesItAFullPass()
    {
        using var h = new MonitorHarness();
        WriteTask(h.Tasks, "Task1", @"C:\Tools\one.exe");
        WriteTask(h.Tasks, "Task2", @"C:\Tools\two.exe");
        h.Baseline();
        var first = h.Collector.Options[h.Collector.Calls.FindIndex(c => c.Contains(PersistenceMonitor.TasksScope))];
        Assert.Null(first!.ChangedTaskFiles); // the first pass checks every file
        Assert.Equal(ScanPriority.Normal, first.ParsePriority);

        WriteTask(h.Tasks, "Task1", @"C:\Tools\one-changed.exe");
        WriteTask(h.Tasks, "Task2", @"C:\Tools\two-changed.exe"); // changed without an event (as if the notification were lost)
        h.Folders.Raise(h.Tasks, new FileChange(FileChangeKind.Modified, "Task1"));
        h.Advance(TimeSpan.FromSeconds(11));

        var hinted = h.Collector.Options[^1]!;
        Assert.Equal([@"\Task1"], hinted.ChangedTaskFiles!);
        Assert.Contains(h.Scanner.Calls.SelectMany(c => c.Entries), e => e.CommandLine.Contains("one-changed", StringComparison.Ordinal));
        Assert.DoesNotContain(h.Scanner.Calls.SelectMany(c => c.Entries), e => e.CommandLine.Contains("two-changed", StringComparison.Ordinal));
        Assert.All(h.Scanner.Calls.Where(c => c.Entries.Any(e => e.Kind == PersistenceKind.ScheduledTask)), c => Assert.Equal(ScanPriority.Normal, c.Options.Priority));

        h.Folders.Overflow(h.Tasks);
        h.Advance(TimeSpan.FromSeconds(11));
        Assert.Null(h.Collector.Options[^1]!.ChangedTaskFiles);
        Assert.Contains(h.Scanner.Calls.SelectMany(c => c.Entries), e => e.CommandLine.Contains("two-changed", StringComparison.Ordinal));
    }

    [Fact]
    public void H5_ATasksScopeCutShortPassAfterPass_RaisesAWarning()
    {
        using var h = new MonitorHarness(limits: new PersistenceLimits { MaxUntrustedTaskFiles = 1 }, trustedTask: (_, _) => false);
        WriteTask(h.Tasks, "a", @"C:\a.exe");
        WriteTask(h.Tasks, "b", @"C:\b.exe");
        h.Baseline();

        for (int i = 0; i < 2; i++)
        {
            h.MarkAndRun(PersistenceMonitor.TasksScope);
        }

        Assert.Single(h.Log.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("was cut short 3 passes in a row", StringComparison.Ordinal));
    }

    [Fact]
    public void M4_ARegistryWatchThatDied_IsRecreated_AndItsScopeCollected()
    {
        using var h = new MonitorHarness();
        h.Baseline();
        string run = MonitorHarness.MachineRun;
        var dead = Assert.Single(h.FakeRegistry.Live, w => w.Root == RegistryRoot.LocalMachine && w.Path == run);
        h.MachineRunValue("WhileDead", h.Target("mal-dead.exe"));

        dead.Die();
        h.Time.Now += TimeSpan.FromSeconds(11);
        h.Monitor.Tick();
        h.Monitor.RunDue();

        Assert.True(dead.Disposed);
        Assert.Single(h.FakeRegistry.Live, w => w.Root == RegistryRoot.LocalMachine && w.Path == run);
        Assert.Single(h.PersistenceAlerts("WhileDead"));
    }

    [Fact]
    public void M5_AUserPrincipalTask_CountsAgainstThatUsersBudget_NotTheEngines()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        WriteTask(h.Tasks, "UserTask", h.Target("mal-task.exe"), userId: Alice);
        WriteTask(h.Tasks, "SystemTask", h.Target("mal-system.exe"));

        h.Baseline();

        var posts = h.Alerts.Posts;
        Assert.Equal($"engine:Persistence:{Alice}", posts.Single(p => p.Alert.Autostart!.Location == @"\UserTask").Budget!.Key);
        Assert.Equal("engine:Persistence", posts.Single(p => p.Alert.Autostart!.Location == @"\SystemTask").Budget!.Key);
    }

    /// <summary>Malicious when the file's content says "evil" (H2: same name, new content).</summary>
    private static FileScanReport ByContent(ScanItem item, OpenedScanFile file, TimeProvider time)
    {
        var report = FakeScanBroker.Judge(item, file, time);
        var buffer = new byte[256];
        int read = RandomAccess.Read(file.Handle, buffer, 0);
        if (!System.Text.Encoding.UTF8.GetString(buffer, 0, read).Contains("evil", StringComparison.Ordinal))
        {
            return report;
        }

        var detection = new Detection(Verdict.Malicious, "YARA synthetic test rule", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara);
        return report with { Result = new ScanResult(item, [detection], report.Result.Timestamp, report.Result.Sha256) };
    }

    private static void WriteTask(string folder, string name, string command, string userId = "S-1-5-18") =>
        File.WriteAllText(Path.Combine(folder, name), $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Principals><Principal id="Author"><UserId>{userId}</UserId></Principal></Principals>
              <Settings><Enabled>true</Enabled></Settings>
              <Actions Context="Author"><Exec><Command>"{command}"</Command></Exec></Actions>
            </Task>
            """, System.Text.Encoding.Unicode);
}
