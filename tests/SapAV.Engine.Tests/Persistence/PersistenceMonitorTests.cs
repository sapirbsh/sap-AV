using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SapAV.Core.Alerts;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Monitoring;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// D4: real-time persistence monitoring. Fake HKLM / HKU under <c>HKCU\Software\sap-AV-tests\…</c>, temp Startup and Tasks
/// folders, fake watches and a manual clock (no sleeps); one end-to-end test with the real registry notification.
/// </summary>
public sealed class PersistenceMonitorTests
{
    private const string Alice = MonitorHarness.Alice;
    private const string Bob = MonitorHarness.Bob;

    [Fact]
    public void DoneWhen_ANewHkcuRunValueInATestKey_TriggersAnAlert()
    {
        // The real RegNotifyChangeKeyValue on the test key and the monitor's own thread, with short real delays.
        using var h = new MonitorHarness(o =>
        {
            o.SettleDelay = TimeSpan.FromMilliseconds(50);
            o.MaxSettleDelay = TimeSpan.FromMilliseconds(200);
            o.MinInterval = TimeSpan.Zero;
        }, realRegistryWatches: true);
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.UserRunValue(Alice, "Existing", h.Target("tool.exe"));
        var monitor = new PersistenceMonitor(h.Options, h.Collector, h.Scanner, h.Store, h.RegistryWatches, h.Folders, TimeProvider.System, h.Log);
        using var baselined = new ManualResetEventSlim();
        using var judged = new ManualResetEventSlim();
        monitor.Judged += findings =>
        {
            if (findings.Any(f => f.Entry.ValueName == "Existing"))
            {
                baselined.Set();
            }

            if (findings.Any(f => f.Entry.ValueName == "Updater"))
            {
                judged.Set();
            }
        };

        try
        {
            monitor.Start();
            Assert.True(baselined.Wait(TimeSpan.FromSeconds(30)), "the initial baseline didn't judge the existing value");
            h.UserRunValue(Alice, "Updater", h.Target("mal-updater.exe"));

            var alert = h.Alerts.WaitFor(a => a.Autostart?.ValueName == "Updater", TimeSpan.FromSeconds(30));
            Assert.NotNull(alert);
            Assert.Equal((AlertType.MaliciousPersistence, ScanTrigger.Persistence, AlertAction.None), (alert.Type, alert.Trigger, alert.Action));
            Assert.Equal($@"HKU\{Alice}\{MonitorHarness.UserRun}", alert.Autostart!.Location);
            Assert.NotNull(alert.TechniqueId);
            Assert.Contains(MitreTechniqueIds.RegistryRunKeysStartupFolder, alert.SecondaryTechniqueIds.Prepend(alert.TechniqueId));
            Assert.True(judged.Wait(TimeSpan.FromSeconds(30)));
            Assert.Empty(h.PersistenceAlerts("Existing"));
        }
        finally
        {
            monitor.Dispose();
        }
    }

    [Fact]
    public void FirstStart_JudgesExistingEntriesQuietly_OnlyTheMaliciousOneAlerts_AndARestartJudgesNothing()
    {
        using var h = new MonitorHarness();
        for (int i = 0; i < 5; i++)
        {
            h.MachineRunValue($"Vendor{i}", h.Target($"vendor{i}.exe"));
        }

        h.MachineRunValue("Dropper", h.Target("mal-dropper.exe"));
        h.Baseline();

        Assert.Single(h.Alerts.Alerts);
        Assert.Single(h.PersistenceAlerts("Dropper"));
        Assert.Equal((6, 0), (h.Monitor.Status.Entries, h.Monitor.Status.Unjudged));
        Assert.Equal((0, 0), (h.Monitor.Status.New, h.Monitor.Status.Changed)); // existing entries aren't "new"
        Assert.DoesNotContain(h.Log.Lines, l => l.Message.Contains("new autostart entry", StringComparison.Ordinal));
        h.Monitor.Dispose();

        // An engine restart: a new monitor on the same (saved) baseline.
        h.Scanner.Calls.Clear();
        using var restart = h.Create();
        restart.Initialize();
        restart.RunDue();

        Assert.Single(h.Alerts.Alerts);
        Assert.Empty(h.Scanner.Calls);
        Assert.Equal(BaselineLoadStatus.Loaded, restart.Status.Baseline);
    }

    [Fact]
    public void AChangedValue_IsJudgedAndAlerted_AndTheUnchangedOnesAreNot()
    {
        using var h = new MonitorHarness();
        h.MachineRunValue("Steady", h.Target("steady.exe"));
        h.MachineRunValue("Helper", h.Target("helper.exe"));
        h.Baseline();
        h.Scanner.Calls.Clear();

        h.MachineRunValue("Helper", h.Target("mal-helper.exe"));
        Assert.True(h.FakeRegistry.Fire(RegistryRoot.LocalMachine, MonitorHarness.MachineRun));
        h.Advance(TimeSpan.FromSeconds(11));

        Assert.Equal(["Helper"], h.Scanner.Judged);
        Assert.Single(h.PersistenceAlerts("Helper"));
        Assert.Equal(1, h.Monitor.Status.Changed);
        Assert.Contains(h.Log.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("changed autostart entry", StringComparison.Ordinal));
    }

    [Fact]
    public void ARemovedEntry_IsLoggedAtInformation_AndLeavesTheBaseline_WithoutAnAlert()
    {
        using var h = new MonitorHarness();
        h.MachineRunValue("Old", h.Target("old.exe"));
        h.Baseline();

        h.Registry.Machine(MonitorHarness.MachineRun).DeleteValue("Old");
        h.FakeRegistry.Fire(RegistryRoot.LocalMachine, MonitorHarness.MachineRun);
        h.Advance(TimeSpan.FromSeconds(11));

        Assert.Contains(h.Log.Lines, l => l.Level == LogLevel.Information && l.Message.Contains(@"autostart entry removed: HKLM\" + MonitorHarness.MachineRun + @"\Old", StringComparison.Ordinal));
        Assert.Equal((1, 0), (h.Monitor.Status.Removed, h.Monitor.Status.Entries));
        Assert.Empty(h.Alerts.Alerts);
    }

    [Fact]
    public void Debounce_ABurstOfChangesIsOneCollection_OfOnlyTheTouchedScope_AfterTheQuietTime()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.Baseline();
        h.Collector.Calls.Clear();

        for (int i = 0; i < 5; i++)
        {
            h.UserRunValue(Alice, $"Burst{i}", h.Target($"burst{i}.exe"));
            Assert.True(h.FakeRegistry.Fire(RegistryRoot.Users, $@"{Alice}\{MonitorHarness.UserRun}"));
            h.Time.Now += TimeSpan.FromMilliseconds(500);
            Assert.Equal(0, h.Monitor.RunDue()); // still settling
        }

        h.Advance(TimeSpan.FromSeconds(15)); // past the settle delay and the scope's interval since the baseline

        var call = Assert.Single(h.Collector.Calls);
        Assert.Equal([new PersistenceScope("registry autoruns", Alice)], call);
        Assert.Equal(5, h.Monitor.Status.New);
    }

    [Fact]
    public void AScopeThatKeepsChanging_IsCollectedAtMostOncePerInterval_ButNoLaterThanTheMaximumSettle()
    {
        using var h = new MonitorHarness(o => o.MinInterval = TimeSpan.FromSeconds(30));
        h.Baseline();
        h.Collector.Calls.Clear();
        var start = h.Time.Now;

        // A change every second for a minute: never quiet for the 2 s settle delay.
        for (int second = 1; second <= 60; second++)
        {
            h.Time.Now = start + TimeSpan.FromSeconds(second);
            h.FakeRegistry.Fire(RegistryRoot.LocalMachine, MonitorHarness.MachineRun);
            h.Monitor.RunDue();
        }

        // Not before the 30 s interval since the baseline pass, then at most once per interval.
        Assert.InRange(h.Collector.Calls.Count, 1, 2);
    }

    [Fact]
    public void AStormInOneUsersHive_IsCappedPerPass_AndAnotherUsersChangeIsServedFirst()
    {
        using var h = new MonitorHarness(o => o.MaxJudgedPerPass = 10);
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.Registry.AddUser(Bob, Path.Combine(h.Base, "bob"), loaded: true);
        h.Baseline();
        h.Scanner.Calls.Clear();

        string target = h.Target("flood.exe");
        for (int i = 0; i < 35; i++)
        {
            h.UserRunValue(Alice, $"Flood{i:D2}", target);
        }

        h.FakeRegistry.Fire(RegistryRoot.Users, $@"{Alice}\{MonitorHarness.UserRun}");
        h.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal(10, h.Scanner.Judged.Count()); // capped

        h.UserRunValue(Bob, "BobsMalware", h.Target("mal-bob.exe"));
        h.FakeRegistry.Fire(RegistryRoot.Users, $@"{Bob}\{MonitorHarness.UserRun}");
        h.Advance(TimeSpan.FromSeconds(11));

        Assert.Single(h.PersistenceAlerts("BobsMalware")); // Bob's turn came between Alice's passes
        int bobsCall = h.Scanner.Calls.FindIndex(c => c.Entries.Any(e => e.ValueName == "BobsMalware"));
        Assert.Equal(1, bobsCall);

        for (int i = 0; i < 5 && h.Monitor.Status.Unjudged > 0; i++)
        {
            h.Advance(TimeSpan.FromSeconds(2));
        }

        Assert.Equal(36, h.Scanner.Judged.Count());
        Assert.All(h.Scanner.Calls, c => Assert.True(c.Entries.Length <= 10));
        Assert.Equal(0, h.Monitor.Status.Unjudged);
    }

    [Fact]
    public void EachUsersAlertsAndTargetScans_CountAgainstThatUsersOwnBudget_MachineEntriesAgainstTheEngines()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.UserRunValue(Alice, "AliceBad", h.Target("mal-a.exe"));
        h.MachineRunValue("MachineBad", h.Target("mal-m.exe"));

        h.Baseline();

        var posts = h.Alerts.Posts;
        Assert.Equal($"engine:Persistence:{Alice}", posts.Single(p => p.Alert.Autostart!.ValueName == "AliceBad").Budget!.Key);
        Assert.Equal("engine:Persistence", posts.Single(p => p.Alert.Autostart!.ValueName == "MachineBad").Budget!.Key);
        Assert.Contains(h.Scanner.Calls, c => c.Options.TargetBudget!.Owner == Alice && c.Options.Priority == SapAV.Engine.Sandbox.ScanPriority.Normal);
        Assert.Contains(h.Scanner.Calls, c => c.Options.TargetBudget!.Owner is null && c.Options.Priority == SapAV.Engine.Sandbox.ScanPriority.High);
    }

    [Fact]
    public void AHiveLoadedLater_GetsItsWatchesAndAQuietFirstCollection_AndAnUnloadReleasesThemButKeepsItsBaseline()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: false); // a profile that isn't logged on
        h.Baseline();
        Assert.DoesNotContain(h.FakeRegistry.Live, w => w.Path.StartsWith(Alice, StringComparison.Ordinal));

        // Logon: the hive appears under HKU.
        string tray = h.Target("tray.exe"), bad = h.Target("mal-tray.exe");
        h.UserRunValue(Alice, "Tray", tray);
        h.UserRunValue(Alice, "Bad", bad);
        h.Time.Now += h.Options.HiveCheckInterval;
        h.Monitor.Tick();
        h.Monitor.RunDue();

        Assert.Contains(h.FakeRegistry.Live, w => w.Path == $@"{Alice}\{MonitorHarness.UserRun}");
        Assert.Single(h.PersistenceAlerts("Bad"));
        Assert.Empty(h.PersistenceAlerts("Tray"));
        Assert.Equal(0, h.Monitor.Status.New); // a hive seen for the first time is baselined, not "all new"

        // Logoff: the hive goes away; its key watches are released, and its entries aren't "removed".
        var aliceWatches = h.FakeRegistry.Live.Where(w => w.Path.StartsWith(Alice, StringComparison.Ordinal)).ToArray();
        h.Registry.UnloadUser(Alice);
        h.Time.Now += h.Options.HiveCheckInterval;
        h.Monitor.Tick();
        h.Monitor.MarkDirty(new PersistenceScope("registry autoruns", Alice), immediate: true);
        h.Monitor.RunDue();

        Assert.All(aliceWatches, w => Assert.True(w.Disposed));
        Assert.Equal(0, h.Monitor.Status.Removed);
        Assert.NotNull(h.Monitor.Baseline.Find(new PersistenceEntry(PersistenceKind.RunKey, Alice, $@"HKU\{Alice}\{MonitorHarness.UserRun}", "Tray", "x",
            ResolvedCommand.Unresolved(TargetUnresolvedReason.EmptyCommand), true).Key));

        // Logon again with nothing changed (same values, same target files): no new judgement, no alert.
        h.UserRunValue(Alice, "Tray", tray);
        h.UserRunValue(Alice, "Bad", bad);
        int alerts = h.Alerts.Alerts.Count();
        h.Scanner.Calls.Clear();
        h.Time.Now += h.Options.HiveCheckInterval;
        h.Monitor.Tick();
        h.Monitor.RunDue();
        Assert.Equal(alerts, h.Alerts.Alerts.Count());
        Assert.Empty(h.Scanner.Calls);
    }

    [Fact]
    public void ANewStartupFolderItem_FromTheFolderWatch_IsJudgedAndAlerted()
    {
        using var h = new MonitorHarness();
        h.Baseline();
        Assert.True(h.Folders.IsWatching(h.Startup));

        File.WriteAllText(Path.Combine(h.Startup, "mal-startup.exe"), "synthetic");
        h.Folders.Added(h.Startup, "mal-startup.exe");
        h.Advance(TimeSpan.FromSeconds(11));

        var alert = Assert.Single(h.PersistenceAlerts("mal-startup.exe"));
        Assert.Equal(AlertType.MaliciousPersistence, alert.Type);
        Assert.Equal([new PersistenceScope("startup folders", null)], h.Collector.Calls[^1]);
    }

    [Fact]
    public void AStartupFolderThatIsAJunction_IsNotWatched_AndSaysWhy()
    {
        using var temp = new TempDir();
        string real = Directory.CreateDirectory(Path.Combine(temp.Path, "real")).FullName;
        string link = Path.Combine(temp.Path, "Startup");
        Assert.Null(Core.Tests.TestSupport.RawJunction.TryCreate(link, @"\??\" + real));
        try
        {
            using var h = new MonitorHarness();
            var collector = new PersistenceCollector(h.Registry.View, new SafePathProbe(), [new StartupFolderSource([(link, null)])]);
            using var monitor = new PersistenceMonitor(h.Options, collector, h.Scanner, h.Store, h.FakeRegistry, h.Folders, h.Time, h.Log);

            monitor.Initialize();

            Assert.False(h.Folders.IsWatching(link));
            Assert.Contains(monitor.Problems.Values, p => p.Contains("junction or symbolic link", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [RequiresFact(Requires.UsnJournal)]
    public void TaskFiles_OnlyChangedOnesAreParsedAgain()
    {
        using var h = new MonitorHarness();
        for (int i = 0; i < 6; i++)
        {
            WriteTask(h.Tasks, $"Task{i}", $@"C:\Tools\app{i}.exe");
        }

        var collector = h.Collector.Inner;
        var first = collector.Collect().SourceTimings.Single(t => t.Source == "scheduled tasks");
        var unchanged = collector.Collect().SourceTimings.Single(t => t.Source == "scheduled tasks");
        WriteTask(h.Tasks, "Task3", @"C:\Tools\changed.exe");
        File.Move(Path.Combine(h.Tasks, "Task5"), Path.Combine(h.Tasks, "Task5b"));
        var afterChange = collector.Collect();
        var changed = afterChange.SourceTimings.Single(t => t.Source == "scheduled tasks");

        Assert.Equal((6, 0), (first.ParsedFiles, first.ReusedFiles));
        Assert.Equal((0, 6), (unchanged.ParsedFiles, unchanged.ReusedFiles));
        Assert.Equal((2, 4), (changed.ParsedFiles, changed.ReusedFiles)); // the rewritten file and the renamed one
        Assert.Equal(8, h.Parser.Files); // 6 + 0 + 2 worker parses in all
        Assert.Contains(afterChange.Entries, e => e.Location == @"\Task3" && e.Resolution.TargetPath == @"C:\Tools\changed.exe");
    }

    [Fact]
    public void FileBaselineStore_RoundTrips_AndRefusesATamperedFileOrAnotherKey()
    {
        using var temp = new TempDir();
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var store = new FileBaselineStore(temp.Path, key);
        var record = new BaselineRecord("RunKey|machine|HKLM\\X|A", new PersistenceScope("registry autoruns", null), new string('a', 64), @"HKLM\X\A", true, BaselineChange.New);
        var snapshot = new BaselineSnapshot([record, record with { Key = "k2", Scope = new PersistenceScope("startup folders", Alice), Judged = false }],
            [new PersistenceScope("registry autoruns", null)]);

        Assert.Equal(BaselineLoadStatus.Missing, store.Load().Status);
        store.Save(snapshot);
        var loaded = store.Load();
        Assert.Equal(BaselineLoadStatus.Loaded, loaded.Status);
        Assert.Equal(snapshot.Records, loaded.Snapshot!.Records);
        Assert.Equal(snapshot.Baselined, loaded.Snapshot.Baselined);

        Assert.Equal(BaselineLoadStatus.Tampered, new FileBaselineStore(temp.Path, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).Load().Status);
        var bytes = File.ReadAllBytes(store.FilePath);
        int at = Array.IndexOf(bytes, (byte)'J', 65); // "Judged" in the body: one flipped byte
        bytes[at + 1] ^= 0x01;
        File.WriteAllBytes(store.FilePath, bytes);
        var tampered = store.Load();
        Assert.Equal(BaselineLoadStatus.Tampered, tampered.Status);
        Assert.Contains("MAC", tampered.Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void ATamperedBaseline_IsTakenAgain_SoAnExistingMaliciousEntryAlertsOnceMore()
    {
        using var temp = new TempDir();
        var store = new FileBaselineStore(temp.Path, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        using var h = new MonitorHarness(store: store);
        h.MachineRunValue("Dropper", h.Target("mal-dropper.exe"));
        h.MachineRunValue("Vendor", h.Target("vendor.exe"));
        h.Baseline();
        h.Monitor.Dispose();
        Assert.Single(h.PersistenceAlerts("Dropper"));

        // An untampered restart judges nothing.
        using (var restart = h.Create())
        {
            restart.Initialize();
            restart.RunDue();
            Assert.Single(h.PersistenceAlerts("Dropper"));
        }

        var bytes = File.ReadAllBytes(store.FilePath);
        bytes[^2] ^= 0x20;
        File.WriteAllBytes(store.FilePath, bytes);

        using var again = h.Create();
        again.Initialize();
        again.RunDue();

        Assert.Equal(BaselineLoadStatus.Tampered, again.Status.Baseline);
        Assert.Equal(2, h.PersistenceAlerts("Dropper").Count()); // judged once more, never hidden
        Assert.Empty(h.PersistenceAlerts("Vendor"));
        Assert.Contains(h.Log.Lines, l => l.Level == LogLevel.Warning && l.Message.Contains("baseline was refused", StringComparison.Ordinal));
        Assert.Equal(BaselineLoadStatus.Loaded, store.Load().Status); // saved again, valid
    }

    [Fact]
    public void Shutdown_StopsTheThread_ReleasesEveryWatch_AndLaterNotificationsDoNothing()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        var monitor = new PersistenceMonitor(h.Options, h.Collector, h.Scanner, h.Store, h.FakeRegistry, h.Folders, h.Time, h.Log);
        using var ready = new ManualResetEventSlim();
        monitor.Judged += _ => ready.Set();
        h.MachineRunValue("App", h.Target("app.exe"));
        monitor.Start();
        Assert.True(ready.Wait(TimeSpan.FromSeconds(30)));

        var watches = h.FakeRegistry.All;
        monitor.Dispose();
        monitor.Dispose();

        Assert.NotEmpty(watches);
        Assert.All(watches, w => Assert.True(w.Disposed));
        Assert.False(h.Folders.IsWatching(h.Startup));
        watches[0].Changed(); // a late notification after shutdown
        Assert.Equal(0, monitor.RunDue());
        Assert.Equal(0, h.Monitor.Status.Failures);
    }

    [Fact]
    public void ScopedCollection_CollectsOnlyTheAskedScopes_AndAnUnloadedHiveIsNotComplete()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.Registry.AddUser(Bob, Path.Combine(h.Base, "bob"), loaded: false);
        h.MachineRunValue("M", h.Target("m.exe"));
        h.UserRunValue(Alice, "A", h.Target("a.exe"));

        var result = h.Collector.Inner.CollectScoped([new("registry autoruns", Alice), new("registry autoruns", Bob)]);

        Assert.Equal(["A"], result.Collection.Entries.Select(e => e.ValueName));
        Assert.Equal([new PersistenceScope("registry autoruns", Alice)], result.EntryScopes);
        Assert.True(result.Outcomes[new("registry autoruns", Alice)].IsComplete);
        Assert.False(result.Outcomes[new("registry autoruns", Bob)].IsComplete); // HiveNotLoaded: nothing may look removed
        Assert.DoesNotContain(new PersistenceScope("registry autoruns", null), result.Outcomes.Keys);
    }

    [Fact]
    public void Plan_WatchesTheCollectorKeysInHklmAndEachLoadedHive_AndTheFolders()
    {
        using var h = new MonitorHarness();
        h.Registry.AddUser(Alice, Path.Combine(h.Base, "alice"), loaded: true);
        h.Registry.AddUser(Bob, Path.Combine(h.Base, "bob"), loaded: false);

        var plan = h.Collector.Plan();
        var keys = plan.Watches.Where(w => w.Target.Kind == PersistenceWatchKind.RegistryKey).Select(w => w.Target.ToString()).ToHashSet();

        Assert.Contains(@"HKLM\" + MonitorHarness.MachineRun, keys);
        Assert.Contains(@"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", keys);
        Assert.Contains(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", keys);
        Assert.Contains(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", keys);
        Assert.Contains($@"HKU\{Alice}\{MonitorHarness.UserRun}", keys);
        Assert.Contains($@"HKU\{Alice}\Software\Microsoft\Windows\CurrentVersion\RunOnce", keys);
        Assert.Contains($@"HKU\{Alice}\Environment", keys);
        Assert.DoesNotContain(keys, k => k.Contains(Bob, StringComparison.Ordinal)); // not loaded: nothing of the hive is held open
        Assert.Contains(plan.Watches, w => w.Target.Kind == PersistenceWatchKind.Folder && w.Target.Path == h.Tasks && w.Target.Subtree);
        Assert.Contains(plan.Watches, w => w.Target.Kind == PersistenceWatchKind.Folder && w.Target.Path == h.Startup && !w.Target.Subtree);
        Assert.Equal((PersistenceScope.Profiles, true), (plan.Watches.Single(w => w.Target.ToString() == "HKU\\").Scope, plan.ProfilesComplete));
        Assert.Contains(Alice, plan.LoadedSids);
        Assert.DoesNotContain(Bob, plan.LoadedSids);
    }

    [Fact]
    public void RealRegistryWatch_FollowsAKeyCreatedLater_FromItsAncestor_AndStopsOnDispose()
    {
        using var registry = new RegistryTestRoot();
        registry.Users(Alice);
        using var fired = new SemaphoreSlim(0);
        var factory = new WindowsRegistryWatchFactory(registry.MachineKey, registry.UsersKey);
        string path = $@"{Alice}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
        var watch = (RegistryKeyWatch)factory.Watch(RegistryRoot.Users, path, subtree: false, () => fired.Release());
        try
        {
            Assert.True(watch.Active);
            Assert.False(watch.WatchingKey); // only the SID key exists: watched through it

            registry.Users(path).Dispose(); // the whole chain at once
            Assert.True(fired.Wait(TimeSpan.FromSeconds(30)), "creating the key wasn't noticed");
            while (fired.Wait(TimeSpan.FromMilliseconds(200)))
            {
                // the ancestor may report the new chain more than once
            }

            Assert.True(watch.WatchingKey);
            registry.Users(path).SetValue("Late", @"C:\late.exe");
            Assert.True(fired.Wait(TimeSpan.FromSeconds(30)), "a value set in the key wasn't noticed");
        }
        finally
        {
            watch.Dispose();
        }

        registry.Users(path).SetValue("AfterDispose", @"C:\x.exe");
        Assert.False(fired.Wait(TimeSpan.FromMilliseconds(300)));
    }

    [Fact]
    public void AFailedFirstPlan_StillLeadsToTheFirstCollection_WhenAPlanWorksAgain()
    {
        using var h = new MonitorHarness();
        h.MachineRunValue("Dropper", h.Target("mal-dropper.exe"));
        var flaky = new FlakyPlanCollector(h.Collector);
        using var monitor = new PersistenceMonitor(h.Options, flaky, h.Scanner, h.Store, h.FakeRegistry, h.Folders, h.Time, h.Log);

        monitor.Initialize();
        Assert.Equal(0, monitor.RunDue());
        Assert.Empty(h.FakeRegistry.Live);

        h.Time.Now += h.Options.RevalidateInterval;
        monitor.Tick();
        monitor.RunDue();

        Assert.NotEmpty(h.FakeRegistry.Live);
        Assert.Single(h.PersistenceAlerts("Dropper"));
    }

    private sealed class FlakyPlanCollector(IScopedPersistenceCollector inner) : IScopedPersistenceCollector
    {
        private int _plans;

        public IRegistryView Registry => inner.Registry;

        public PersistenceCollection Collect(CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null) => inner.Collect(cancellationToken, options);

        public PersistenceScopedCollection CollectScoped(IReadOnlyCollection<PersistenceScope>? scopes, CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null) =>
            inner.CollectScoped(scopes, cancellationToken, options);

        public PersistenceWatchPlan Plan(CancellationToken cancellationToken = default) =>
            Interlocked.Increment(ref _plans) == 1 ? throw new IOException("first plan fails") : inner.Plan(cancellationToken);
    }

    [Fact]
    public void EngineHost_RegistersTheMonitor_WithAnOnOffOption()
    {
        var builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder([]);
        builder.Configuration["PersistenceMonitor:Enabled"] = "false";
        EngineHost.Configure(builder);

        Assert.Contains(builder.Services, d => d.ImplementationType == typeof(PersistenceMonitorService));
        using var provider = builder.Services.BuildServiceProvider();
        Assert.False(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<PersistenceMonitorOptions>>().Value.Enabled);
        Assert.True(new PersistenceMonitorOptions().Enabled);
    }

    private static void WriteTask(string folder, string name, string command) =>
        File.WriteAllText(Path.Combine(folder, name), $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
              <Settings><Enabled>true</Enabled></Settings>
              <Actions Context="Author"><Exec><Command>{command}</Command></Exec></Actions>
            </Task>
            """, System.Text.Encoding.Unicode);
}
