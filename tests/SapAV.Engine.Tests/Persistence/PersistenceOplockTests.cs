using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Remediation;
using SapAV.Engine.Tests.RealTime;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section D review H2: a user's oplock (held, never acknowledged) can't freeze persistence collection, D4's judgement or a
/// D5 action, and a D5 action that hangs anyway releases the lock after its timeout. Real batch oplocks on temp files.
/// </summary>
public sealed class PersistenceOplockTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);
    private readonly MonitorHarness _m = new();

    public void Dispose() => _m.Dispose();

    /// <summary>Runs <paramref name="work"/>, which must finish within <see cref="Limit"/> while the oplock is held.</summary>
    private static T Within<T>(Func<T> work)
    {
        var task = Task.Run(work);
        Assert.True(task.Wait(Limit), "the work waited for the oplock break");
        return task.Result;
    }

    [Fact]
    public void AShortcutWithAHeldOplock_InAStartupFolder_DoesntFreezeTheCollection()
    {
        string lnk = Path.Combine(_m.Startup, "held.lnk");
        File.WriteAllBytes(lnk, new byte[256]);
        File.WriteAllText(Path.Combine(_m.Startup, "other.cmd"), "@echo synthetic");
        using var oplock = new BatchOplock(lnk);

        var collected = Within(() => _m.Collector.Inner.Collect());

        Assert.Contains(collected.Entries, e => e.ValueName == "other.cmd");
        Assert.Contains(collected.Issues, i => i.Location.EndsWith("held.lnk", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ARunValueTargetWithAHeldOplock_IsRetriedLater_NotWaitedFor()
    {
        string target = _m.Target("tool.exe");
        _m.MachineRunValue("Held", target);
        using var oplock = new BatchOplock(target);

        Within(() =>
        {
            _m.Baseline();
            return 0;
        });

        Assert.True(_m.Monitor.Status.Retries >= 1); // Locked: not a verdict, tried again with backoff
        Assert.False(_m.Monitor.Baseline.Find(Assert.Single(_m.Collector.Inner.Collect().Entries, e => e.ValueName == "Held").Key)!.Judged);
    }

    [Fact]
    public void BlockingAStartupItemWithAHeldOplock_FailsAsInUse_AtOnce()
    {
        using var h = new RemediationHarness();
        string item = Path.Combine(h.AliceStartup, "held.cmd");
        File.WriteAllText(item, "@echo synthetic");
        string id = h.IdOf("held.cmd");
        using var oplock = new BatchOplock(item);

        var result = Within(() => h.Block(h.User(RemediationHarness.Alice), id));

        Assert.Equal(RemediationStatus.Failed, result.Status);
        Assert.Contains("in use", result.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(item));
    }

    [Fact]
    public void AnActionThatHangs_TimesOutForTheCaller_ButHoldsTheLockUntilItReallyEnds()
    {
        // Follow-up M1: the lock is released by the action's own thread, so a late action never overlaps the next one.
        using var hang = new ManualResetEventSlim();
        using var h = new RemediationHarness();
        var hooked = new HookedCollector(h.Collector);
        using var stuck = new RemediationHarness(collector: hooked, registry: h.Registry, actionTimeout: TimeSpan.FromSeconds(1));
        h.UserRunKey(RemediationHarness.Alice).SetValue("Tool", @"C:\Tools\tool.exe");
        string id = h.IdOf("Tool");
        hooked.Before(1, () => hang.Wait(TimeSpan.FromSeconds(60)));
        var alice = stuck.User(RemediationHarness.Alice);

        try
        {
            Assert.Equal(RemediationStatus.Failed, Within(() => stuck.Block(alice, id)).Status);
            Assert.Equal(RemediationStatus.Busy, Within(() => stuck.Block(alice, id)).Status); // it still runs
        }
        finally
        {
            hang.Set();
        }

        RemediationResult later;
        var deadline = DateTime.UtcNow + Limit;
        do
        {
            later = stuck.Block(alice, id);
        }
        while (later.Status == RemediationStatus.Busy && DateTime.UtcNow < deadline);

        Assert.Equal(RemediationStatus.EntryChanged, later.Status); // the late block finished first: the value is gone
        Assert.Single(stuck.Store.List(), r => r.Record?.State == SapAV.Core.Pipe.PersistenceBackupState.Active);
        Assert.Null(h.UserRunKey(RemediationHarness.Alice).GetValue("Tool"));
    }

    [Fact]
    public void LedgerHolds_AreCounted_AKeyHeldTwiceStaysHeldUntilBothRelease()
    {
        var ledger = new PersistenceActionLedger(new TestSupport.ManualTime());
        string[] prefix = [@"RunKey|S-1-5-21-1|HKU\X\RUN|"];
        ledger.Hold(prefix);
        ledger.Hold(prefix);

        ledger.Release(prefix);
        Assert.True(ledger.IsHeld(@"RunKey|S-1-5-21-1|HKU\X\RUN|EVIL", out _));
        ledger.Release(prefix);
        Assert.False(ledger.IsHeld(@"RunKey|S-1-5-21-1|HKU\X\RUN|EVIL", out _));
    }
}
