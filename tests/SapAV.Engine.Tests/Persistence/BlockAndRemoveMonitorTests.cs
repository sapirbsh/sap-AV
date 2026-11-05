using SapAV.Core.Alerts;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Remediation;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// D5 ↔ D4: real-time persistence monitoring doesn't re-alert the user's own Block &amp; remove or restore, and the
/// suppression is exact (anything else in the same place still alerts).
/// </summary>
public sealed class BlockAndRemoveMonitorTests : IDisposable
{
    private const string Alice = MonitorHarness.Alice;
    private readonly MonitorHarness _m = new();
    private readonly RemediationHarness _h;

    public BlockAndRemoveMonitorTests()
    {
        _m.UserActions = new PersistenceActionLedger(_m.Time);
        _h = new RemediationHarness(_m.Collector, _m.UserActions, _m.Time, _m.Registry);
    }

    public void Dispose()
    {
        _h.Dispose();
        _m.Dispose();
    }

    private string IdOf(string valueName) => PersistenceEntryId.Compute(Assert.Single(_m.Collector.Inner.Collect().Entries, e => e.ValueName == valueName));

    [Fact]
    public void BlockThenRestore_RaisesNoNewPersistenceAlert_ButAnotherNewValueStillDoes()
    {
        _m.UserRunValue(Alice, "Evil", _m.Target("malware.exe"));
        _m.Baseline();
        int before = _m.PersistenceAlerts("Evil").Count(); // the initial baseline flags it once
        Assert.Equal(1, before);
        var alice = _h.User(Alice);

        var blocked = _h.Block(alice, IdOf("Evil"));
        _m.Monitor.RunDue(); // the hand-over asked for this scope again right away
        var restored = _h.Restore(alice, blocked.Record!.Id);
        _m.Monitor.RunDue();

        Assert.Equal((RemediationStatus.Blocked, RemediationStatus.Restored), (blocked.Status, restored.Status));
        Assert.Equal(before, _m.PersistenceAlerts("Evil").Count()); // the restore isn't a "new entry"
        Assert.True(_m.Monitor.Baseline.Find(Assert.Single(_m.Collector.Inner.Collect().Entries, e => e.ValueName == "Evil").Key)!.Judged);

        _m.UserRunValue(Alice, "Evil2", _m.Target("malware2.exe"));
        _m.MarkAndRun(new PersistenceScope("registry autoruns", Alice));
        Assert.Single(_m.PersistenceAlerts("Evil2"));
    }

    [Fact]
    public void ARestoredValueChangedAgainBeforeTheMonitorLooked_IsStillJudged()
    {
        _m.UserRunValue(Alice, "Evil", _m.Target("malware.exe"));
        _m.Baseline();
        var alice = _h.User(Alice);
        var blocked = _h.Block(alice, IdOf("Evil"));
        _m.Monitor.RunDue();
        _h.Restore(alice, blocked.Record!.Id);

        _m.UserRunValue(Alice, "Evil", _m.Target("malware-other.exe")); // not what the restore handed over
        _m.Monitor.RunDue();

        Assert.Equal(2, _m.PersistenceAlerts("Evil").Count());
    }

    [Fact]
    public void AValueWrittenIntoTheSameKey_ThenBlockingAnother_StillGetsJudged()
    {
        // Review H1: a user process writes V2 and right away blocks V1 in the same Run key; V2 must not ride along.
        _m.UserRunValue(Alice, "V1", _m.Target("tool.exe"));
        _m.Baseline();
        _m.UserRunValue(Alice, "V2", _m.Target("malware.exe"));

        var blocked = _h.Block(_h.User(Alice), IdOf("V1"));
        _m.Monitor.RunDue();

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.Single(_m.PersistenceAlerts("V2"));
    }

    [Fact]
    public void Ledger_HoldsByPrefixUntilReleasedOrExpired_AndAcceptsAFingerprintOnce()
    {
        var time = new ManualTime();
        var ledger = new PersistenceActionLedger(time);
        ledger.Hold(["RunKey|S-1-5-21-1|HKU\\X\\RUN|"]);

        Assert.True(ledger.IsHeld("RunKey|S-1-5-21-1|HKU\\X\\RUN|EVIL", out _));
        Assert.False(ledger.IsHeld("RunKey|S-1-5-21-1|HKU\\X\\RUNONCE|EVIL", out _));
        time.Now += PersistenceActionLedger.MaxHold + TimeSpan.FromSeconds(1);
        Assert.False(ledger.IsHeld("RunKey|S-1-5-21-1|HKU\\X\\RUN|EVIL", out _));

        ledger.Accept(new Dictionary<string, LedgerAcceptance>
        {
            ["k"] = new("f1"),
            ["neighbour"] = new("n2", JudgedAs: "n1"),
        }, new PersistenceScope("registry autoruns", null));
        Assert.False(ledger.TryConsume("k", "f2", null));
        Assert.True(ledger.TryConsume("k", "f1", null));
        Assert.False(ledger.TryConsume("k", "f1", null));

        // Review H1: a neighbour only from the state it was judged in (never a new or unjudged one).
        Assert.False(ledger.TryConsume("neighbour", "n2", null));
        Assert.False(ledger.TryConsume("neighbour", "n2", "other"));
        Assert.True(ledger.TryConsume("neighbour", "n2", "n1"));
    }
}
