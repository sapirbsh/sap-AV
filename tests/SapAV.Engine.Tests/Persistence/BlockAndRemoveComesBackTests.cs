using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Remediation;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>A collector that runs a hook right before one chosen later collection (e.g. the hand-over after an action).</summary>
internal sealed class HookedCollector(IScopedPersistenceCollector inner) : IScopedPersistenceCollector
{
    private int _calls;

    /// <summary>Runs before collection number <see cref="BeforeCall"/> (1-based) from now on.</summary>
    public Action? Hook { get; set; }

    public int BeforeCall { get; set; }

    public IRegistryView Registry => inner.Registry;

    public PersistenceCollection Collect(CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null) =>
        inner.Collect(cancellationToken, options);

    public PersistenceScopedCollection CollectScoped(
        IReadOnlyCollection<PersistenceScope>? scopes, CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null)
    {
        if (Hook is { } hook && Interlocked.Increment(ref _calls) == BeforeCall)
        {
            Hook = null;
            hook();
        }

        return inner.CollectScoped(scopes, cancellationToken, options);
    }

    public PersistenceWatchPlan Plan(CancellationToken cancellationToken = default) => inner.Plan(cancellationToken);

    /// <summary>Arms <paramref name="hook"/> for the <paramref name="call"/>-th collection from now (1 = the action's lookup).</summary>
    public void Before(int call, Action hook)
    {
        _calls = 0;
        BeforeCall = call;
        Hook = hook;
    }
}

/// <summary>
/// Section D review H1: the hand-over to D4 accepts the entry only in the state the action produced. An entry re-created
/// right after Block (a watchdog that rewrites its Run value), or changed right after a restore, is reported and judged.
/// </summary>
public sealed class BlockAndRemoveComesBackTests : IDisposable
{
    private const string Alice = MonitorHarness.Alice;
    private readonly MonitorHarness _m = new();
    private readonly HookedCollector _collector;
    private readonly RemediationHarness _h;

    public BlockAndRemoveComesBackTests()
    {
        _m.UserActions = new PersistenceActionLedger(_m.Time);
        _collector = new HookedCollector(_m.Collector);
        _h = new RemediationHarness(_collector, _m.UserActions, _m.Time, _m.Registry);
    }

    public void Dispose()
    {
        _h.Dispose();
        _m.Dispose();
    }

    private string IdOf(string valueName) => PersistenceEntryId.Compute(Assert.Single(_m.Collector.Inner.Collect().Entries, e => e.ValueName == valueName));

    [Fact]
    public void ARunValueRecreatedRightAfterBlock_IsReported_AndAlerted()
    {
        string evil = _m.Target("malware.exe");
        _m.UserRunValue(Alice, "Evil", evil);
        _m.Baseline();
        int before = _m.PersistenceAlerts("Evil").Count();
        _collector.Before(2, () => _m.UserRunValue(Alice, "Evil", evil)); // the watchdog puts it back before the hand-over

        var result = _h.Block(_h.User(Alice), IdOf("Evil"));
        _m.MarkAndRun(new PersistenceScope("registry autoruns", Alice));

        Assert.Equal(RemediationStatus.EntryChanged, result.Status);
        Assert.NotNull(result.Record); // the block itself happened and is restorable
        Assert.Equal(before + 1, _m.PersistenceAlerts("Evil").Count());
    }

    [Fact]
    public void ARestoredValueChangedRightAfter_IsReported_AndAlerted()
    {
        _m.UserRunValue(Alice, "Evil", _m.Target("malware.exe"));
        _m.Baseline();
        var alice = _h.User(Alice);
        var blocked = _h.Block(alice, IdOf("Evil"));
        _m.Monitor.RunDue();
        int before = _m.PersistenceAlerts("Evil").Count();
        _collector.Before(1, () => _m.UserRunValue(Alice, "Evil", _m.Target("malware-other.exe"))); // restore's only collection: the hand-over

        var result = _h.Restore(alice, blocked.Record!.Id);
        _m.Monitor.RunDue();

        Assert.Equal(RemediationStatus.EntryChanged, result.Status);
        Assert.Equal(before + 1, _m.PersistenceAlerts("Evil").Count());
    }

    [Fact]
    public void ARunValueLeftGone_IsNotReported()
    {
        _m.UserRunValue(Alice, "Evil", _m.Target("malware.exe"));
        _m.Baseline();

        Assert.Equal(RemediationStatus.Blocked, _h.Block(_h.User(Alice), IdOf("Evil")).Status);
    }
}
