using System.Diagnostics;
using SapAV.Core.Alerts;
using SapAV.Engine.Alerts;
using SapAV.Engine.Persistence.Monitoring;
using SapAV.Engine.RealTime;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.RealTime;

namespace SapAV.Engine.Tests.Alerts;

/// <summary>
/// Section D review M4: health alerts 9010 (real-time unavailable) and 9011 (persistence monitoring unavailable), and the
/// monitors restarting a failed loop with backoff instead of staying off until the engine restarts.
/// </summary>
public sealed class MonitorHealthAlertTests
{
    [Fact]
    public void TheNewHealthAlerts_HaveFixedErrorEvents_AndAreValidAlerts()
    {
        var now = DateTimeOffset.UnixEpoch;
        var realTime = ScanAlerts.RealTimeUnavailable("its scan thread failed.", now);
        var persistence = ScanAlerts.PersistenceMonitorUnavailable("its thread failed.", now);

        Assert.Equal(new AlertEventDefinition(9010, EventLogEntryType.Error), AlertEventCatalog.For(realTime.Type));
        Assert.Equal(new AlertEventDefinition(9011, EventLogEntryType.Error), AlertEventCatalog.For(persistence.Type));
        Assert.Equal((AlertType.RealTimeUnavailable, "T1562.001"), (realTime.Type, realTime.TechniqueId));
        Assert.Contains("its thread failed", Assert.Single(persistence.Reasons), StringComparison.Ordinal);
    }

    [Fact]
    public void RealTime_WithNothingWatchable_RaisesTheHealthAlertOnce()
    {
        using var rt = new RealTimeHarness();
        var problems = new List<string>();
        rt.Unavailable = p =>
        {
            lock (problems)
            {
                problems.Add(p);
            }
        };
        rt.Folders.Folders.Clear();
        rt.Folders.Folders.Add(new WatchedFolder(Path.Combine(rt.Base, "missing"), WatchedFolderKind.Downloads));

        rt.Start();
        rt.Monitor.Revalidate();

        lock (problems)
        {
            Assert.Contains("no watched folder", Assert.Single(problems), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ThePersistenceMonitorLoop_ThatFails_IsReported_AndRestarted()
    {
        var store = new FailingOnceStore();
        using var m = new MonitorHarness(store: store);
        var problems = new List<string>();
        using var reported = new ManualResetEventSlim();
        m.Unavailable = p =>
        {
            lock (problems)
            {
                problems.Add(p);
            }

            reported.Set();
        };

        m.Monitor.Start();

        Assert.True(reported.Wait(TimeSpan.FromSeconds(30)), "the failure wasn't reported");
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (store.Loads < 2 && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(20);
        }

        Assert.True(store.Loads >= 2, "the loop wasn't restarted");
        lock (problems)
        {
            Assert.Contains("its thread failed", problems[0], StringComparison.Ordinal);
        }
    }

    /// <summary>A baseline store whose first load fails (an unexpected bug in the loop), then works.</summary>
    private sealed class FailingOnceStore : IPersistenceBaselineStore
    {
        private int _loads;

        public int Loads => Volatile.Read(ref _loads);

        public BaselineLoadResult Load() =>
            Interlocked.Increment(ref _loads) == 1 ? throw new InvalidOperationException("synthetic failure") : new(BaselineLoadStatus.Missing, null);

        public void Save(BaselineSnapshot snapshot)
        {
        }
    }
}
