using Microsoft.Win32.SafeHandles;
using SapAV.Engine.RealTime;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>
/// The D1 immediate review: H1 (oplocks never stall real-time threads), H2 (per-folder quotas, fair turns, long names,
/// minimum re-scan interval), M1 (both caps for rescans), M2 (per-owner budgets), M3 (one worker kept free).
/// </summary>
public sealed class RealTimeReviewTests : IDisposable
{
    private readonly RealTimeHarness _rt = new();
    private readonly ManualTime _time = new();

    public void Dispose() => _rt.Dispose();

    private WatchedRoot Root(int id, string? sid = null)
    {
        var handle = SafeTree.Open(_rt.Watched, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _)!;
        return new WatchedRoot(id, new WatchedFolder(_rt.Watched, WatchedFolderKind.Downloads, sid), Core.Hashing.ExactPath.ToExtended(_rt.Watched)!,
            handle, 1, id.ToString(System.Globalization.CultureInfo.InvariantCulture), _time.Now);
    }

    // ---- H1: oplocks ----

    [Fact]
    public async Task TheProbe_DoesNotWaitForAnOplockBreakThatIsNeverAcknowledged_ItIsLocked()
    {
        var path = _rt.Write("held.exe");
        using var folder = SafeTree.Open(_rt.Watched, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _)!;
        using var oplock = new BatchOplock(path);

        var probe = Task.Run(() => UnlockProbe.Probe(folder, "held.exe"));

        var result = await probe.WaitAsync(TimeSpan.FromSeconds(10)); // throws TimeoutException if it hangs behind the break
        Assert.Equal(ProbeOutcome.Locked, result.Outcome);
    }

    [Fact]
    public void AFileUnderAnUnacknowledgedOplock_IsReportedLocked_AndTheScanThreadGoesOn()
    {
        _rt.Options.MaxLockWait = TimeSpan.FromMilliseconds(300);
        var held = _rt.Write("held.exe");
        _rt.Write("next.txt");
        _rt.Start();
        using var oplock = new BatchOplock(held);

        _rt.Events.Added(_rt.Watched, "held.exe", "next.txt");
        var result = _rt.WaitFor("held.exe"); // the probe, then the scan open (shared fallback included), never wait for the break

        Assert.True(result.LockWaitExpired);
        Assert.Equal(ScanSkipReason.Locked, result.Scan?.SkipReason);
        Assert.Equal(RealTimeOutcome.Scanned, _rt.WaitFor("next.txt").Outcome); // the one scan thread is free
    }

    [Fact]
    public void TheWatchdog_CancelsAThreadStuckInASynchronousOpen()
    {
        var path = _rt.Write("stuck.bin");
        using var oplock = new BatchOplock(path);
        ScanThreadWatch? watch = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            watch = ScanThreadWatch.ForCurrentThread();
            watch.Arm(path, "open", TimeSpan.FromMilliseconds(100));
            try
            {
                File.ReadAllBytes(path); // a plain open: waits for the break acknowledgement that never comes
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        }) { IsBackground = true };
        thread.Start();

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        while (thread.IsAlive && DateTime.UtcNow < deadline)
        {
            watch?.CancelIfOverdue(Environment.TickCount64);
            Thread.Sleep(50);
        }

        Assert.False(thread.IsAlive, "the stuck open was not cancelled");
        Assert.IsAssignableFrom<IOException>(failure is OperationCanceledException ? new IOException("cancelled", failure) : failure);
        Assert.True(watch!.Cancellations >= 1);
        watch.Dispose();
    }

    // ---- H2: per-folder quotas, turns, long names, re-scan interval ----

    [Fact]
    public void OneFoldersStorm_UsesOnlyItsShare_TheFoldersTakeTurns_AndLongNamesWaitForARescan()
    {
        var options = new RealTimeOptions { MaxPendingFiles = 80, FolderShareDivisor = 8, MaxQueuedNameLength = 64, SettleDelay = TimeSpan.Zero };
        var queue = new RealTimeQueue(options);
        using var a = Root(1);
        using var b = Root(2);

        var offered = Enumerable.Range(0, 30).Select(i => queue.Offer(a, $"a{i:D2}.exe", true, _time.Now)).ToArray();
        Assert.Equal(10, offered.Count(r => r == OfferResult.Queued)); // A's share: 80 / 8
        Assert.Equal(OfferResult.Queued, queue.Offer(b, "letter.txt", false, _time.Now)); // B is unaffected by A's storm
        Assert.Equal(OfferResult.TooLong, queue.Offer(b, new string('n', 65), false, _time.Now));
        Assert.Equal(OfferResult.Queued, queue.Offer(b, new string('n', 65), false, _time.Now, allowLong: true)); // the rescan may

        while (queue.TryTakeDue(_time.Now, out var file))
        {
            queue.MakeReady(file, file.MotwHint ? 0 : 13); // A's files outrank B's
        }

        var order = new List<int>();
        while (queue.TryTakeReady(out var next))
        {
            order.Add(next.Root.Id);
        }

        Assert.Equal([1, 2, 1, 2], order.Take(4)); // turns, not strict rank across folders
        Assert.Equal(12, order.Count);
    }

    [Fact]
    public void AFileRewrittenAllTheTime_IsScannedAtMostOncePerMinimumInterval()
    {
        var queue = new RealTimeQueue(new RealTimeOptions { SettleDelay = TimeSpan.FromMilliseconds(100), MinRescanInterval = TimeSpan.FromSeconds(15) });
        using var root = Root(1);
        queue.Offer(root, "log.bin", false, _time.Now);
        _time.Now += TimeSpan.FromSeconds(1);
        Assert.True(queue.TryTakeDue(_time.Now, out var first));
        queue.MakeReady(first, 0);
        Assert.True(queue.TryTakeReady(out first));
        Assert.False(queue.Complete(first, _time.Now)); // scanned now

        _time.Now += TimeSpan.FromMilliseconds(500); // appended again half a second later
        Assert.Equal(OfferResult.Queued, queue.Offer(root, "log.bin", false, _time.Now));
        Assert.False(queue.TryTakeDue(_time.Now + TimeSpan.FromSeconds(10), out _));
        Assert.True(queue.TryTakeDue(_time.Now + TimeSpan.FromSeconds(15), out _));
    }

    [Fact]
    public void AStormInOneWatchedFolder_DoesNotDelayAFileInAnother()
    {
        var other = Directory.CreateDirectory(Path.Combine(_rt.Base, "other")).FullName;
        _rt.Folders.Folders.Add(new WatchedFolder(other, WatchedFolderKind.Desktop));
        _rt.Options.MaxPendingFiles = 80; // 10 per folder
        _rt.Broker.OnScan = async (item, _, _) =>
        {
            if (item.Path.Contains(@"\watched\", StringComparison.OrdinalIgnoreCase))
            {
                await Task.Delay(30);
            }

            return null;
        };
        var names = Enumerable.Range(0, 100).Select(i => $"x{i:D3}.exe").ToArray();
        foreach (var name in names)
        {
            File.WriteAllText(_rt.Write(name) + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n"); // the highest rank there is
        }

        File.WriteAllText(Path.Combine(other, "letter.txt"), "a plain document");
        _rt.Start();

        _rt.Events.Added(_rt.Watched, names);
        _rt.Events.Added(other, "letter.txt");
        var letter = _rt.WaitFor("letter.txt");

        var before = _rt.Results().TakeWhile(r => !ReferenceEquals(r, letter)).Count();
        Assert.True(before <= 3, $"{before} files of the storming folder went first");
        Assert.Equal(RealTimeOutcome.Scanned, letter.Outcome);
        Assert.DoesNotContain(_rt.LogLines(), l => l.Message.Contains("queue is full", StringComparison.Ordinal) && l.Message.Contains(@"\other", StringComparison.Ordinal));
    }

    // ---- M2 / M3 ----

    [Fact]
    public void RealTimeBudgets_ArePerWatchedFolderUserOrFileOwner_AndTheEnginesOwnStaysReserved()
    {
        var monitor = _rt.Start();
        using var userFolder = Root(7, sid: "S-1-5-21-1-2-3-1001");
        using var machineFolder = Root(8);

        Assert.Equal("engine:RealTime:S-1-5-21-1-2-3-1001", monitor.BudgetFor(userFolder, "S-1-5-21-1-2-3-1002").Alerts.Key); // the folder's user
        Assert.Equal("engine:RealTime:S-1-5-21-1-2-3-1002", monitor.BudgetFor(machineFolder, "S-1-5-21-1-2-3-1002").Alerts.Key); // the file's owner
        Assert.Equal("engine:RealTime", monitor.BudgetFor(machineFolder, "S-1-5-18").Alerts.Key); // SYSTEM-owned: the engine's own
        Assert.Equal("engine:RealTime", monitor.BudgetFor(machineFolder, null).Alerts.Key);
        Assert.Null(monitor.BudgetFor(machineFolder, "S-1-5-21-1-2-3-1002").Quota);

        for (int i = 0; i < RealTimeMonitor.MaxOwnerBudgets; i++)
        {
            monitor.BudgetFor(machineFolder, $"S-1-5-21-9-9-9-{2000 + i}");
        }

        Assert.Equal("engine:RealTime:*", monitor.BudgetFor(machineFolder, "S-1-5-21-9-9-9-9999").Alerts.Key); // bounded: the rest share one
    }

    [Theory]
    [InlineData(2, 4, 1)] // two workers: real-time takes one at most
    [InlineData(4, 2, 2)]
    [InlineData(4, 4, 3)]
    [InlineData(1, 3, 1)] // a single worker: one thread, nothing to keep free
    public void RealTimeScanThreads_LeaveOneWorkerFree(int workers, int configured, int used) =>
        Assert.Equal(used, new RealTimeOptions { ScanThreads = configured }.EffectiveScanThreads(workers));
}
