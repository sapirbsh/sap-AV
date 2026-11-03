using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.RealTime;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>
/// D1 through the real monitor (queue, threads, scan pipeline, hardened opens) with hand-pushed watcher events, so no test
/// depends on FileSystemWatcher timing. Verdicts come from the fake broker (by file name).
/// </summary>
public sealed class RealTimeMonitorTests : IDisposable
{
    private readonly RealTimeHarness _rt = new();

    public void Dispose() => _rt.Dispose();

    [Fact]
    public void ANewFile_IsScannedOnce_OnABackgroundThread_AsRealTime_OnTheEnginesBudget()
    {
        var handler = new BudgetRecordingHandler();
        _rt.Handler = handler;
        _rt.Write("mal-invoice.exe");
        _rt.Start();

        _rt.Events.Added(_rt.Watched, "mal-invoice.exe");
        var result = _rt.WaitFor("mal-invoice.exe");

        Assert.Equal(RealTimeOutcome.Scanned, result.Outcome);
        Assert.Equal(Verdict.Malicious, result.Scan!.Verdict);
        Assert.Equal(1, _rt.Broker.Calls);
        Assert.All(_rt.Broker.BackgroundModeSeen, Assert.True);
        var (report, budget) = Assert.Single(handler.Seen);
        Assert.Equal(ScanTrigger.RealTime, report.Result.Item.Trigger);
        Assert.Equal("engine:RealTime", budget!.Alerts.Key); // never a user's budget
        Assert.Null(budget.Quota); // no per-user quota check for files a user drops (review C1 L6)
    }

    [Fact]
    public void ABurstOfEventsForOneFile_IsCoalescedIntoOneScan()
    {
        _rt.Write("setup.exe");
        _rt.Start();

        for (int i = 0; i < 20; i++)
        {
            _rt.Events.Raise(_rt.Watched, new FileChange(i == 0 ? FileChangeKind.Added : FileChangeKind.Modified, "setup.exe"));
        }

        _rt.WaitFor("setup.exe");
        _rt.Write("after.txt");
        _rt.Events.Added(_rt.Watched, "after.txt");
        _rt.WaitFor("after.txt"); // everything for setup.exe has been handled by now

        Assert.Equal(2, _rt.Broker.Calls);
        Assert.True(_rt.Monitor.Status.Coalesced >= 19);
    }

    [Fact]
    public void AFileStillBeingWritten_IsWaitedFor_AndScannedOnceTheWriterClosesIt()
    {
        var path = _rt.Write("download.exe", "half");
        _rt.Start();
        using (var writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            _rt.Events.Added(_rt.Watched, "download.exe");
            RealTimeHarness.Until(() => _rt.Monitor.Status.LockRetries >= 3, "a few lock retries");
            Assert.Equal(0, _rt.Broker.Calls); // never scanned half-written
            writer.Write("-and the rest"u8);
        }

        var result = _rt.WaitFor("download.exe");

        Assert.Equal((RealTimeOutcome.Scanned, false), (result.Outcome, result.LockWaitExpired));
        Assert.Equal(1, _rt.Broker.Calls);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData("half-and the rest"u8)), result.Scan!.Sha256); // the whole file
    }

    [Fact]
    public void AWriterThatNeverCloses_GivesUpAfterTheLimit_ScansWithTheJournalCheck_ButLeavesInProgressDownloadsToTheirRename()
    {
        _rt.Options.MaxLockWait = TimeSpan.FromMilliseconds(300);
        var held = _rt.Write("dropper.exe", "payload");
        var partial = _rt.Write("big.iso.crdownload", "partial");
        _rt.Start();
        using var writer1 = new FileStream(held, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        using var writer2 = new FileStream(partial, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);

        _rt.Events.Added(_rt.Watched, "dropper.exe", "big.iso.crdownload");
        var dropper = _rt.WaitFor("dropper.exe");
        var download = _rt.WaitFor("big.iso.crdownload");

        // Reported, never silently lost: scanned shared with the change-journal check (or Locked without a journal).
        Assert.True(dropper.LockWaitExpired);
        Assert.Equal(RealTimeOutcome.Scanned, dropper.Outcome);
        Assert.True(dropper.Scan!.Status == ScanStatus.Scanned || dropper.Scan.SkipReason == ScanSkipReason.Locked);
        Assert.Equal((RealTimeOutcome.StillLocked, true), (download.Outcome, download.LockWaitExpired));
        Assert.Equal(2, _rt.Monitor.Status.LockWaitsExpired);
        Assert.True(_rt.Broker.Calls <= 1); // the .crdownload never reached the worker
    }

    [Fact]
    public void AFileOverTheSizeLimit_IsReported_AndNeverSentToTheWorker()
    {
        _rt.Options.MaxFileSizeBytes = 16;
        _rt.Write("huge.exe", new string('x', 100));
        _rt.Start();

        _rt.Events.Added(_rt.Watched, "huge.exe");

        Assert.Equal(RealTimeOutcome.TooLarge, _rt.WaitFor("huge.exe").Outcome);
        Assert.Equal(0, _rt.Broker.Calls);
    }

    [Fact]
    public void DownloadedFiles_WithAMarkOfTheWeb_AreScannedFirst()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var order = new List<string>();
        _rt.Broker.OnScan = async (item, _, _) =>
        {
            lock (order)
            {
                order.Add(Path.GetFileName(item.Path));
            }

            if (item.Path.EndsWith("first.bin", StringComparison.Ordinal))
            {
                await gate.Task;
            }

            return null;
        };
        _rt.Write("first.bin");
        _rt.Write("tool.exe");
        var downloaded = _rt.Write("letter.txt");
        File.WriteAllText(downloaded + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
        _rt.Start();

        _rt.Events.Added(_rt.Watched, "first.bin");
        RealTimeHarness.Until(() => _rt.Broker.Calls == 1, "the first scan to start");
        _rt.Events.Added(_rt.Watched, "tool.exe", "letter.txt");
        RealTimeHarness.Until(() => _rt.Monitor.Status.Ready == 2, "both files ranked");
        gate.SetResult();
        _rt.WaitFor("tool.exe");
        _rt.WaitFor("letter.txt");

        Assert.Equal(["first.bin", "letter.txt", "tool.exe"], order); // the download (a .txt) before the executable without one
    }

    [Fact]
    public void AnOverflow_RescansRecentlyChangedFilesInThatFolder_NotOldOnes_AndACappedRescanIsReported()
    {
        // The monitor's clock runs 10 minutes ahead, so a file written now is "old" (changed before the last batch the watcher
        // delivered); the "recent" ones get a last-write time after it (a change time can't be set from here, a write time can).
        _rt.Time = new ShiftedTime(TimeSpan.FromMinutes(10));
        _rt.Write("old.exe");
        foreach (var name in new[] { "a.exe", "b.dll", @"sub\c.js" })
        {
            File.SetLastWriteTimeUtc(_rt.Write(name), DateTime.UtcNow.AddMinutes(20));
        }

        _rt.Start();
        _rt.Events.Overflow(_rt.Watched);

        foreach (var name in new[] { "a.exe", "b.dll", "c.js" })
        {
            Assert.Equal(RealTimeOutcome.Scanned, _rt.WaitFor(name).Outcome);
        }

        RealTimeHarness.Until(() => _rt.LogLines().Any(l => l.Message.Contains("3 file(s) queued", StringComparison.Ordinal)), "the rescan to finish");
        Assert.Equal(1, _rt.Monitor.Status.Overflows);
        Assert.DoesNotContain(_rt.Results(), r => r.Path.EndsWith("old.exe", StringComparison.Ordinal)); // changed before the lost events
        Assert.Equal(0, _rt.Monitor.Status.RescansIncomplete);

        // A second overflow with a cap of 2 files: reported as incomplete.
        _rt.Options.MaxRescanFiles = 2;
        _rt.Events.Overflow(_rt.Watched);
        RealTimeHarness.Until(() => _rt.Monitor.Status.RescansIncomplete == 1, "the capped rescan");
        RealTimeHarness.Until(() => _rt.LogLines().Any(l => l.Level == LogLevel.Warning && l.Message.Contains("Quick Scan", StringComparison.Ordinal)),
            "the incomplete-rescan warning");
    }

    [Fact]
    public void AnEventStorm_NeverGrowsTheQueuePastItsCap_AndTheDroppedFilesAreRescannedLater()
    {
        _rt.Options.MaxPendingFiles = 8;
        _rt.Time = new ShiftedTime(TimeSpan.FromMinutes(-1)); // the files written below count as changed after the storm began, however slow the disk
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _rt.Broker.OnScan = async (_, _, _) =>
        {
            await gate.Task;
            return null;
        };
        var names = Enumerable.Range(0, 200).Select(i => $"x{i:D3}.exe").ToArray();
        foreach (var name in names)
        {
            _rt.Write(name);
        }

        _rt.Start();
        int maxPending = 0;
        foreach (var chunk in names.Chunk(20))
        {
            _rt.Events.Added(_rt.Watched, chunk);
            maxPending = Math.Max(maxPending, _rt.Monitor.Queue.Count);
        }

        Assert.True(maxPending <= 8, $"the queue grew to {maxPending}");
        Assert.True(_rt.Monitor.Status.Dropped >= 190);
        gate.SetResult();

        RealTimeHarness.Until(() => names.All(n => _rt.Results().Any(r => r.Path.EndsWith(n, StringComparison.Ordinal))), "every file scanned");
        Assert.True(_rt.Monitor.Status.Rescans >= 1);
        Assert.True(_rt.Monitor.Queue.Count <= 8);
        Assert.Single(_rt.LogLines(), l => l.Message.Contains("queue is full", StringComparison.Ordinal)); // one storm notice, not 190
    }

    [Fact]
    public void AFolderMovedIn_HasItsFilesScanned_ThoughTheyRaiseNoEventsOfTheirOwn()
    {
        _rt.Write(@"moved\inner\payload.exe");
        _rt.Write(@"moved\readme.txt");
        _rt.Start();

        _rt.Events.Raise(_rt.Watched, new FileChange(FileChangeKind.RenamedTo, "moved", FileAttributes.Directory));

        Assert.Equal(RealTimeOutcome.Scanned, _rt.WaitFor("payload.exe").Outcome);
        Assert.Equal(RealTimeOutcome.Scanned, _rt.WaitFor("readme.txt").Outcome);
    }

    [Fact]
    public void AFileBlockedByAnotherAntivirus_IsReportedAsSuch_NotAsAnError()
    {
        _rt.Broker.OnScan = (item, file, _) => Task.FromResult<FileScanReport?>(ScanFileOpener.NotOpenedReport(item,
            HashResult.NotHashed(HashFailureReason.BlockedByAntivirus, "Operation did not complete successfully because the file contains a virus."),
            [], DateTimeOffset.UtcNow) with { Identity = file.Identity });
        _rt.Write("flagged.exe");
        _rt.Start();

        _rt.Events.Added(_rt.Watched, "flagged.exe");
        var result = _rt.WaitFor("flagged.exe");

        Assert.Equal(RealTimeOutcome.BlockedByAntivirus, result.Outcome);
        Assert.Equal(1, _rt.Monitor.Status.BlockedByAntivirus);
        Assert.Equal(0, _rt.Monitor.Status.Errors);
        Assert.Contains(_rt.LogLines(), l => l.Level == LogLevel.Information && l.Message.Contains("Another antivirus", StringComparison.Ordinal));
        Assert.DoesNotContain(_rt.LogLines(), l => l.Level >= LogLevel.Warning);
    }

    [Fact]
    public void Folders_NotOnALocalFixedDrive_OrRemote_AreNotWatched()
    {
        var removable = Directory.CreateDirectory(Path.Combine(_rt.Base, "usb")).FullName;
        _rt.Folders.Folders.Add(new WatchedFolder(removable, WatchedFolderKind.Configured));
        _rt.DriveType = root => 3;
        _rt.Remote = new ClassifyAs(path => path.Contains("usb", StringComparison.OrdinalIgnoreCase) ? FileLocation.Remote : FileLocation.Local);
        _rt.Start();

        Assert.True(_rt.Events.IsWatching(_rt.Watched));
        Assert.False(_rt.Events.IsWatching(removable));
        Assert.Contains("remote", _rt.Monitor.Problems[ExactPath.ToExtended(removable)!], StringComparison.Ordinal);

        using var other = new RealTimeHarness { DriveType = _ => 2 /* DRIVE_REMOVABLE */ };
        other.Start();
        Assert.Equal(0, other.Events.Started);
        Assert.Contains("local fixed drive", Assert.Single(other.Monitor.Problems).Value, StringComparison.Ordinal);
    }

    /// <summary>Classifies by the handle's final path (stands in for an SMB handle).</summary>
    private sealed class ClassifyAs(Func<string, FileLocation> byPath) : IRemoteFileProbe
    {
        public FileLocation Classify(System.Runtime.InteropServices.SafeHandle handle) =>
            byPath(NativeFile.TryGetFinalDosPath((SafeFileHandle)handle) ?? string.Empty);
    }

    /// <summary>Records what the verdict handler was given (no alerts, no quarantine).</summary>
    private sealed class BudgetRecordingHandler : IScanVerdictHandler
    {
        public List<(FileScanReport Report, ScanBudget? Budget)> Seen { get; } = [];

        public Task<ScanVerdictOutcome> HandleAsync(FileScanReport report, OpenedScanFile? opened, ScanBudget? budget, CancellationToken cancellationToken)
        {
            lock (Seen)
            {
                Seen.Add((report, budget));
            }

            return Task.FromResult(ScanVerdictOutcome.Nothing);
        }

        public void JobFinished(ScanJob job)
        {
        }
    }
}
