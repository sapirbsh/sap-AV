using System.IO.MemoryMappedFiles;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.RealTime;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>D1: the bounded, coalescing, prioritised queue (pure, on a hand-moved clock) and the "wait until unlocked" probe.</summary>
public sealed class RealTimeQueueTests : IDisposable
{
    private readonly TempDir _temp = new();
    private readonly ManualTime _time = new();
    private readonly WatchedRoot _root;

    public RealTimeQueueTests()
    {
        var handle = SafeTree.Open(_temp.Path, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _)!;
        _root = new WatchedRoot(1, new WatchedFolder(_temp.Path, WatchedFolderKind.Downloads), Core.Hashing.ExactPath.ToExtended(_temp.Path)!, handle, 1, "1", _time.Now);
    }

    public void Dispose()
    {
        _root.Dispose();
        _temp.Dispose();
    }

    private static RealTimeOptions Options(int maxPending = 100, long maxChars = 1_000_000) => new()
    {
        MaxPendingFiles = maxPending,
        MaxPendingPathChars = maxChars,
        SettleDelay = TimeSpan.FromMilliseconds(500),
        MaxSettleDelay = TimeSpan.FromSeconds(3),
    };

    [Fact]
    public void RepeatedEvents_ForOneFile_AreOneEntry_DueAfterTheLastEvent_ButNoLaterThanTheCap()
    {
        var queue = new RealTimeQueue(Options());

        Assert.Equal(OfferResult.Queued, queue.Offer(_root, "setup.exe", false, _time.Now));
        for (int i = 0; i < 50; i++)
        {
            _time.Now += TimeSpan.FromMilliseconds(100);
            Assert.Equal(OfferResult.Coalesced, queue.Offer(_root, "SETUP.exe", false, _time.Now)); // case-insensitive, like the file system
        }

        Assert.Equal(1, queue.Count);
        _time.Now += TimeSpan.FromMilliseconds(100);
        Assert.True(queue.TryTakeDue(_time.Now, out var file)); // 5.1 s after the first event: the 3 s cap made it due
        Assert.False(queue.TryTakeDue(_time.Now, out _)); // one heap entry per file, however many events
        Assert.Equal("setup.exe", file.Relative);

        // An event while it is being scanned: looked at again afterwards, from then on.
        queue.MakeReady(file, 0);
        Assert.True(queue.TryTakeReady(out var scanning));
        Assert.Equal(OfferResult.Coalesced, queue.Offer(_root, "setup.exe", false, _time.Now));
        Assert.True(queue.Complete(scanning, _time.Now));
        Assert.False(queue.TryTakeDue(_time.Now, out _));
        Assert.True(queue.TryTakeDue(_time.Now + TimeSpan.FromMilliseconds(500), out _));
    }

    [Fact]
    public void ReadyFiles_LeaveByRank_ThenInTheOrderTheyWereRanked()
    {
        var queue = new RealTimeQueue(Options());
        foreach (var name in new[] { "notes.txt", "tool.exe", "invoice.pdf", "download.zip" })
        {
            queue.Offer(_root, name, motwHint: name == "invoice.pdf", _time.Now);
        }

        _time.Now += TimeSpan.FromSeconds(1);
        while (queue.TryTakeDue(_time.Now, out var file))
        {
            // The monitor's ranking: Mark-of-the-Web first, then executables (0), archives (1), the rest (3).
            int rank = (file.MotwHint ? 0 : 10) + file.Relative switch { "tool.exe" => 0, "download.zip" => 1, _ => 3 };
            queue.MakeReady(file, rank);
        }

        var order = new List<string>();
        while (queue.TryTakeReady(out var next))
        {
            order.Add(next.Relative);
        }

        Assert.Equal(["invoice.pdf", "tool.exe", "download.zip", "notes.txt"], order);
    }

    [Fact]
    public void TheQueue_IsCappedByFiles_AndByPathCharacters_AndFreesBothOnCompletion()
    {
        var byFiles = new RealTimeQueue(Options(maxPending: 4));
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal(OfferResult.Queued, byFiles.Offer(_root, $"f{i}.bin", false, _time.Now));
        }

        Assert.Equal(OfferResult.Dropped, byFiles.Offer(_root, "f4.bin", false, _time.Now));
        Assert.Equal(OfferResult.Coalesced, byFiles.Offer(_root, "f0.bin", false, _time.Now)); // a waiting file still merges

        var byChars = new RealTimeQueue(Options(maxChars: 1024));
        string longName = new('a', 600);
        Assert.Equal(OfferResult.Queued, byChars.Offer(_root, longName, false, _time.Now));
        Assert.Equal(OfferResult.Dropped, byChars.Offer(_root, new string('b', 600), false, _time.Now));

        _time.Now += TimeSpan.FromSeconds(1);
        Assert.True(byChars.TryTakeDue(_time.Now, out var file));
        byChars.MakeReady(file, 0);
        Assert.True(byChars.TryTakeReady(out file));
        Assert.False(byChars.Complete(file, _time.Now));
        Assert.Equal((0, 0L), (byChars.Count, byChars.PathChars));
        Assert.Equal(OfferResult.Queued, byChars.Offer(_root, new string('b', 600), false, _time.Now));
    }

    // ---- The "wait until unlocked" probe ----

    private SafeFileHandle Folder() => SafeTree.Open(_temp.Path, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _)!;

    [Fact]
    public void Probe_IsLockedWhileAWriterHasTheFile_UnlockedForReaders_AndGoneWhenMissing()
    {
        var path = Path.Combine(_temp.Path, "download.exe");
        File.WriteAllText(path, "partial");
        using var folder = Folder();

        using (new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
        {
            Assert.Equal(ProbeOutcome.Locked, UnlockProbe.Probe(folder, "download.exe").Outcome);
        }

        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            var unlocked = UnlockProbe.Probe(folder, "download.exe");
            Assert.Equal((ProbeOutcome.Unlocked, 7L), (unlocked.Outcome, unlocked.Length));
        }

        Assert.Equal(ProbeOutcome.Unlocked, UnlockProbe.Probe(folder, "download.exe").Outcome);
        Assert.Equal(ProbeOutcome.Gone, UnlockProbe.Probe(folder, "missing.exe").Outcome);
        Directory.CreateDirectory(Path.Combine(_temp.Path, "sub"));
        Assert.Equal(ProbeOutcome.Directory, UnlockProbe.Probe(folder, "sub").Outcome);
    }

    [Fact]
    public void Probe_IsLockedWhileOnlyAWritableMappedViewIsLeft_TheFileHandleClosed()
    {
        // ROADMAP D1 (L6): a writer can keep a writable view after closing its handle; the deny-writers open still fails on NTFS.
        var path = Path.Combine(_temp.Path, "mapped.bin");
        File.WriteAllBytes(path, new byte[4096]);
        using var folder = Folder();
        MemoryMappedFile map;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
        {
            map = MemoryMappedFile.CreateFromFile(stream, null, 0, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: true);
        }

        using (map)
        using (var view = map.CreateViewAccessor(0, 4096, MemoryMappedFileAccess.ReadWrite))
        {
            view.Write(0, (byte)1);
            Assert.Equal(ProbeOutcome.Locked, UnlockProbe.Probe(folder, "mapped.bin").Outcome);
        }

        Assert.Equal(ProbeOutcome.Unlocked, UnlockProbe.Probe(folder, "mapped.bin").Outcome);
    }

    [Theory]
    [InlineData((int)SafeTreeFailure.Error, 225, (int)ProbeOutcome.BlockedByAntivirus)] // ERROR_VIRUS_INFECTED: Defender got there first
    [InlineData((int)SafeTreeFailure.Error, 226, (int)ProbeOutcome.BlockedByAntivirus)] // ERROR_VIRUS_DELETED
    [InlineData((int)SafeTreeFailure.Redirected, 4395, (int)ProbeOutcome.Link)]
    [InlineData((int)SafeTreeFailure.Locked, 32, (int)ProbeOutcome.Locked)]
    public void ProbeFailures_AreClassifiedByTheirError(int failureValue, int error, int expectedValue)
    {
        var (failure, expected) = ((SafeTreeFailure)failureValue, (ProbeOutcome)expectedValue);
        Assert.Equal(expected, UnlockProbe.Classify(failure, error));
        if (error is 225 or 226)
        {
            Assert.Equal(Core.Hashing.HashFailureReason.BlockedByAntivirus, SafeScanOpen.Reason(failure, error)); // the scan open says so too
        }
    }
}
