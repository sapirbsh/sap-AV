using SapAV.Engine.RealTime;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>
/// Section D review H5: real-time fairness is per owner as well as per folder. One user flooding a dozen of their own
/// watched folders can't fill the queue: another user's file is still queued (and scanned).
/// </summary>
public sealed class RealTimeOwnerShareTests : IDisposable
{
    private const string Mallory = "S-1-5-21-1000-2000-3000-1101";
    private const string Alice = "S-1-5-21-1000-2000-3000-1001";
    private readonly TempDir _temp = new();
    private readonly ManualTime _time = new();
    private readonly List<WatchedRoot> _roots = [];

    public void Dispose()
    {
        _roots.ForEach(r => r.Dispose());
        _temp.Dispose();
    }

    private WatchedRoot Root(int id, string sid)
    {
        string path = Directory.CreateDirectory(Path.Combine(_temp.Path, id.ToString(System.Globalization.CultureInfo.InvariantCulture))).FullName;
        var handle = SafeTree.Open(path, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _)!;
        var root = new WatchedRoot(id, new WatchedFolder(path, WatchedFolderKind.Temp, sid), Core.Hashing.ExactPath.ToExtended(path)!, handle, 1,
            id.ToString(System.Globalization.CultureInfo.InvariantCulture), _time.Now);
        _roots.Add(root);
        return root;
    }

    [Fact]
    public void OneOwnersTwelveFloodedFolders_LeaveRoomForAnotherUser()
    {
        var options = new RealTimeOptions { MaxPendingFiles = 96, FolderShareDivisor = 8 }; // 12 per folder; 12 folders could take 144
        var queue = new RealTimeQueue(options);
        var flooded = Enumerable.Range(1, 12).Select(i => Root(i, Mallory)).ToArray();

        int queued = 0;
        foreach (var root in flooded)
        {
            for (int n = 0; n < 50; n++)
            {
                queued += queue.Offer(root, $"junk{n}.tmp", false, _time.Now) == OfferResult.Queued ? 1 : 0;
            }
        }

        var alice = Root(99, Alice);
        Assert.Equal(OfferResult.Queued, queue.Offer(alice, "invoice.exe", false, _time.Now));
        Assert.True(queued <= queue.OwnerShare.Files, $"{queued} files of one owner were queued; the owner share is {queue.OwnerShare.Files}");
        Assert.False(queue.OwnerUnderQuota(flooded[0]));
        Assert.True(queue.OwnerUnderQuota(alice)); // so Alice's folders' rescans still run while the queue is busy
    }
}
