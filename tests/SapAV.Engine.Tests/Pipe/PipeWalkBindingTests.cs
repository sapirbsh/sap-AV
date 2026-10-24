using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>Review B4 H3 / M2: walking and opening are bound to handles; links on the way are refused, never followed.</summary>
public sealed class PipeWalkBindingTests
{
    [RequiresFact(Requires.Junctions)]
    public async Task AFolderSwappedForAJunctionDuringTheWalk_IsNotFollowed()
    {
        using var h = new HandlerHarness();
        for (int i = 0; i < 8; i++)
        {
            h.Jobs.Write($"f{i}.txt");
        }

        string sub = Directory.CreateDirectory(Path.Combine(h.Jobs.Root, "zsub")).FullName;
        File.WriteAllText(Path.Combine(sub, "mal-ordinary.bin"), "x");
        string secret = Directory.CreateDirectory(Path.Combine(h.Jobs.Base, "secret")).FullName;
        File.WriteAllText(Path.Combine(secret, "mal-secret-name.bin"), "x");
        HandlerHarness.Mark(secret); // the requester may not list it

        var gate = new TaskCompletionSource();
        h.Jobs.Broker.OnScan = async (_, _, ct) =>
        {
            await gate.Task.WaitAsync(ct);
            return null;
        };
        var user = h.Session(HandlerHarness.MarkedUser());
        var id = await h.CreateAsync(user);
        var job = h.Jobs.Service.Get(id)!;
        var blocked = new TaskCompletionSource();
        job.EnumeratorBlocked = () => blocked.TrySetResult();
        Assert.Equal(PipeStatus.Ok, (await h.SendAsync(user, PipeRequestKind.ScanStart, new JobRequest(id))).Status);
        await blocked.Task.WaitAsync(TimeSpan.FromSeconds(10)); // the root is listed, "zsub" not opened yet

        Directory.Delete(sub, recursive: true);
        Assert.Null(RawJunction.TryCreate(sub, @"\??\" + secret));
        gate.SetResult();
        await JobWait.Done(job);

        Assert.DoesNotContain(job.Results, r => r.Path.Contains("secret-name", StringComparison.Ordinal));
        Assert.DoesNotContain(job.Results, r => r.Path.Contains("ordinary", StringComparison.Ordinal));
        Assert.Equal(1, job.Skipped.SkippedLinks);
        Directory.Delete(sub); // remove the junction itself, never the target's content
    }

    [RequiresFact(Requires.Junctions)]
    public async Task RootsReachedThroughAJunction_AreRefused_ForUsersAndAdmins()
    {
        using var h = new HandlerHarness();
        string real = Directory.CreateDirectory(Path.Combine(h.Jobs.Base, "real", "inner")).FullName;
        File.WriteAllText(Path.Combine(real, "f.txt"), "x");
        string link = Path.Combine(h.Jobs.Root, "link");
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + Path.GetDirectoryName(real)));
        var user = h.Session(new FakeClientIdentity());
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        try
        {
            foreach (var session in new[] { user, admin })
            {
                foreach (var path in new[] { link, Path.Combine(link, "inner"), Path.Combine(link, "inner", "f.txt") })
                {
                    var reply = await h.SendAsync(session, PipeRequestKind.ScanCreate, new ScanCreateRequest([path]));
                    Assert.True(reply.Status == PipeStatus.InvalidPath, $"{path}: {reply.Status}");
                }
            }

            Assert.Empty(h.Jobs.Service.List());
            Assert.Equal(AccessDecision.Redirected, ClientAccess.CanReadOrList(new FakeClientIdentity(), Path.Combine(link, "inner")));
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [RequiresFact(Requires.Junctions)]
    public void TheSafeScanOpen_RefusesAFileBehindAJunction_AndOpensAPlainOne()
    {
        using var h = new HandlerHarness();
        string real = Directory.CreateDirectory(Path.Combine(h.Jobs.Base, "real2")).FullName;
        File.WriteAllText(Path.Combine(real, "f.txt"), "content");
        string plain = h.Jobs.Write("plain.txt");
        string link = Path.Combine(h.Jobs.Root, "link2");
        Assert.Null(RawJunction.TryCreate(link, @"\??\" + real));
        try
        {
            using var refused = SafeScanOpen.Open(new ScanItem(Path.Combine(link, "f.txt"), ScanTrigger.CustomScan), [], TimeProvider.System, out var report);
            using var opened = SafeScanOpen.Open(new ScanItem(plain, ScanTrigger.CustomScan), [], TimeProvider.System, out var none);

            Assert.Null(refused);
            Assert.NotEqual(ScanStatus.Scanned, report!.Result.Status);
            Assert.Equal(SapAV.Core.Hashing.HashFailureReason.NotRegularFile, report.Hash.FailureReason);
            Assert.NotNull(opened);
            Assert.Null(none);
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public async Task AUserJob_ListsAndScansThroughHandles_EndToEnd()
    {
        using var h = new HandlerHarness();
        string file = h.Jobs.Write(Path.Combine("a", "b", "mal-deep.bin"));
        var user = h.Session(new FakeClientIdentity());

        var job = await h.RunAsync(user);

        var result = Assert.Single(job.Results);
        Assert.Equal(file, result.Path);
        Assert.Equal(Verdict.Malicious, result.Verdict);
        Assert.NotNull(result.Sha256);
    }
}
