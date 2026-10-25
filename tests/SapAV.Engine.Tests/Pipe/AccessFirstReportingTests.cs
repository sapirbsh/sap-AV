using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>
/// C1 / ROADMAP B4 L3: in a standard user's job the read-access check comes first, so a file the user can't read is
/// reported only as "you can't read it" (no lock state, size, exclusion, other file name, hash or verdict), and a scan
/// request can't be used to probe for names in folders the user can't list.
/// </summary>
public sealed class AccessFirstReportingTests
{
    [Fact]
    public async Task ALockedFileTheUserCantRead_IsReportedOnlyAsNoAccess_ALockedReadableOneAsLocked()
    {
        using var h = new HandlerHarness();
        string hidden = h.Jobs.Write("mal-hidden.bin");
        string mine = h.Jobs.Write("mal-mine.bin");
        HandlerHarness.Mark(hidden);
        using var lockHidden = new FileStream(hidden, FileMode.Open, FileAccess.Read, FileShare.None);
        using var lockMine = new FileStream(mine, FileMode.Open, FileAccess.Read, FileShare.None);
        var user = h.Session(HandlerHarness.MarkedUser());

        var job = await h.RunAsync(user);

        var noAccess = PipeMapping.Result(0, Assert.Single(job.Results, r => r.Path == hidden));
        Assert.Equal((ScanStatus.AccessDenied, NotScannedReason.NoAccess), (noAccess.Status, noAccess.NotScannedReason));
        Assert.DoesNotContain("lock", noAccess.Detail!, StringComparison.OrdinalIgnoreCase);
        Assert.Null(noAccess.Sha256);
        Assert.Empty(noAccess.Reasons);
        var locked = PipeMapping.Result(1, Assert.Single(job.Results, r => r.Path == mine));
        Assert.Equal((ScanStatus.Locked, NotScannedReason.Locked), (locked.Status, locked.NotScannedReason));
    }

    [Fact]
    public async Task AFileTheUserCantRead_IsNoAccess_EvenWhenTheEngineWouldHaveSkippedItForAnotherReason()
    {
        using var h = new HandlerHarness();
        string hidden = h.Jobs.Write("big.bin", new string('x', 4096));
        HandlerHarness.Mark(hidden);
        h.Jobs.RemoteProbe = new Scanning.FakeRemoteProbe("big.bin"); // would be refused as remote; access comes first
        var user = h.Session(HandlerHarness.MarkedUser());

        var job = await h.RunAsync(user);

        var result = Assert.Single(job.Results);
        Assert.Equal(ScanSkipReason.NoAccess, result.SkipReason);
        Assert.False(result.RequesterCouldRead);
        Assert.Equal(0, h.Jobs.Broker.Calls);
    }

    [Fact]
    public async Task ARootInAFolderTheUserCantList_GetsTheSameAnswer_WhetherItExistsOrNot()
    {
        using var h = new HandlerHarness();
        string secret = Directory.CreateDirectory(Path.Combine(h.Jobs.Root, "secret")).FullName;
        string exists = Path.Combine(secret, "salary.xlsx");
        File.WriteAllText(exists, "x");
        HandlerHarness.Mark(secret);
        HandlerHarness.Mark(exists);
        var user = h.Session(HandlerHarness.MarkedUser());

        var present = await h.SendAsync(user, PipeRequestKind.ScanCreate, new ScanCreateRequest([exists]));
        var missing = await h.SendAsync(user, PipeRequestKind.ScanCreate, new ScanCreateRequest([Path.Combine(secret, "nothing.xlsx")]));

        Assert.Equal(PipeStatus.NotFound, present.Status);
        Assert.Equal(present.Status, missing.Status);
        Assert.Equal(present.Error!.Replace("1", "", StringComparison.Ordinal), missing.Error!.Replace("1", "", StringComparison.Ordinal));
    }
}
