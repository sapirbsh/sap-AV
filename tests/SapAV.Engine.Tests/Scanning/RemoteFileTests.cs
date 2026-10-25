using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.Pipe;
using SapAV.Engine.Tests.TestSupport;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>Says "remote" for every handle whose final path contains <see cref="Marker"/>.</summary>
internal sealed class FakeRemoteProbe(string marker = "remote") : IRemoteFileProbe
{
    public string Marker { get; } = marker;

    public int Calls;

    public FileLocation Classify(SafeHandle handle)
    {
        Interlocked.Increment(ref Calls);
        string? path = Core.Hashing.NativeFile.TryGetFinalDosPath((SafeFileHandle)handle);
        return path is not null && path.Contains(Marker, StringComparison.OrdinalIgnoreCase) ? FileLocation.Remote : FileLocation.Local;
    }
}

/// <summary>C1 / ROADMAP A2 W-A: files and folders on remote file systems are refused unless the job allows them.</summary>
public sealed class RemoteFileTests
{
    [Theory]
    [InlineData(true, 0, "Remote")]
    [InlineData(false, 87, "Local")] // ERROR_INVALID_PARAMETER: local file systems don't implement the class
    [InlineData(false, 1, "Local")]
    [InlineData(false, 5, "Unknown")] // anything unexpected fails closed
    public void Classifier_MapsTheQueryOutcome(bool succeeded, int error, string expected) =>
        Assert.Equal(expected, RemoteFileProbe.Classify(succeeded, error).ToString());

    [Fact]
    public void RealProbe_SaysLocal_ForATempFileAndFolder()
    {
        using var temp = new TempDir();
        var file = Path.Combine(temp.Path, "local.txt");
        File.WriteAllText(file, "x");
        using var fileHandle = File.OpenHandle(file);
        using var folder = SafeTree.Open(temp.Path, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out _, out _);

        Assert.Equal(FileLocation.Local, RemoteFileProbe.Instance.Classify(fileHandle));
        Assert.Equal(FileLocation.Local, RemoteFileProbe.Instance.Classify(folder!));
    }

    [Theory]
    [InlineData(@"\\localhost\C$\Windows\win.ini")]
    [InlineData(@"\\?\UNC\server\share\x.bin")]
    public void SafeTree_RefusesUncPaths_BeforeOpeningAnything_UnlessAllowed(string path)
    {
        using var handle = SafeTree.Open(path, SafeTree.InspectAccess, SafeTree.ShareAll, 0, out var failure, out int error);

        Assert.Null(handle);
        Assert.Equal(SafeTreeFailure.Remote, failure);
        Assert.Equal(0, error); // refused from the string: no open was attempted
    }

    [Fact]
    public async Task RemoteFile_IsNotScanned_WithTheRemoteReason_AndNeverReachesTheScanner()
    {
        using var h = new ScanJobHarness();
        h.RemoteProbe = new FakeRemoteProbe();
        h.Write("mal-remote.bin");
        h.Write("local.txt");

        var (job, _) = h.Start();
        await JobWait.Done(job);

        var refused = Assert.Single(job.Results);
        Assert.Equal((ScanStatus.Error, ScanSkipReason.RemoteFile), (refused.Status, refused.SkipReason));
        Assert.Null(refused.Verdict);
        Assert.Null(refused.Sha256);
        Assert.Equal(1, h.Broker.Calls); // only local.txt
        Assert.Equal(NotScannedReason.RemoteFile, Engine.Pipe.PipeMapping.Result(0, refused).NotScannedReason);
    }

    [Fact]
    public async Task RemoteFolder_IsNotListed()
    {
        using var h = new ScanJobHarness();
        h.RemoteProbe = new FakeRemoteProbe("remote-share");
        h.Write(@"remote-share\mal-inside.bin");
        h.Write("local.txt");

        var (job, _) = h.Start();
        await JobWait.Done(job);

        Assert.Empty(job.Results);
        Assert.Equal(1, job.Skipped.UnreadableFolders);
        Assert.Contains(job.Warnings, w => w.Message.Contains("RemoteFolder", StringComparison.Ordinal));
        Assert.Equal(1, h.Broker.Calls);
    }

    [Fact]
    public async Task AJobThatAllowsRemoteFiles_ScansThem()
    {
        using var h = new ScanJobHarness();
        h.RemoteProbe = new FakeRemoteProbe();
        h.Write("mal-remote.bin");

        var job = h.Service.Create(new ScanJobRequest([h.Root], ScanTrigger.CustomScan) { AllowRemoteFiles = true });
        h.Service.Start(job.Id);
        await JobWait.Done(job);

        Assert.Equal(Verdict.Malicious, Assert.Single(job.Results).Verdict);
    }

    [RequiresFact(Requires.AdminShare)]
    public async Task AdminShare_IsRefusedByDefault_AndScannedOnlyWhenAllowed()
    {
        using var h = new ScanJobHarness();
        var local = h.Write("mal-share.bin");
        string share = TestRequirements.ToAdminShare(local);

        var refusedJob = h.Service.Create(new ScanJobRequest([share], ScanTrigger.CustomScan));
        h.Service.Start(refusedJob.Id);
        await JobWait.Done(refusedJob);
        var allowedJob = h.Service.Create(new ScanJobRequest([share], ScanTrigger.CustomScan) { AllowRemoteFiles = true });
        h.Service.Start(allowedJob.Id);
        await JobWait.Done(allowedJob);

        var refused = Assert.Single(refusedJob.Results);
        Assert.Equal(ScanSkipReason.RemoteFile, refused.SkipReason);
        Assert.Null(refused.Sha256);
        var allowed = Assert.Single(allowedJob.Results);
        Assert.Equal(Verdict.Malicious, allowed.Verdict); // a real SMB handle, scanned because the job allowed it
        using var smb = File.OpenHandle(share);
        Assert.Equal(FileLocation.Remote, RemoteFileProbe.Instance.Classify(smb)); // the handle-level check sees it
    }

    [RequiresFact(Requires.AdminShare)]
    public async Task AdminShare_ThroughThePipe_IsInvalidPath_EvenForAdmins_UnlessAllowed()
    {
        using var h = new HandlerHarness();
        string share = TestRequirements.ToAdminShare(h.Jobs.Write("x.txt"));
        var admin = h.Session(new FakeClientIdentity(isAdmin: true));

        var byDefault = await h.SendAsync(admin, PipeRequestKind.ScanCreate, new ScanCreateRequest([share]));
        var allowed = await h.SendAsync(admin, PipeRequestKind.ScanCreate, new ScanCreateRequest([share], AllowRemote: true));

        Assert.Equal(PipeStatus.InvalidPath, byDefault.Status);
        Assert.Equal(PipeStatus.Ok, allowed.Status);
    }

    [Fact]
    public async Task AStandardUser_MayNotAskForRemoteFiles()
    {
        using var h = new HandlerHarness();
        var user = h.Session(new FakeClientIdentity());

        var reply = await h.SendAsync(user, PipeRequestKind.ScanCreate, new ScanCreateRequest([h.Jobs.Root], AllowRemote: true));

        Assert.Equal(PipeStatus.AccessDenied, reply.Status);
        Assert.Empty(h.Jobs.Service.List());
    }

    [Theory]
    [InlineData(@"\\server\share\dir\file.txt", @"\\server\share\dir\file.txt")]
    [InlineData(@"\\?\UNC\server\share\a\..\b", null)] // '..' in an extended path is refused
    [InlineData(@"\\server\share\x.txt:stream", null)]
    [InlineData(@"\\server\share\NUL", null)]
    [InlineData(@"\\.\PhysicalDrive0", null)]
    [InlineData(@"\\server", null)]
    public void Policy_AcceptsUncOnlyWhenNetworkIsAllowed(string path, string? expected)
    {
        var allowed = ScanPathPolicy.Evaluate(path, allowNetwork: true);

        Assert.False(ScanPathPolicy.Evaluate(path).IsAllowed);
        Assert.Equal(expected, allowed.IsAllowed ? allowed.NormalizedPath : null);
    }
}
