using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Checks;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// Section C follow-up review H-D: any standard user can make their own folder look like a cloud placeholder (a cloud / HSM
/// reparse tag plus Offline, set with FSCTL_SET_REPARSE_POINT without elevation). Only a sync root the Cloud Files API confirms
/// may make a scan skip one; outside every sync root it is walked and scanned, and a skip that can't be confirmed makes the phase
/// Incomplete.
/// </summary>
/// <remarks>
/// The look comes from the test seam (Offline counts as the look), the answer from the probe each test gives: the real
/// Cloud Files API on the real folder handle, or a fixed one. A real user-tagged folder can't be used: with a cloud tag and
/// Offline the cloud filter refuses every open of it (ERROR_CLOUD_FILE_METADATA_CORRUPT, so it couldn't be removed again), and
/// with an HSM tag nothing inside opens without an HSM filter (ERROR_CANT_ACCESS_FILE).
/// </remarks>
public sealed class PlaceholderSyncRootTests
{
    private const int DrivePhase = 2; // programs, autostarts, drives

    private static async Task<(ScanJob Job, FullScanHarness Scan, string Inside)> RunWithAPlaceholderLookingFolder(ISyncRootProbe probe, FullScanHarness f)
    {
        f.Jobs.SyncRoots = probe;
        var inside = f.Write(@"Looks like OneDrive\payload.exe");
        string folder = Path.GetDirectoryName(inside)!;
        using var look = FilePlaceholder.OfflineIsPlaceholderForTests();
        File.SetAttributes(folder, FileAttributes.Directory | FileAttributes.Offline);
        try
        {
            return (await f.RunAsync(), f, inside);
        }
        finally
        {
            File.SetAttributes(folder, FileAttributes.Directory);
        }
    }

    [RequiresFact(Requires.CloudFilesApi)]
    public async Task AFolderThatLooksLikeAPlaceholder_OutsideAnySyncRoot_IsWalked_AndItsFilesScanned()
    {
        using var f = new FullScanHarness();

        var (job, _, inside) = await RunWithAPlaceholderLookingFolder(CloudSyncRootProbe.Instance, f); // the real API, on the real handle

        Assert.True(f.WasScanned(inside));
        Assert.Equal(ScanPhaseState.Completed, job.Phases[DrivePhase].State);
        Assert.Contains(job.Phases[DrivePhase].Notes, n => n.Contains("outside any sync root were walked and scanned", StringComparison.Ordinal));
    }

    [Fact]
    public async Task InAConfirmedSyncRoot_ThePlaceholderFolderIsntListed_AndThePhaseIsComplete()
    {
        using var f = new FullScanHarness();
        var local = f.Write("local.txt");

        var (job, _, inside) = await RunWithAPlaceholderLookingFolder(new FixedSyncRoot(SyncRootStatus.InSyncRoot), f);

        Assert.False(f.WasScanned(inside));
        Assert.True(f.WasScanned(local));
        Assert.Equal(ScanPhaseState.Completed, job.Phases[DrivePhase].State);
        Assert.Contains(job.Phases[DrivePhase].Notes, n => n.Contains("1 cloud placeholders (in a sync root", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WhenTheSyncRootCantBeConfirmed_TheFolderIsSkipped_AndThePhaseIsIncomplete()
    {
        using var f = new FullScanHarness();

        var (job, _, inside) = await RunWithAPlaceholderLookingFolder(new FixedSyncRoot(SyncRootStatus.Unknown), f);

        Assert.False(f.WasScanned(inside));
        Assert.Equal(ScanPhaseState.Incomplete, job.Phases[DrivePhase].State);
        Assert.Contains(job.Phases[DrivePhase].Notes, n => n.Contains("without a confirmed sync root", StringComparison.Ordinal));
    }

    [Fact]
    public void ThePlaceholderLook_IsDecidedByTheSyncRoot_OnTheHandle()
    {
        using var temp = new TempDir();
        string path = Path.Combine(temp.Path, "f.bin");
        File.WriteAllBytes(path, [1]);
        using var handle = File.OpenHandle(path);
        const FileAttributes look = FileAttributes.Offline | FileAttributes.ReparsePoint;
        const uint cloud = 0x9000101A;

        Assert.Equal(PlaceholderKind.OutsideSyncRoot, FilePlaceholder.Classify(handle, look, cloud, new FixedSyncRoot(SyncRootStatus.NotInSyncRoot)));
        Assert.Equal(PlaceholderKind.InSyncRoot, FilePlaceholder.Classify(handle, look, cloud, new FixedSyncRoot(SyncRootStatus.InSyncRoot)));
        Assert.Equal(PlaceholderKind.Unconfirmed, FilePlaceholder.Classify(handle, look, cloud, new FixedSyncRoot(SyncRootStatus.Unknown)));
        Assert.Equal(PlaceholderKind.None, FilePlaceholder.Classify(handle, FileAttributes.Offline, 0, new FixedSyncRoot(SyncRootStatus.InSyncRoot)));
        Assert.False(FilePlaceholder.IsConfirmedPlaceholder(handle, look, cloud, new FixedSyncRoot(SyncRootStatus.NotInSyncRoot)));
    }

    [Theory]
    [InlineData(0, SyncRootStatus.InSyncRoot)]
    [InlineData(unchecked((int)0x80070186), SyncRootStatus.NotInSyncRoot)] // ERROR_CLOUD_FILE_NOT_IN_SYNC_ROOT
    [InlineData(unchecked((int)0x80070005), SyncRootStatus.Unknown)] // access denied: can't tell
    public void TheApiAnswer_IsClassified_OnlyNotInSyncRootRulesItOut(int hresult, SyncRootStatus expected)
    {
        Assert.Equal(expected, CloudSyncRootProbe.Classify(hresult));
    }

    private sealed class FixedSyncRoot(SyncRootStatus status) : ISyncRootProbe
    {
        public SyncRootStatus Check(SafeFileHandle handle) => status;
    }
}
