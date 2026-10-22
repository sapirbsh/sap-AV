using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Alerts;
using SapAV.Core.Quarantine;
using SapAV.Core.Scanning;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Tests.Quarantine;

/// <summary>
/// The quarantine acts only on the file object that was scanned (B2 review C1): identity, path and no reparse points.
/// </summary>
public sealed class QuarantineIdentityTests
{
    [RequiresFact(Requires.Junctions)]
    public async Task FolderSwappedForAJunctionAfterTheScan_IsRefused_AndTheOtherFileIsUntouched()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile(@"x\invoice.dat", content);
        var report = QuarantineTestContext.ReportFor(path, content);

        // A same-content file elsewhere, standing in for a file the user can't delete themselves.
        var victimDir = Directory.CreateDirectory(Path.Combine(ctx.Base, "victim")).FullName;
        var victim = Path.Combine(victimDir, "invoice.dat");
        File.WriteAllBytes(victim, content);
        File.Delete(path);
        Directory.Delete(Path.Combine(ctx.Files, "x"));
        Assert.Null(RawJunction.TryCreate(Path.Combine(ctx.Files, "x"), @"\??\" + victimDir));

        var result = await ctx.Manager.QuarantineAsync(report);

        Assert.Contains(result.Status, new[] { QuarantineStatus.PathRedirected, QuarantineStatus.IdentityMismatch });
        Assert.Equal(AlertAction.QuarantineFailed, result.Action);
        Assert.Equal(content, File.ReadAllBytes(victim));
        Assert.Empty(ctx.StoreFiles());
    }

    [RequiresFact(Requires.Junctions)]
    public async Task ScanThatWentThroughAJunction_IsPathRedirected()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var real = ctx.WriteFile(@"real\a.dat", content);
        var alias = Path.Combine(ctx.Base, "alias");
        Assert.Null(RawJunction.TryCreate(alias, @"\??\" + Path.Combine(ctx.Files, "real")));

        // The scanner's handle reports the real final path, not the requested alias path.
        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(Path.Combine(alias, "a.dat"), content));

        Assert.Equal(QuarantineStatus.PathRedirected, result.Status);
        Assert.Equal(content, File.ReadAllBytes(real));
        Assert.Empty(ctx.StoreFiles());
    }

    [Fact]
    public async Task SamePathSameContent_ButAReplacedFile_IsIdentityMismatch()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("swap.dat", content);
        var report = QuarantineTestContext.ReportFor(path, content);
        File.Delete(path);
        File.WriteAllBytes(path, content); // a new file object with the same name and bytes

        var result = await ctx.Manager.QuarantineAsync(report);

        Assert.Equal(QuarantineStatus.IdentityMismatch, result.Status);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Empty(ctx.StoreFiles());
    }

    [Fact]
    public async Task ReportWithoutIdentity_IsNotEligible()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("noid.dat", content);

        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content, identity: null));

        Assert.Equal(QuarantineStatus.NotEligible, result.Status);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task HandleOverload_QuarantinesThroughTheScanHandle_WithoutReopening()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("viahandle.dat", content);
        using var handle = OpenForQuarantine(path);
        var report = QuarantineTestContext.ReportFor(path, content, FileIdentity.TryCapture(handle));

        var result = await ctx.Manager.QuarantineHandleAsync(handle, report);

        Assert.Equal(QuarantineStatus.Quarantined, result.Status);
        Assert.False(handle.IsClosed); // the caller's handle is not closed
        Assert.False(File.Exists(path));
        handle.Dispose();
        Assert.Equal(RestoreStatus.Restored, (await ctx.Manager.RestoreAsync(result.Entry!.Id)).Status);
        Assert.Equal(content, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task HandleOverload_WithoutDeleteAccess_IsNotEligible()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("readonlyhandle.dat", content);
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        var result = await ctx.Manager.QuarantineHandleAsync(handle, QuarantineTestContext.ReportFor(path, content, FileIdentity.TryCapture(handle)));

        Assert.Equal(QuarantineStatus.NotEligible, result.Status);
        Assert.True(File.Exists(path));
    }

    private static Microsoft.Win32.SafeHandles.SafeFileHandle OpenForQuarantine(string path)
    {
        var handle = SafeFile.TryOpen(path, N.GenericRead | N.Delete | N.WriteDac, N.ShareRead | N.ShareDelete,
            out var directory, out _, out _, out var reason);
        directory?.Dispose();
        Assert.True(handle is not null, reason);
        return handle;
    }
}
