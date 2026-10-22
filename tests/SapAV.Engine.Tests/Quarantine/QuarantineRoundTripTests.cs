using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Quarantine;
using SapAV.Engine.Alerts;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

public sealed class QuarantineRoundTripTests
{
    private static readonly DateTime Created = new(2024, 3, 4, 5, 6, 7, DateTimeKind.Utc);
    private static readonly DateTime Written = new DateTime(2025, 1, 2, 3, 4, 5, DateTimeKind.Utc).AddTicks(1234567);

    [Theory]
    [InlineData(false)]
    [InlineData(true)] // cross-volume code path (copy from handle, verify, delete by handle) through the test seam
    public async Task QuarantineThenRestore_KeepsContentPathTimesAttributesAndMotw(bool crossVolume)
    {
        using var ctx = new QuarantineTestContext(forceCrossVolume: crossVolume);
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile(@"dl\invoice.dat", content);
        var zone = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.test/invoice.dat\r\n"u8.ToArray();
        File.WriteAllBytes(path + ":Zone.Identifier", zone);
        File.SetCreationTimeUtc(path, Created);
        File.SetLastWriteTimeUtc(path, Written);
        File.SetAttributes(path, FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive);

        var quarantined = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));

        Assert.True(quarantined.Status == QuarantineStatus.Quarantined, $"{quarantined.Status}: {quarantined.Reason}");
        Assert.Equal(AlertAction.Quarantined, quarantined.Action);
        Assert.False(File.Exists(path));
        var entry = Assert.Single(ctx.Manager.List());
        Assert.Equal(QuarantineState.Quarantined, entry.State);
        Assert.Equal(path, entry.OriginalPath, ignoreCase: true);
        Assert.True(entry.HasMarkOfTheWeb);

        var restored = await ctx.Manager.RestoreAsync(entry.Id);

        Assert.True(restored.Status == RestoreStatus.Restored, $"{restored.Status}: {restored.Reason}");
        Assert.True(restored.Notes.Count == 0, string.Join(" | ", restored.Notes));
        Assert.Equal(path, restored.RestoredPath, ignoreCase: true);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Equal(Created, File.GetCreationTimeUtc(path));
        Assert.Equal(Written, File.GetLastWriteTimeUtc(path));
        Assert.Equal(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive, File.GetAttributes(path));
        Assert.Equal(zone, File.ReadAllBytes(path + ":Zone.Identifier"));
        Assert.Empty(ctx.Manager.List());
        Assert.Empty(ctx.StoreFiles());
    }

    [Fact]
    public async Task Restore_KeepsExplicitAclEntries()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("acl.bin", content);
        var info = new FileInfo(path);
        var security = info.GetAccessControl();
        var guests = new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null);
        security.AddAccessRule(new FileSystemAccessRule(guests, FileSystemRights.Read, AccessControlType.Deny));
        info.SetAccessControl(security);

        var q = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        var r = await ctx.Manager.RestoreAsync(q.Entry!.Id);

        Assert.Equal(RestoreStatus.Restored, r.Status);
        var rules = new FileInfo(path).GetAccessControl().GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>();
        Assert.Contains(rules, rule => rule.IdentityReference.Equals(guests) && rule.AccessControlType == AccessControlType.Deny);
    }

    [Fact]
    public async Task StoredFile_IsNeutralised_RandomNameNoExtension_NoExecuteAcl()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("payload.exe", content);

        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));

        string id = result.Entry!.Id;
        Assert.True(QuarantineItemId.IsValid(id));
        Assert.Equal(new[] { id, id + ".json" }.Order(), ctx.StoreFiles());
        var dataPath = Path.Combine(ctx.StoreRoot, id);
        Assert.Equal(string.Empty, Path.GetExtension(dataPath));
        var stored = File.ReadAllBytes(dataPath);
        Assert.Equal(content.Length + QuarantineContentTransform.HeaderLength, stored.Length);
        Assert.Equal("SAPAVQ01"u8.ToArray(), stored[..8]);
        Assert.Equal(-1, stored.AsSpan().IndexOf(QuarantineTestContext.Marker));
        Assert.NotEqual(content, stored[QuarantineContentTransform.HeaderLength..]);

        var rules = new FileInfo(dataPath).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule => Assert.Equal(0, (int)rule.FileSystemRights & 0x20 /* FILE_EXECUTE */));
    }

    [Theory]
    [InlineData(false)] // same size, different bytes
    [InlineData(true)]  // appended
    public async Task FileChangedSinceScan_IsRefused_AndLeftInPlace(bool append)
    {
        using var ctx = new QuarantineTestContext();
        var scanned = QuarantineTestContext.SampleContent();
        var now = (byte[])scanned.Clone();
        now[500] ^= 0xFF;
        if (append)
        {
            now = [.. scanned, 1, 2, 3];
        }

        var path = ctx.WriteFile("changed.exe", now);

        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, scanned));

        Assert.Equal(QuarantineStatus.ContentChanged, result.Status);
        Assert.Equal(AlertAction.QuarantineFailed, result.Action);
        Assert.Equal(now, File.ReadAllBytes(path));
        Assert.Empty(ctx.StoreFiles());
    }

    [Theory]
    [InlineData(FileShare.ReadWrite, FileAccess.ReadWrite)] // a writer has it open
    [InlineData(FileShare.Read, FileAccess.Read)]           // a reader that doesn't share delete
    public async Task LockedFile_IsQuarantineFailed_AndLeftInPlace(FileShare share, FileAccess access)
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("locked.exe", content);
        QuarantineResult result;
        using (new FileStream(path, FileMode.Open, access, share))
        {
            result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        }

        Assert.Equal(QuarantineStatus.Locked, result.Status);
        Assert.Equal(AlertAction.QuarantineFailed, result.Action);
        Assert.False(string.IsNullOrWhiteSpace(result.Reason));
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Empty(ctx.StoreFiles());
    }

    [Fact]
    public async Task HardLinkedFile_IsRefused()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("linked.exe", content);
        Assert.True(QuarantineTestContext.CreateHardLink(Path.Combine(ctx.Files, "other-name.exe"), path, IntPtr.Zero));

        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));

        Assert.Equal(QuarantineStatus.MultipleHardLinks, result.Status);
        Assert.True(File.Exists(path));
        Assert.Empty(ctx.StoreFiles());
    }

    [Fact]
    public async Task CleanOrNotScannedResult_IsNotEligible()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("clean.exe", content);
        var report = QuarantineTestContext.ReportFor(path, content);
        var clean = report with { Result = ScanResult.Clean(report.Result.Item, report.Result.Timestamp, report.Result.Sha256) };
        var notScanned = report with { Result = ScanResult.NotScanned(report.Result.Item, ScanStatus.Error, report.Result.Timestamp) };

        Assert.Equal(QuarantineStatus.NotEligible, (await ctx.Manager.QuarantineAsync(clean)).Status);
        Assert.Equal(QuarantineStatus.NotEligible, (await ctx.Manager.QuarantineAsync(notScanned)).Status);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task SecondOperationOnTheSameFile_WhileOneIsRunning_IsBusy()
    {
        using var gate = new ManualResetEventSlim();
        using var reached = new ManualResetEventSlim();
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("busy.exe", content);
        using var manager = ctx.Create(step =>
        {
            if (step == QuarantineStep.QuarantineJournalWritten)
            {
                reached.Set();
                gate.Wait(TimeSpan.FromSeconds(30));
            }
        });
        ctx.Manager.Dispose();
        manager.Initialize();

        var first = manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        Assert.True(reached.Wait(TimeSpan.FromSeconds(30)));
        var second = await manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        gate.Set();

        Assert.Equal(QuarantineStatus.Busy, second.Status);
        Assert.Equal(QuarantineStatus.Quarantined, (await first).Status);
    }

    [Fact]
    public async Task Restore_EmitsQuarantineRestoredAlert_Event3001()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("alert.exe", content);
        var q = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        Assert.Empty(ctx.Alerts.Alerts);

        await ctx.Manager.RestoreAsync(q.Entry!.Id);

        var alert = Assert.Single(ctx.Alerts.Alerts);
        Assert.Equal(AlertType.QuarantineRestored, alert.Type);
        Assert.Equal(AlertEventCatalog.QuarantineRestoredEventId, AlertEventCatalog.For(alert.Type).EventId);
        Assert.Equal(AlertAction.Restored, alert.Action);
        Assert.Equal(Verdict.Malicious, alert.Verdict);
        Assert.Equal(q.Entry.Sha256, alert.Sha256);
        Assert.Equal(path, alert.FilePath, ignoreCase: true);
        Assert.Equal("T1204.002", alert.TechniqueId);
        Assert.Contains(q.Entry.Id, alert.Reasons[0]);
    }

    [Fact]
    public async Task ListAndGet_ReturnEntries_WithoutKeys()
    {
        using var ctx = new QuarantineTestContext();
        var a = QuarantineTestContext.SampleContent();
        var b = QuarantineTestContext.SampleContent();
        var qa = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(ctx.WriteFile("a.exe", a), a), Guid.NewGuid());
        await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(ctx.WriteFile("b.exe", b), b));

        var list = ctx.Manager.List();
        var got = ctx.Manager.Get(qa.Entry!.Id);

        Assert.Equal(2, list.Count);
        Assert.All(list, e => Assert.Equal(QuarantineEntryIntegrity.Valid, e.Integrity));
        Assert.NotNull(got);
        Assert.Equal(qa.Entry.AlertId, got.AlertId);
        Assert.Null(ctx.Manager.Get("00000000000000000000000000000000"));
        Assert.Null(ctx.Manager.Get(@"..\..\x"));
        Assert.DoesNotContain(typeof(QuarantineEntry).GetProperties(), p => p.Name.Contains("Key", StringComparison.Ordinal));
    }

    [RequiresFact(Requires.SecondVolume)]
    public async Task RealCrossVolume_QuarantineAndRestore_RoundTrip()
    {
        using var other = new TempDir(TestRequirements.SecondVolumeFolder);
        using var ctx = new QuarantineTestContext(filesParent: other.Path);
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("x.exe", content);

        var q = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));
        Assert.Equal(QuarantineStatus.Quarantined, q.Status);
        Assert.False(File.Exists(path));
        var r = await ctx.Manager.RestoreAsync(q.Entry!.Id);

        Assert.Equal(RestoreStatus.Restored, r.Status);
        Assert.Equal(content, File.ReadAllBytes(path));
    }
}
