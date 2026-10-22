using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Quarantine;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

public sealed class QuarantineRestoreSecurityTests
{
    [Fact]
    public async Task TamperedMetadata_OriginalPathChanged_IsRefused_AndNothingWritten()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("t.exe", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;
        var elsewhere = Directory.CreateDirectory(Path.Combine(ctx.Base, "elsewhere")).FullName;

        // Rewrite the payload to point the restore somewhere else, keeping the old HMAC.
        var metadataPath = Path.Combine(ctx.StoreRoot, id + ".json");
        var envelope = JsonNode.Parse(File.ReadAllBytes(metadataPath))!;
        var payload = JsonNode.Parse(Convert.FromBase64String(envelope["payload"]!.GetValue<string>()))!;
        payload["OriginalPath"] = Path.Combine(elsewhere, "t.exe");
        envelope["payload"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        File.WriteAllText(metadataPath, envelope.ToJsonString());

        var result = await ctx.Manager.RestoreAsync(id);

        Assert.Equal(RestoreStatus.MetadataInvalid, result.Status);
        Assert.Empty(Directory.GetFileSystemEntries(elsewhere));
        Assert.False(File.Exists(path));
        Assert.Equal(QuarantineEntryIntegrity.Invalid, ctx.Manager.Get(id)!.Integrity);
        Assert.Empty(ctx.Alerts.Alerts);
    }

    [Fact]
    public async Task MetadataCopiedOntoAnotherItem_IsRefused()
    {
        using var ctx = new QuarantineTestContext();
        var a = QuarantineTestContext.SampleContent();
        var b = QuarantineTestContext.SampleContent(seed: 2);
        var idA = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(ctx.WriteFile("a.exe", a), a))).Entry!.Id;
        var idB = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(ctx.WriteFile("b.exe", b), b))).Entry!.Id;

        File.Copy(Path.Combine(ctx.StoreRoot, idA + ".json"), Path.Combine(ctx.StoreRoot, idB + ".json"), overwrite: true);

        Assert.Equal(RestoreStatus.MetadataInvalid, (await ctx.Manager.RestoreAsync(idB)).Status);
        Assert.False(File.Exists(Path.Combine(ctx.Files, "b.exe")));
    }

    [Fact]
    public async Task TamperedStoredContent_IsRefused()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("c.exe", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;
        var data = Path.Combine(ctx.StoreRoot, id);
        var bytes = File.ReadAllBytes(data);
        bytes[^1] ^= 0x55;
        File.WriteAllBytes(data, bytes);

        Assert.Equal(RestoreStatus.StoredContentInvalid, (await ctx.Manager.RestoreAsync(id)).Status);
        Assert.False(File.Exists(path));
    }

    [RequiresTheory(Requires.Junctions)]
    [InlineData(false)] // the file's own folder replaced by a junction
    [InlineData(true)]  // a folder higher up the chain replaced by a junction
    public async Task TargetFolderReplacedByJunction_IsRefused_AndNothingWrittenThere(bool higherUp)
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile(@"top\sub\j.exe", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;

        var victim = Directory.CreateDirectory(Path.Combine(ctx.Base, "victim")).FullName; // stands in for System32
        Directory.CreateDirectory(Path.Combine(victim, "sub"));
        var replaced = higherUp ? Path.Combine(ctx.Files, "top") : Path.Combine(ctx.Files, "top", "sub");
        Directory.Delete(replaced, recursive: true);
        Assert.Null(RawJunction.TryCreate(replaced, @"\??\" + (higherUp ? victim : Path.Combine(victim, "sub"))));

        var result = await ctx.Manager.RestoreAsync(id);

        Assert.Equal(RestoreStatus.TargetRedirected, result.Status);
        Assert.Empty(Directory.GetFiles(victim, "*", SearchOption.AllDirectories));
        Assert.Equal(QuarantineState.Quarantined, ctx.Manager.Get(id)!.State);
        Assert.Empty(ctx.Alerts.Alerts);
    }

    [Fact]
    public async Task TargetExists_IsNotOverwritten_RestoredUnderNewName()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("report.pdf.exe", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;
        var newer = "the user's new file"u8.ToArray();
        File.WriteAllBytes(path, newer);
        File.WriteAllBytes(Path.Combine(ctx.Files, "report.pdf (restored 1).exe"), newer);

        var result = await ctx.Manager.RestoreAsync(id);

        Assert.Equal(RestoreStatus.Restored, result.Status);
        Assert.Equal(Path.Combine(ctx.Files, "report.pdf (restored 2).exe"), result.RestoredPath, ignoreCase: true);
        Assert.Equal(newer, File.ReadAllBytes(path));
        Assert.Equal(content, File.ReadAllBytes(result.RestoredPath!));
    }

    [Fact]
    public async Task EveryCandidateNameTaken_FailsWithTargetExists_NothingOverwritten()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("x.bin", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;
        for (int n = 0; n <= QuarantinePath.MaxRestoreSuffix; n++)
        {
            File.WriteAllBytes(Path.Combine(ctx.Files, QuarantinePath.RestoredName("x.bin", n)), [(byte)n]);
        }

        var result = await ctx.Manager.RestoreAsync(id);

        Assert.Equal(RestoreStatus.TargetExists, result.Status);
        Assert.Equal(QuarantinePath.MaxRestoreSuffix + 1, Directory.GetFiles(ctx.Files).Length); // no temp file left
        Assert.Equal([0], File.ReadAllBytes(path));
        Assert.Equal(QuarantineState.Quarantined, ctx.Manager.Get(id)!.State);
    }

    [Fact]
    public async Task TargetFolderDeleted_FailsWithoutRecreatingIt()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile(@"gone\x.exe", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;
        Directory.Delete(Path.Combine(ctx.Files, "gone"));

        Assert.Equal(RestoreStatus.TargetDirectoryMissing, (await ctx.Manager.RestoreAsync(id)).Status);
        Assert.False(Directory.Exists(Path.Combine(ctx.Files, "gone")));
    }

    [Theory]
    [InlineData("")]
    [InlineData(@"..\..\windows")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF")] // uppercase: not an ID we create
    public async Task InvalidItemId_IsNotFound(string id)
    {
        using var ctx = new QuarantineTestContext();
        Assert.Equal(RestoreStatus.NotFound, (await ctx.Manager.RestoreAsync(id)).Status);
    }
}
