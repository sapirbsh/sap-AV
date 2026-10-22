using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Quarantine;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

/// <summary>
/// B2 review follow-ups: the staged file is locked down and hard links are re-checked before the delete (M1), and
/// recovery never rolls back onto a different file at the original path (L1).
/// </summary>
public sealed class QuarantineFollowUpTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HardLinkAddedDuringTheMove_IsRefused_AndTheFileIsBackAndReadable(bool crossVolume)
    {
        using var ctx = new QuarantineTestContext(forceCrossVolume: crossVolume);
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("late-link.dat", content);
        var extraLink = Path.Combine(ctx.Files, "extra-link.dat");
        ctx.Restart(step =>
        {
            if (step == QuarantineStep.QuarantineStoredCopyWritten)
            {
                // Link to wherever the file is right now (the user folder, or the store's staged name).
                var current = crossVolume ? path : Directory.GetFiles(ctx.StoreRoot, "*.staged").Single();
                Assert.True(QuarantineTestContext.CreateHardLink(extraLink, current, IntPtr.Zero));
            }
        });

        var result = await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content));

        Assert.Equal(QuarantineStatus.MultipleHardLinks, result.Status);
        Assert.Equal(content, File.ReadAllBytes(path));
        Assert.Empty(ctx.StoreFiles());
        Assert.Empty(ctx.Manager.List());
    }

    [Fact]
    public async Task StagedFile_GetsAProtectedDacl_WithoutImplicitOwnerRights_OrExecute()
    {
        FileSystemAccessRule[]? rules = null;
        bool? isProtected = null;
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("staged-acl.dat", content);
        ctx.Restart(step =>
        {
            if (step == QuarantineStep.QuarantineStoredCopyWritten)
            {
                var security = new FileInfo(Directory.GetFiles(ctx.StoreRoot, "*.staged").Single()).GetAccessControl(AccessControlSections.Access);
                isProtected = security.AreAccessRulesProtected;
                rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            }
        });

        Assert.Equal(QuarantineStatus.Quarantined, (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Status);

        Assert.True(isProtected);
        Assert.NotNull(rules);
        var ownerRights = new SecurityIdentifier("S-1-3-4");
        Assert.Contains(rules, r => r.IdentityReference.Equals(ownerRights) && r.FileSystemRights == FileSystemRights.ReadPermissions);
        Assert.All(rules, r => Assert.Equal(0, (int)r.FileSystemRights & 0x20 /* FILE_EXECUTE */));
        Assert.All(rules.Where(r => !r.IdentityReference.Equals(ownerRights)), r => Assert.Contains(r.IdentityReference,
            new IdentityReference[] { QuarantineAccessPolicy.LocalSystem, QuarantineAccessPolicy.Administrators, QuarantineTestContext.CurrentUser }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Recovery_NeverRollsBackOntoADifferentFileAtTheOriginalPath(bool crossVolume)
    {
        using var ctx = new QuarantineTestContext(forceCrossVolume: crossVolume);
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("l1.dat", content);
        ctx.Restart(step =>
        {
            if (step == QuarantineStep.QuarantineSourceDeleted)
            {
                throw new SimulatedCrashException(step.ToString());
            }
        });
        await Assert.ThrowsAsync<SimulatedCrashException>(() => ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content)));

        File.WriteAllBytes(path, content); // a new file with the same bytes, not the quarantined object
        ctx.Restart();

        Assert.Equal(QuarantineState.Quarantined, Assert.Single(ctx.Manager.List()).State);
        Assert.Equal(content, File.ReadAllBytes(path));
    }
}
