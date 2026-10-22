using SapAV.Core.Quarantine;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Quarantine;

/// <summary>
/// A crash (the step hook throws; handles close as on process exit) at each journal step, then an engine restart:
/// recovery must end in a consistent state with at least one intact copy, and only ever in the expected one.
/// </summary>
public sealed class QuarantineRecoveryTests
{
    public enum Outcome
    {
        /// <summary>No item; the original is back/still in place, intact.</summary>
        RolledBack,

        /// <summary>One Quarantined item that restores to the original content; the original path is empty.</summary>
        Quarantined,
    }

    [Theory]
    [InlineData(nameof(QuarantineStep.QuarantineJournalWritten), false, Outcome.RolledBack)]
    [InlineData(nameof(QuarantineStep.QuarantineStaged), false, Outcome.Quarantined)]          // finished from the staged raw file
    [InlineData(nameof(QuarantineStep.QuarantineStoredCopyWritten), false, Outcome.Quarantined)] // staged raw file removed
    [InlineData(nameof(QuarantineStep.QuarantineSourceDeleted), false, Outcome.Quarantined)]
    [InlineData(nameof(QuarantineStep.QuarantineJournalWritten), true, Outcome.RolledBack)]
    [InlineData(nameof(QuarantineStep.QuarantineStoredCopyWritten), true, Outcome.RolledBack)]  // original never deleted
    [InlineData(nameof(QuarantineStep.QuarantineSourceDeleted), true, Outcome.Quarantined)]
    public async Task CrashDuringQuarantine_RecoversToAConsistentState(string crashAtName, bool crossVolume, Outcome expected)
    {
        var crashAt = Enum.Parse<QuarantineStep>(crashAtName);
        using var ctx = new QuarantineTestContext(forceCrossVolume: crossVolume);
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("crash.exe", content);
        ctx.Restart(Crash(crashAt));

        await Assert.ThrowsAsync<SimulatedCrashException>(() => ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content)));
        var actions = ctx.Restart();

        Assert.Single(actions);
        if (expected == Outcome.RolledBack)
        {
            Assert.Equal(content, File.ReadAllBytes(path));
            Assert.Empty(ctx.Manager.List());
            Assert.Empty(ctx.StoreFiles());
            return;
        }

        Assert.False(File.Exists(path));
        var entry = Assert.Single(ctx.Manager.List());
        Assert.Equal(QuarantineState.Quarantined, entry.State);
        Assert.Equal(new[] { entry.Id, entry.Id + ".json" }.Order(), ctx.StoreFiles()); // no staged / partial left
        Assert.Equal(RestoreStatus.Restored, (await ctx.Manager.RestoreAsync(entry.Id)).Status);
        Assert.Equal(content, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(nameof(QuarantineStep.RestoreJournalWritten), false)]
    [InlineData(nameof(QuarantineStep.RestoreTempWritten), false)]   // the partial temp file is removed
    [InlineData(nameof(QuarantineStep.RestoreRenamed), true)]        // restored file kept, item kept too (duplicate, never lost)
    [InlineData(nameof(QuarantineStep.RestoreMarkedRestored), true)]
    [InlineData(nameof(QuarantineStep.RestoreDataDeleted), true)]
    public async Task CrashDuringRestore_RecoversToAConsistentState(string crashAtName, bool fileRestored)
    {
        var crashAt = Enum.Parse<QuarantineStep>(crashAtName);
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("r.exe", content);
        var id = (await ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content))).Entry!.Id;
        ctx.Restart(Crash(crashAt));

        await Assert.ThrowsAsync<SimulatedCrashException>(() => ctx.Manager.RestoreAsync(id));
        var actions = ctx.Restart();

        Assert.Single(actions);
        Assert.DoesNotContain(Directory.GetFiles(ctx.Files), f => Path.GetFileName(f).StartsWith("~sapav-restore-", StringComparison.Ordinal));
        Assert.Equal(fileRestored, File.Exists(path));
        if (fileRestored)
        {
            Assert.Equal(content, File.ReadAllBytes(path));
        }

        bool itemKept = crashAt is QuarantineStep.RestoreJournalWritten or QuarantineStep.RestoreTempWritten or QuarantineStep.RestoreRenamed;
        if (itemKept)
        {
            Assert.Equal(QuarantineState.Quarantined, Assert.Single(ctx.Manager.List()).State);
        }
        else
        {
            Assert.Empty(ctx.Manager.List());
            Assert.Empty(ctx.StoreFiles());
        }
    }

    [Fact]
    public async Task NotRestorable_WhileJournalSaysAnOperationIsInProgress()
    {
        using var ctx = new QuarantineTestContext();
        var content = QuarantineTestContext.SampleContent();
        var path = ctx.WriteFile("p.exe", content);
        ctx.Restart(Crash(QuarantineStep.QuarantineStaged));
        await Assert.ThrowsAsync<SimulatedCrashException>(() => ctx.Manager.QuarantineAsync(QuarantineTestContext.ReportFor(path, content)));

        // Same manager, no restart: the item is still Quarantining.
        var entry = Assert.Single(ctx.Manager.List());
        Assert.Equal(QuarantineState.Quarantining, entry.State);
        Assert.Equal(RestoreStatus.NotRestorable, (await ctx.Manager.RestoreAsync(entry.Id)).Status);
    }

    private static Action<QuarantineStep> Crash(QuarantineStep at) => step =>
    {
        if (step == at)
        {
            throw new SimulatedCrashException(step.ToString());
        }
    };
}
