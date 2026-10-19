using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

public class DetectionTests
{
    [Fact]
    public void Constructor_StoresAllValues()
    {
        var detection = new Detection(
            Verdict.Suspicious,
            "Word spawned PowerShell",
            MitreTechniqueIds.SpearphishingAttachment,
            DetectionSource.Heuristic,
            [MitreTechniqueIds.PowerShell]);

        Assert.Equal(Verdict.Suspicious, detection.Verdict);
        Assert.Equal("Word spawned PowerShell", detection.Reason);
        Assert.Equal("T1566.001", detection.TechniqueId);
        Assert.Equal(DetectionSource.Heuristic, detection.Source);
        Assert.Equal(["T1059.001"], detection.SecondaryTechniqueIds);
    }

    [Fact]
    public void SecondaryTechniqueIds_DefaultToEmpty()
    {
        var detection = new Detection(Verdict.Malicious, "SHA-256 in blocklist", "T1204.002", DetectionSource.Blocklist);

        Assert.Empty(detection.SecondaryTechniqueIds);
    }

    [Fact]
    public void ValidTechniqueId_NotInCatalog_IsAccepted()
    {
        // YARA rules may carry their own mitre meta value.
        var detection = new Detection(Verdict.Malicious, "YARA rule X", "T1105", DetectionSource.Yara);

        Assert.Equal("T1105", detection.TechniqueId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("T1547.1")]
    [InlineData("t1547.001")]
    [InlineData("1547")]
    [InlineData("T1547.001 ")]
    public void Constructor_RejectsMalformedPrimaryTechniqueId(string? id)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new Detection(Verdict.Malicious, "reason", id!, DetectionSource.Yara));
        Assert.Equal(nameof(Detection.TechniqueId), ex.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("T59")]
    [InlineData(null)]
    public void Constructor_RejectsMalformedSecondaryTechniqueId(string? id)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new Detection(Verdict.Malicious, "reason", "T1204.002", DetectionSource.Yara, ["T1059.001", id!]));
        Assert.Equal(nameof(Detection.SecondaryTechniqueIds), ex.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Constructor_RejectsEmptyReason(string? reason)
    {
        Assert.ThrowsAny<ArgumentException>(
            () => new Detection(Verdict.Malicious, reason!, "T1204.002", DetectionSource.Blocklist));
    }

    [Theory]
    [InlineData(Verdict.Clean)]
    [InlineData((Verdict)42)]
    public void Constructor_RejectsCleanOrUndefinedVerdict(Verdict verdict)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new Detection(verdict, "reason", "T1204.002", DetectionSource.Blocklist));
    }

    [Fact]
    public void With_StillValidatesTechniqueIdAndVerdict()
    {
        var detection = new Detection(Verdict.Malicious, "reason", "T1204.002", DetectionSource.Blocklist);

        Assert.Throws<ArgumentException>(() => detection with { TechniqueId = "bogus" });
        Assert.Throws<ArgumentOutOfRangeException>(() => detection with { Verdict = Verdict.Clean });
    }

    [Fact]
    public void With_StillValidatesReasonAndSecondaryTechniqueIds()
    {
        var detection = new Detection(Verdict.Malicious, "reason", "T1204.002", DetectionSource.Blocklist);

        Assert.ThrowsAny<ArgumentException>(() => detection with { Reason = " " });
        var ex = Assert.Throws<ArgumentException>(() => detection with { SecondaryTechniqueIds = ["T1059.001", "bogus"] });
        Assert.Equal(nameof(Detection.SecondaryTechniqueIds), ex.ParamName);
        Assert.Throws<ArgumentNullException>(() => detection with { SecondaryTechniqueIds = null! });
    }

    [Fact]
    public void With_SecondaryTechniqueIds_AreCopied_NotAliased()
    {
        var detection = new Detection(Verdict.Suspicious, "reason", "T1566.001", DetectionSource.Heuristic);
        var source = new List<string> { "T1059.001" };

        var updated = detection with { SecondaryTechniqueIds = source };
        source.Add("not-an-id");

        Assert.Equal(["T1059.001"], updated.SecondaryTechniqueIds);
        Assert.Empty(detection.SecondaryTechniqueIds);
    }

    [Fact]
    public void SecondaryTechniqueIds_CannotBeMutatedThroughCast()
    {
        var detection = new Detection(Verdict.Suspicious, "reason", "T1566.001", DetectionSource.Heuristic, ["T1059.001"]);

        var asList = Assert.IsAssignableFrom<IList<string>>(detection.SecondaryTechniqueIds);
        Assert.Throws<NotSupportedException>(() => asList[0] = "bogus");
        Assert.Throws<NotSupportedException>(() => asList.Add("T1059.003"));
    }

    [Fact]
    public void SecondaryTechniqueIds_AreCopied_NotAliased()
    {
        var source = new List<string> { "T1059.001" };
        var detection = new Detection(Verdict.Suspicious, "reason", "T1566.001", DetectionSource.Heuristic, source);

        source.Add("not-an-id");

        Assert.Equal(["T1059.001"], detection.SecondaryTechniqueIds);
        Assert.IsNotType<string[]>(detection.SecondaryTechniqueIds);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(5)]
    [InlineData(int.MinValue)]
    public void Constructor_RejectsUndefinedSource(int raw)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => new Detection(Verdict.Malicious, "reason", "T1204.002", (DetectionSource)raw));
        Assert.Equal(nameof(Detection.Source), ex.ParamName);
    }

    [Fact]
    public void With_StillValidatesSource()
    {
        var detection = new Detection(Verdict.Malicious, "reason", "T1204.002", DetectionSource.Blocklist);

        Assert.Throws<ArgumentOutOfRangeException>(() => detection with { Source = (DetectionSource)99 });
    }

    [Fact]
    public void DetectionSource_HasNoSignatureMember()
    {
        // Authenticode never produces a detection by itself (ROADMAP.md, feature 2).
        Assert.False(Enum.TryParse<DetectionSource>("Signature", out _));
    }

    // --- Value equality ---

    private static Detection WithSecondaries(params string[] ids) =>
        new(Verdict.Suspicious, "Word spawned a script host", "T1566.001", DetectionSource.Heuristic, ids);

    [Fact]
    public void Equal_WhenAllValuesAndSecondariesMatch_EvenWithDifferentListInstances()
    {
        var a = WithSecondaries("T1059.001", "T1059.003");
        var b = new Detection(Verdict.Suspicious, "Word spawned a script host", "T1566.001",
            DetectionSource.Heuristic, new List<string> { "T1059.001", "T1059.003" });

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Equal_WhenBothHaveNoSecondaries()
    {
        var a = new Detection(Verdict.Malicious, "blocklist", "T1204.002", DetectionSource.Blocklist);
        var b = new Detection(Verdict.Malicious, "blocklist", "T1204.002", DetectionSource.Blocklist, []);

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void NotEqual_WhenSecondaryOrderOrContentDiffers()
    {
        var baseline = WithSecondaries("T1059.001", "T1059.003");

        Assert.NotEqual(baseline, WithSecondaries("T1059.003", "T1059.001"));
        Assert.NotEqual(baseline, WithSecondaries("T1059.001"));
        Assert.NotEqual(baseline, WithSecondaries("T1059.001", "T1059.005"));
        Assert.NotEqual(baseline, WithSecondaries());
    }

    [Fact]
    public void NotEqual_WhenAnyScalarDiffers()
    {
        var baseline = WithSecondaries("T1059.001");

        Assert.NotEqual(baseline, baseline with { Verdict = Verdict.Malicious });
        Assert.NotEqual(baseline, baseline with { Reason = "other" });
        Assert.NotEqual(baseline, baseline with { TechniqueId = "T1566.002" });
        Assert.NotEqual(baseline, baseline with { Source = DetectionSource.Yara });
        Assert.False(baseline.Equals(null));
        Assert.True(baseline != null);
    }
}
