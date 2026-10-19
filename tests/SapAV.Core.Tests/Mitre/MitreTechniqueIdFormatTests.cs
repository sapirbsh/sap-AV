using SapAV.Core.Mitre;

namespace SapAV.Core.Tests.Mitre;

public class MitreTechniqueIdFormatTests
{
    [Theory]
    [InlineData("T1059")]
    [InlineData("T1547.001")]
    [InlineData("T9999.999")]
    [InlineData("T0000")]
    public void IsValid_AcceptsWellFormedIds(string id)
    {
        Assert.True(MitreTechniqueIdFormat.IsValid(id));
        MitreTechniqueIdFormat.EnsureValid(id, "id");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("T")]
    [InlineData("T123")]
    [InlineData("T12345")]
    [InlineData("T1547.")]
    [InlineData("T1547.1")]
    [InlineData("T1547.0011")]
    [InlineData("T1547.001.001")]
    [InlineData("t1547.001")]
    [InlineData("1547.001")]
    [InlineData("TA0003")]
    [InlineData("T1547-001")]
    [InlineData(" T1547.001")]
    [InlineData("T1547.001 ")]
    [InlineData("T1547.001\n")]
    [InlineData("T١٥٤٧")] // Arabic-Indic digits must not count as digits
    public void IsValid_RejectsMalformedIds(string? id)
    {
        Assert.False(MitreTechniqueIdFormat.IsValid(id));
        var ex = Assert.Throws<ArgumentException>(() => MitreTechniqueIdFormat.EnsureValid(id, "techniqueId"));
        Assert.Equal("techniqueId", ex.ParamName);
    }

    // --- TryNormalize (lenient parsing of rule-author input) ---

    public static TheoryData<string, string[]> NormalizeCases => new()
    {
        { "T1059.001", ["T1059.001"] },
        { "t1059.001", ["T1059.001"] },                                 // lowercase
        { "  T1059.001\t", ["T1059.001"] },                             // surrounding whitespace
        { "T1566.001,T1059.001", ["T1566.001", "T1059.001"] },          // comma list
        { "T1566.001, t1059.001 ,T1059.003", ["T1566.001", "T1059.001", "T1059.003"] },
        { "T1566.001 T1059.001", ["T1566.001", "T1059.001"] },          // space-separated
        { "T1566.001;T1059.001\nT1486", ["T1566.001", "T1059.001", "T1486"] },
        { "T1059.001, t1059.001, T1059.001", ["T1059.001"] },           // duplicates dropped
        { "garbage, T1486, T12, TA0003, T1547.1", ["T1486"] },          // invalid tokens dropped
        { ",,, T1091 ,,", ["T1091"] },                                  // empty tokens
        { "T1486 T1091 T1486", ["T1486", "T1091"] },                    // order kept, first wins
    };

    [Theory]
    [MemberData(nameof(NormalizeCases))]
    public void TryNormalize_ReturnsCleanIds(string raw, string[] expected)
    {
        Assert.True(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));
        Assert.Equal(expected, ids);
        Assert.All(ids, id => Assert.True(MitreTechniqueIdFormat.IsValid(id)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(", ;\t\n")]
    [InlineData("garbage")]
    [InlineData("T12 T1547.1 TA0003 1547")]
    [InlineData("T1547.001)")]
    [InlineData("\0￿\uD800")] // control chars, noncharacter, lone surrogate
    public void TryNormalize_NoValidIds_ReturnsFalseAndEmpty(string? raw)
    {
        Assert.False(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));
        Assert.Empty(ids);
    }

    [Fact]
    public void TryNormalize_ResultIsReadOnly()
    {
        MitreTechniqueIdFormat.TryNormalize("T1486", out var ids);

        var asList = Assert.IsAssignableFrom<IList<string>>(ids);
        Assert.Throws<NotSupportedException>(() => asList.Add("T1091"));
    }

    // --- SelectOrDefault (primary + secondaries with fallback) ---

    [Fact]
    public void SelectOrDefault_FirstValidIdIsPrimary_RestAreSecondary()
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault("t1566.001, bogus, T1059.001 T1059.001");

        Assert.Equal("T1566.001", selection.PrimaryId);
        Assert.Equal(["T1059.001"], selection.SecondaryIds);
    }

    [Fact]
    public void SelectOrDefault_SingleId_HasNoSecondaries()
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault("T1486");

        Assert.Equal("T1486", selection.PrimaryId);
        Assert.Empty(selection.SecondaryIds);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("garbage")]
    [InlineData("T12, TA0003")]
    public void SelectOrDefault_NothingValid_FallsBackToMaliciousFile(string? raw)
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault(raw);

        Assert.Equal(MitreTechniqueIds.MaliciousFile, selection.PrimaryId);
        Assert.Equal("T1204.002", selection.PrimaryId);
        Assert.Empty(selection.SecondaryIds);
    }

    [Fact]
    public void SelectOrDefault_UsesCustomFallback()
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault("nope", MitreTechniqueIds.SoftwarePacking);

        Assert.Equal("T1027.002", selection.PrimaryId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bogus")]
    [InlineData("t1204.002")]
    public void SelectOrDefault_RejectsMalformedFallback(string fallback)
    {
        Assert.Throws<ArgumentException>(() => MitreTechniqueIdFormat.SelectOrDefault("T1486", fallback));
    }

    [Fact]
    public void SelectOrDefault_ResultIsAcceptedByDetection()
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault(" t1566.001 , T1059.001 ");

        var detection = new SapAV.Core.Models.Detection(
            SapAV.Core.Models.Verdict.Suspicious, "YARA rule", selection.PrimaryId,
            SapAV.Core.Models.DetectionSource.Yara, selection.SecondaryIds);

        Assert.Equal("T1566.001", detection.TechniqueId);
        Assert.Equal(["T1059.001"], detection.SecondaryTechniqueIds);
    }
}
