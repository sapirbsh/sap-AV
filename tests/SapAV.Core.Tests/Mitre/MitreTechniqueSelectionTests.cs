using SapAV.Core.Mitre;

namespace SapAV.Core.Tests.Mitre;

public class MitreTechniqueSelectionTests
{
    [Fact]
    public void Constructor_StoresValidIds()
    {
        var selection = new MitreTechniqueSelection("T1566.001", ["T1059.001", "T1059.003"]);

        Assert.Equal("T1566.001", selection.PrimaryId);
        Assert.Equal(["T1059.001", "T1059.003"], selection.SecondaryIds);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("t1566.001")]
    [InlineData("T1566.1")]
    [InlineData("bogus")]
    public void Constructor_RejectsMalformedPrimary(string? primary)
    {
        var ex = Assert.Throws<ArgumentException>(() => new MitreTechniqueSelection(primary!, []));
        Assert.Equal(nameof(MitreTechniqueSelection.PrimaryId), ex.ParamName);
    }

    [Fact]
    public void Constructor_RejectsNullSecondaryList()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new MitreTechniqueSelection("T1486", null!));
        Assert.Equal(nameof(MitreTechniqueSelection.SecondaryIds), ex.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("T59")]
    [InlineData("t1059.001")]
    public void Constructor_RejectsMalformedSecondary(string? secondary)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new MitreTechniqueSelection("T1486", ["T1059.001", secondary!]));
        Assert.Equal(nameof(MitreTechniqueSelection.SecondaryIds), ex.ParamName);
    }

    [Fact]
    public void With_StillValidates()
    {
        var selection = new MitreTechniqueSelection("T1486", []);

        Assert.Throws<ArgumentException>(() => selection with { PrimaryId = "bogus" });
        Assert.Throws<ArgumentException>(() => selection with { SecondaryIds = ["bogus"] });
    }

    [Fact]
    public void SecondaryIds_AreCopied_AndReadOnly()
    {
        var source = new List<string> { "T1059.001" };
        var selection = new MitreTechniqueSelection("T1566.001", source);

        source.Add("not-an-id");

        Assert.Equal(["T1059.001"], selection.SecondaryIds);
        var asList = Assert.IsAssignableFrom<IList<string>>(selection.SecondaryIds);
        Assert.Throws<NotSupportedException>(() => asList[0] = "bogus");
    }

    [Fact]
    public void Equal_WhenSameIds_EvenWithDifferentListInstances()
    {
        var a = new MitreTechniqueSelection("T1566.001", ["T1059.001", "T1059.003"]);
        var b = new MitreTechniqueSelection("T1566.001", new List<string> { "T1059.001", "T1059.003" });

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void NotEqual_WhenPrimaryOrSecondaryOrderOrContentDiffers()
    {
        var baseline = new MitreTechniqueSelection("T1566.001", ["T1059.001", "T1059.003"]);

        Assert.NotEqual(baseline, new MitreTechniqueSelection("T1566.002", ["T1059.001", "T1059.003"]));
        Assert.NotEqual(baseline, new MitreTechniqueSelection("T1566.001", ["T1059.003", "T1059.001"]));
        Assert.NotEqual(baseline, new MitreTechniqueSelection("T1566.001", ["T1059.001"]));
        Assert.NotEqual(baseline, new MitreTechniqueSelection("T1566.001", []));
        Assert.False(baseline.Equals(null));
    }

    [Fact]
    public void SelectOrDefault_ResultsCompareByValue()
    {
        Assert.Equal(
            new MitreTechniqueSelection("T1566.001", ["T1059.001"]),
            MitreTechniqueIdFormat.SelectOrDefault("t1566.001, T1059.001"));
        Assert.Equal(
            MitreTechniqueIdFormat.SelectOrDefault(null),
            MitreTechniqueIdFormat.SelectOrDefault("garbage"));
    }
}
