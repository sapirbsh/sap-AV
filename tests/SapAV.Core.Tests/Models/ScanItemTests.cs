using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

public class ScanItemTests
{
    [Fact]
    public void Constructor_StoresPathAndTrigger()
    {
        var item = new ScanItem(@"C:\Users\test\Downloads\file.exe", ScanTrigger.RealTime);

        Assert.Equal(@"C:\Users\test\Downloads\file.exe", item.Path);
        Assert.Equal(ScanTrigger.RealTime, item.Trigger);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"relative\file.exe")]
    [InlineData("file.exe")]
    [InlineData(@"C:file.exe")]
    [InlineData(@"\Users\test\file.exe")] // rooted on the current drive, not fully qualified
    [InlineData(@"..\file.exe")]
    public void Constructor_RejectsEmptyOrRelativePath(string path)
    {
        Assert.Throws<ArgumentException>(() => new ScanItem(path, ScanTrigger.CustomScan));
    }

    [Fact]
    public void Constructor_RejectsNullPath()
    {
        Assert.Throws<ArgumentNullException>(() => new ScanItem(null!, ScanTrigger.CustomScan));
    }

    [Theory]
    [InlineData(@"\\server\share\file.exe")]       // UNC (network share)
    [InlineData(@"\\?\C:\very\long\path\file.exe")] // extended-length path
    [InlineData(@"D:\file.exe")]
    public void Constructor_AcceptsOtherFullyQualifiedForms(string path)
    {
        Assert.Equal(path, new ScanItem(path, ScanTrigger.FullScan).Path);
    }

    [Fact]
    public void With_StillValidatesPath()
    {
        var item = new ScanItem(@"C:\a.txt", ScanTrigger.QuickScan);

        Assert.Throws<ArgumentException>(() => item with { Path = "a.txt" });
        Assert.Throws<ArgumentException>(() => item with { Path = "" });
        Assert.Throws<ArgumentNullException>(() => item with { Path = null! });
    }

    [Fact]
    public void Records_WithSameValues_AreEqual()
    {
        Assert.Equal(
            new ScanItem(@"C:\a.txt", ScanTrigger.FullScan),
            new ScanItem(@"C:\a.txt", ScanTrigger.FullScan));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(5)]
    [InlineData(int.MaxValue)]
    public void Constructor_RejectsUndefinedTrigger(int raw)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new ScanItem(@"C:\a.txt", (ScanTrigger)raw));
        Assert.Equal(nameof(ScanItem.Trigger), ex.ParamName);
    }

    [Fact]
    public void With_StillValidatesTrigger()
    {
        var item = new ScanItem(@"C:\a.txt", ScanTrigger.QuickScan);

        Assert.Throws<ArgumentOutOfRangeException>(() => item with { Trigger = (ScanTrigger)99 });
    }
}
