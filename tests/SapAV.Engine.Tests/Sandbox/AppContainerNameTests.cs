using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>Review H1 (defence in depth): the default AppContainer name carries a per-install random suffix.</summary>
public sealed class AppContainerNameTests : IDisposable
{
    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"))).FullName;

    public void Dispose() => TempDir.DeleteTree(_dir);

    [Fact]
    public void Suffix_IsRandom_StoredOnce_AndStable()
    {
        var a = Directory.CreateDirectory(Path.Combine(_dir, "a")).FullName;
        var b = Directory.CreateDirectory(Path.Combine(_dir, "b")).FullName;

        string first = AppContainerName.FromDirectory(a);

        Assert.True(AppContainerName.IsValidName(first), first);
        Assert.True(first.Length <= 64, "AppContainer names are limited to 64 characters");
        Assert.Equal(first, AppContainerName.FromDirectory(a)); // same install, same SID
        Assert.NotEqual(first, AppContainerName.FromDirectory(b)); // another install can't predict it
        Assert.Single(Directory.GetFiles(a)); // no temp files left
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-hex-at-all")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF")] // upper case is not what we write
    public void InvalidIdFile_IsReplacedWithANewRandomSuffix(string content)
    {
        File.WriteAllText(Path.Combine(_dir, AppContainerName.IdFileName), content);

        string name = AppContainerName.FromDirectory(_dir);

        Assert.True(AppContainerName.IsValidName(name), name);
        Assert.Equal(name, AppContainerName.FromDirectory(_dir));
    }

    [Fact]
    public void ExplicitName_Wins() =>
        Assert.Equal("sap-AV.ScanWorker.Test.x", AppContainerName.Resolve(new SandboxOptions { AppContainerName = "sap-AV.ScanWorker.Test.x" }));
}
