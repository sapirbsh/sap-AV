using SapAV.Core.Scanning;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Scanning;

public sealed class FileIdentityTests
{
    [Fact]
    public void Capture_GivesAStableFileIdAndTheFinalPath_AndDistinguishesFiles()
    {
        using var dir = new TempDirectory();
        var a = dir.WriteFile("a.bin", [1, 2, 3]);
        var b = dir.WriteFile("b.bin", [1, 2, 3]);

        var a1 = Capture(a);
        var a2 = Capture(a);
        var bId = Capture(b);

        Assert.NotNull(a1);
        Assert.Matches("^[0-9a-f]{32}$", a1.FileId);
        Assert.Equal(Path.GetFullPath(a), a1.FinalPath, ignoreCase: true);
        Assert.True(a1.IsSameObject(a2));
        Assert.False(a1.IsSameObject(bId));
        Assert.False(a1.IsSameObject(null));
    }

    [Fact]
    public void Capture_FollowsTheObjectAcrossARename_NotThePath()
    {
        using var dir = new TempDirectory();
        var path = dir.WriteFile("x.bin", [9]);
        var before = Capture(path);
        File.Move(path, dir.File("moved.bin"));
        File.WriteAllBytes(path, [9]);

        Assert.True(before!.IsSameObject(Capture(dir.File("moved.bin"))));
        Assert.False(before.IsSameObject(Capture(path)));
    }

    private static FileIdentity? Capture(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return FileIdentity.TryCapture(handle);
    }
}
