using SapAV.Core.Scanning;

namespace SapAV.Core.Tests.Scanning;

public sealed class ScanPathPolicyTests
{
    [Theory]
    [InlineData(@"\\.\C:\x", ScanPathRejection.DeviceNamespace)]
    [InlineData(@"\\.\PhysicalDrive0", ScanPathRejection.DeviceNamespace)]
    [InlineData(@"\\?\Volume{12345678-1234-1234-1234-123456789012}\x", ScanPathRejection.DeviceNamespace)]
    [InlineData(@"//?/C:/x", ScanPathRejection.DeviceNamespace)]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\x", ScanPathRejection.GlobalRoot)]
    [InlineData(@"\\.\globalroot\Device\Null", ScanPathRejection.GlobalRoot)]
    [InlineData(@"\\server\share\x", ScanPathRejection.Network)]
    [InlineData(@"//server/share/x", ScanPathRejection.Network)]
    [InlineData(@"\\?\UNC\server\share\x", ScanPathRejection.Network)]
    [InlineData(@"C:\dir\file.txt:secret", ScanPathRejection.AlternateDataStream)]
    [InlineData(@"C:\dir\file.txt::$DATA", ScanPathRejection.AlternateDataStream)]
    [InlineData(@"\\?\C:\dir\f:s", ScanPathRejection.AlternateDataStream)]
    [InlineData(@"C:\dir\NUL", ScanPathRejection.ReservedDeviceName)]
    [InlineData(@"C:\dir\con.txt", ScanPathRejection.ReservedDeviceName)]
    [InlineData(@"C:\COM1 .log\x", ScanPathRejection.ReservedDeviceName)]
    [InlineData("\\\\?\\C:\\dir\\lpt\u00B9", ScanPathRejection.ReservedDeviceName)]
    [InlineData("C:\\dir\0\\x", ScanPathRejection.InvalidCharacter)]
    [InlineData(@"C:\dir\*.exe", ScanPathRejection.InvalidCharacter)]
    [InlineData(@"C:\dir\a?b", ScanPathRejection.InvalidCharacter)]
    [InlineData(@"relative\x", ScanPathRejection.NotFullyQualified)]
    [InlineData(@"C:x", ScanPathRejection.NotFullyQualified)]
    [InlineData(@"\rooted\x", ScanPathRejection.NotFullyQualified)]
    [InlineData(@"\\?\C:\a\..\b", ScanPathRejection.Malformed)]
    [InlineData("   ", ScanPathRejection.Empty)]
    public void RejectsEachRefusedForm(string path, ScanPathRejection expected)
    {
        var decision = ScanPathPolicy.Evaluate(path);

        Assert.False(decision.IsAllowed);
        Assert.Equal(expected, decision.Rejection);
        Assert.Null(decision.NormalizedPath);
    }

    [Fact]
    public void RejectsNtNamespaceAndNull()
    {
        Assert.False(ScanPathPolicy.Evaluate(@"\??\C:\x").IsAllowed);
        Assert.Equal(ScanPathRejection.Empty, ScanPathPolicy.Evaluate(null).Rejection);
    }

    [Theory]
    [InlineData(@"C:\Users\me\Downloads", @"C:\Users\me\Downloads")]
    [InlineData(@"C:/Users//me/./Downloads/", @"C:\Users\me\Downloads")]
    [InlineData(@"C:\Users\me\..\..\Windows\x", @"C:\Windows\x")]
    [InlineData(@"C:\..\..\x", @"C:\x")]
    [InlineData(@"\\?\C:\Users\me", @"C:\Users\me")]
    [InlineData(@"C:\", @"C:\")]
    public void NormalisesDotsAndSeparatorsLexically(string path, string expected)
    {
        var decision = ScanPathPolicy.Evaluate(path);

        Assert.True(decision.IsAllowed, decision.Reason);
        Assert.Equal(expected, decision.NormalizedPath);
    }

    [Theory]
    [InlineData(@"C:\dir\evil.exe.", @"\\?\C:\dir\evil.exe.")]
    [InlineData(@"C:\dir\x \y", @"\\?\C:\dir\x \y")]
    [InlineData(@"\\?\C:\dir\sap-AV.", @"\\?\C:\dir\sap-AV.")]
    public void KeepsTrailingDotsAndSpacesExactly(string path, string expected)
    {
        var decision = ScanPathPolicy.Evaluate(path);

        Assert.True(decision.IsAllowed, decision.Reason);
        Assert.Equal(expected, decision.NormalizedPath);
    }

    [Fact]
    public void RejectsOverlongNames()
    {
        Assert.Equal(ScanPathRejection.TooLong, ScanPathPolicy.Evaluate(@"C:\" + new string('a', 256)).Rejection);
        Assert.Equal(ScanPathRejection.TooLong, ScanPathPolicy.Evaluate(@"C:\" + new string('a', 40_000)).Rejection);
        Assert.True(ScanPathPolicy.Evaluate(@"C:\" + new string('a', 255)).IsAllowed);
    }

    [Theory]
    [InlineData("nul", true)]
    [InlineData("NUL.tar.gz", true)]
    [InlineData("nul ", true)]
    [InlineData("null", false)]
    [InlineData("console.txt", false)]
    [InlineData("COM10", false)]
    public void ReservedDeviceNames(string component, bool reserved)
    {
        Assert.Equal(reserved, ScanPathPolicy.IsReservedDeviceName(component));
    }
}
