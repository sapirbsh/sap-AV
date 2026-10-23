using SapAV.Core.Hashing;

namespace SapAV.Core.Tests.Hashing;

/// <summary>B3 review H1: exact paths keep trailing dots and spaces; only "." / ".." and separators are resolved.</summary>
public sealed class ExactPathTests
{
    [Theory]
    [InlineData(@"C:\a\.\b\..\evil.exe.", @"\\?\C:\a\evil.exe.")]
    [InlineData(@"C:/a//sap-AV \x", @"\\?\C:\a\sap-AV \x")]
    [InlineData(@"\\server\share\dir.\f", @"\\?\UNC\server\share\dir.\f")]
    [InlineData(@"\\?\C:\a\b.", @"\\?\C:\a\b.")]
    [InlineData(@"C:\", @"\\?\C:\")]
    public void ToExtended_KeepsNamesExactly(string path, string expected) => Assert.Equal(expected, ExactPath.ToExtended(path));

    [Theory]
    [InlineData(@"relative\x")]
    [InlineData(@"C:relative")]
    [InlineData(@"\\.\pipe\x")]
    [InlineData(@"\\?\GLOBALROOT\Device\x")]
    [InlineData(@"\\?\C:\a\..\b")] // extended paths are taken verbatim: a ".." there is refused, not resolved
    [InlineData(@"\\server")]
    public void ToExtended_RefusesWhatItCantMakeExact(string path) => Assert.Null(ExactPath.ToExtended(path));

    [Fact]
    public void NeedsExtended_OnlyForNamesEndingInADotOrSpace_AndForOpeningIsPlainWhenLossless()
    {
        Assert.True(ExactPath.NeedsExtended(@"C:\a\evil.exe."));
        Assert.True(ExactPath.NeedsExtended(@"C:\dir \f.txt"));
        Assert.False(ExactPath.NeedsExtended(@"C:\a\..\b\.\f.txt"));
        Assert.Equal(@"C:\a\f.txt", ExactPath.ForOpening(@"\\?\C:\a\f.txt"));
        Assert.Equal(@"\\?\C:\a\f.", ExactPath.ForOpening(@"\\?\C:\a\f."));
        Assert.Equal(@"\\srv\share\f", ExactPath.StripPrefix(@"\\?\UNC\srv\share\f"));
    }
}
