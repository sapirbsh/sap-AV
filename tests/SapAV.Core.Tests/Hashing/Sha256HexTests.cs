using SapAV.Core.Hashing;

namespace SapAV.Core.Tests.Hashing;

public class Sha256HexTests
{
    private const string Lower = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    [Fact]
    public void TryNormalize_LowercasesValidInput()
    {
        Assert.True(Sha256Hex.TryNormalize(Lower.ToUpperInvariant(), out var normalized));
        Assert.Equal(Lower, normalized);

        Assert.True(Sha256Hex.TryNormalize(Lower, out var same));
        Assert.Same(Lower, same); // already lowercase: no allocation
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a")]   // 63
    [InlineData("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad0")] // 65
    [InlineData("ga7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]  // non-hex
    [InlineData(" a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]  // not trimmed
    [InlineData("２a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")] // fullwidth digit
    public void TryNormalize_RejectsMalformed(string? value)
    {
        Assert.False(Sha256Hex.IsValid(value));
        Assert.False(Sha256Hex.TryNormalize(value, out var normalized));
        Assert.Null(normalized);
    }
}
