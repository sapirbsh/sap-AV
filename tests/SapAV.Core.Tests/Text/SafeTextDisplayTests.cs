using SapAV.Core.Text;

namespace SapAV.Core.Tests.Text;

public sealed class SafeTextDisplayTests
{
    [Theory]
    [InlineData("a\u200Bb", "a\uFFFDb")]
    [InlineData("a\u2060\u2064b", "a\uFFFD\uFFFDb")]
    [InlineData("\uFEFFx\uFFF9y", "\uFFFDx\uFFFDy")]
    [InlineData("soft\u00ADhyphen", "soft\uFFFDhyphen")]
    [InlineData("tag\U000E0041\U000E007F!", "tag\uFFFD\uFFFD!")]
    public void Display_MapsInvisibleFormatCharactersToReplacement(string raw, string expected)
    {
        Assert.Equal(expected, SafeText.Display(raw, 100));
    }

    [Fact]
    public void Display_KeepsJoinersAndEmoji_AndIsIdempotent()
    {
        const string text = "family \U0001F468\u200D\U0001F469 ok";
        Assert.Equal(text, SafeText.Display(text, 100));
        string once = SafeText.Display("x\u200B\u202Ey\r\nz", 100);
        Assert.Equal(once, SafeText.Display(once, 100));
        Assert.Equal("x\uFFFD\uFFFDy  z", once);
    }

    [Fact]
    public void ContainsHiddenCharacters_FlagsBidiAndInvisible()
    {
        Assert.True(SafeText.ContainsHiddenCharacters("inv\u202Efdp.exe"));
        Assert.True(SafeText.ContainsHiddenCharacters("a\u200Bb"));
        Assert.False(SafeText.ContainsHiddenCharacters(@"C:\Users\me\file.txt"));
    }
}
