using SapAV.Core.Text;

namespace SapAV.Core.Tests.Text;

public sealed class SafeTextTests
{
    [Theory]
    [InlineData("line1\r\nFAKE: Clean", "line1  FAKE: Clean")]
    [InlineData("a\u2028b\u2029c", "a b c")]
    [InlineData("a\u0085b\tc\u0000d", "a b c d")]
    [InlineData("  \n padded \u00A0 ", "padded")]
    public void SingleLine_TurnsLineBreaksAndControlsIntoSpaces(string raw, string expected)
    {
        Assert.Equal(expected, SafeText.SingleLine(raw, 100));
    }

    [Fact]
    public void SingleLine_ReplacesBidiControlsAndUnpairedSurrogates_KeepsValidPairs()
    {
        var result = SafeText.SingleLine("invoice\u202Eexe.pdf \uD800 \U0001F600", 100);

        Assert.Equal("invoice\uFFFDexe.pdf \uFFFD \U0001F600", result);
    }

    [Fact]
    public void SingleLine_CapsAtMaxLength_WithEllipsis_WithoutSplittingASurrogatePair()
    {
        var capped = SafeText.SingleLine(new string('a', 5000), 1024);
        var pair = SafeText.SingleLine("abc\U0001F600def", 5); // the cut would land inside the emoji

        Assert.Equal(1024, capped.Length);
        Assert.EndsWith(SafeText.Ellipsis.ToString(), capped);
        Assert.Equal("abc" + SafeText.Ellipsis, pair);
    }

    [Theory]
    [InlineData("a\r\nb\u202E c", true)]
    [InlineData("already clean", false)]
    public void BothFunctions_AreIdempotent(string raw, bool addLoneSurrogate)
    {
        // Lone surrogates can't be stored in attribute metadata (UTF-8), so add it here.
        raw = addLoneSurrogate ? raw + "\uDC00" : raw;
        var line = SafeText.SingleLine(raw + new string('x', 2000), 1024);
        var id = SafeText.Identifier(raw);

        Assert.Equal(line, SafeText.SingleLine(line, 1024));
        Assert.Equal(id, SafeText.Identifier(id));
    }

    [Fact]
    public void Identifier_ReplacesOnlyUnloggableCharacters_AndNeverCuts()
    {
        var path = @"C:\Users\x\Downloads\in" + "\u202E" + "fdp.exe" + "\n" + "\uD800" + new string('a', 40_000);

        var result = SafeText.Identifier(path);

        Assert.Equal(path.Length, result.Length);
        Assert.Contains('\u202E', result); // bidi kept as evidence; the JSON encoder escapes it
        Assert.DoesNotContain('\n', result);
        Assert.Equal('\uFFFD', result[path.IndexOf('\n')]);
        Assert.Equal('\uFFFD', result[path.IndexOf('\uD800')]);
    }
}
