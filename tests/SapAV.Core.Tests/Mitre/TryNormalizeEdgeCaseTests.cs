using System.Diagnostics;
using System.Globalization;
using System.Text;
using SapAV.Core.Mitre;

namespace SapAV.Core.Tests.Mitre;

/// <summary>
/// Edge cases for <see cref="MitreTechniqueIdFormat.TryNormalize"/> / <see cref="MitreTechniqueIdFormat.SelectOrDefault"/>
/// not covered by <see cref="MitreTechniqueIdFormatTests"/>. YARA meta values come from rule authors, so input
/// can be arbitrarily long or oddly formatted; parsing must never throw and must stay linear.
/// </summary>
public class TryNormalizeEdgeCaseTests
{
    [Fact]
    public void DuplicatesOfDifferentCase_FirstOccurrenceWins_OrderKept()
    {
        Assert.True(MitreTechniqueIdFormat.TryNormalize("t1486 T1091 T1486 t1091 T1059.001", out var ids));

        Assert.Equal(["T1486", "T1091", "T1059.001"], ids);
    }

    [Fact]
    public void LowercaseDuplicateOfPrimary_IsNotRepeatedAsSecondary()
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault("T1566.001, t1566.001, T1059.001");

        Assert.Equal("T1566.001", selection.PrimaryId);
        Assert.Equal(["T1059.001"], selection.SecondaryIds);
    }

    [Theory]
    [InlineData(" T1486 T1091　")] // NBSP, em space, ideographic space
    [InlineData("\r\nT1486\r\nT1091\r\n")]
    [InlineData(";;T1486;,;T1091,,")]
    public void UnicodeWhitespaceAndMixedSeparators_Split(string raw)
    {
        Assert.True(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));

        Assert.Equal(["T1486", "T1091"], ids);
    }

    [Fact]
    public void ZeroWidthSpace_IsNotASeparator_TokenRejected()
    {
        // U+200B is not whitespace per char.IsWhiteSpace, so "T1486​" is one (invalid) token.
        Assert.False(MitreTechniqueIdFormat.TryNormalize("T1486​", out var ids));
        Assert.Empty(ids);
    }

    [Fact]
    public void OnlySeparators_VeryLong_ReturnsFalse()
    {
        var raw = string.Concat(Enumerable.Repeat(", ;\t\n", 200_000)); // 1,000,000 chars

        Assert.False(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));
        Assert.Empty(ids);
        Assert.Equal(MitreTechniqueIds.MaliciousFile, MitreTechniqueIdFormat.SelectOrDefault(raw).PrimaryId);
    }

    [Fact]
    public void SingleHugeToken_ReturnsFalse_WithoutThrowing()
    {
        var raw = "T" + new string('1', 1_000_000);

        Assert.False(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));
        Assert.Empty(ids);
    }

    [Fact]
    public void VeryLongInput_ManyDuplicates_DedupedQuickly()
    {
        var raw = string.Concat(Enumerable.Repeat("t1059.001, T1486; ", 100_000)); // ~1.8M chars

        var sw = Stopwatch.StartNew();
        Assert.True(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));
        sw.Stop();

        Assert.Equal(["T1059.001", "T1486"], ids);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"TryNormalize took {sw.Elapsed}");
    }

    [Fact]
    public void VeryLongInput_ManyDistinctIds_AllKeptInOrder()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 10_000; i++)
        {
            sb.Append('T').Append(i.ToString("D4", CultureInfo.InvariantCulture)).Append(',');
        }

        Assert.True(MitreTechniqueIdFormat.TryNormalize(sb.ToString(), out var ids));

        Assert.Equal(10_000, ids.Count);
        Assert.Equal("T0000", ids[0]);
        Assert.Equal("T9999", ids[^1]);
    }

    [Fact]
    public void ValidIdAtVeryEndOfLongGarbage_IsFound()
    {
        var raw = new string('x', 500_000) + " t1091";

        Assert.True(MitreTechniqueIdFormat.TryNormalize(raw, out var ids));
        Assert.Equal(["T1091"], ids);
    }

    [Fact]
    public void Normalization_IsCultureInvariant_UnderTurkishCulture()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            Assert.True(MitreTechniqueIdFormat.TryNormalize("t1486", out var ids));
            Assert.Equal(["T1486"], ids);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void NullRaw_OutIdsIsEmptyNotNull()
    {
        Assert.False(MitreTechniqueIdFormat.TryNormalize(null, out var ids));
        Assert.NotNull(ids);
        Assert.Empty(ids);
    }

    [Fact]
    public void SelectOrDefault_NullFallback_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => MitreTechniqueIdFormat.SelectOrDefault("T1486", null!));
        Assert.Equal("fallbackId", ex.ParamName);
    }

    [Fact]
    public void SelectOrDefault_SecondaryIds_AreReadOnly()
    {
        var selection = MitreTechniqueIdFormat.SelectOrDefault("T1486, T1091");

        var asList = Assert.IsAssignableFrom<IList<string>>(selection.SecondaryIds);
        Assert.Throws<NotSupportedException>(() => asList.Add("T1059"));
    }
}
