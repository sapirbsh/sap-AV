using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

public class VerdictTests
{
    [Fact]
    public void Verdicts_AreOrderedBySeverity()
    {
        Assert.True(Verdict.Clean < Verdict.Suspicious);
        Assert.True(Verdict.Suspicious < Verdict.Malicious);
        Assert.Equal(Verdict.Malicious, new[] { Verdict.Suspicious, Verdict.Malicious, Verdict.Clean }.Max());
    }
}
