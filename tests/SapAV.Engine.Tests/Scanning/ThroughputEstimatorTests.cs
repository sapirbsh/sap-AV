using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>ETA from the smoothed throughput, on a fake clock.</summary>
public sealed class ThroughputEstimatorTests
{
    [Fact]
    public void Eta_IsUnknownUntilTheFirstWindow_ThenFromTheSmoothedByteRate()
    {
        var time = new ManualTime();
        var estimator = new ThroughputEstimator(time) { Smoothing = 0.5 };
        estimator.Restart();

        estimator.Record(500, 1); // window still open (0 s)
        Assert.Null(estimator.Estimate(10_000, 10));

        time.Now += TimeSpan.FromSeconds(1);
        estimator.Record(500, 1); // 1000 bytes in 1 s
        Assert.Equal(1000, estimator.BytesPerSecond);
        Assert.Equal(TimeSpan.FromSeconds(10), estimator.Estimate(10_000, 10));

        time.Now += TimeSpan.FromSeconds(1);
        estimator.Record(3000, 1); // 3000 B/s sample, blended 50/50 -> 2000 B/s
        Assert.Equal(2000, estimator.BytesPerSecond);
        Assert.Equal(TimeSpan.FromSeconds(5), estimator.Estimate(10_000, 10));
    }

    [Fact]
    public void Eta_UsesTheFileRate_WhenNoBytesAreLeft_AndZeroWhenDone()
    {
        var time = new ManualTime();
        var estimator = new ThroughputEstimator(time);
        estimator.Restart();
        time.Now += TimeSpan.FromSeconds(2);
        estimator.Record(0, 4); // empty files: 2 files/s

        Assert.Equal(TimeSpan.FromSeconds(3), estimator.Estimate(0, 6));
        Assert.Equal(TimeSpan.Zero, estimator.Estimate(0, 0));
    }

    [Fact]
    public void Restart_DropsTheOpenWindow_SoPausedTimeDoesNotLowerTheRate()
    {
        var time = new ManualTime();
        var estimator = new ThroughputEstimator(time);
        estimator.Restart();
        estimator.Record(1000, 1);
        time.Now += TimeSpan.FromHours(1); // paused for an hour
        estimator.Restart();               // resume
        time.Now += TimeSpan.FromSeconds(1);
        estimator.Record(1000, 1);

        Assert.Equal(1000, estimator.BytesPerSecond);
    }
}
