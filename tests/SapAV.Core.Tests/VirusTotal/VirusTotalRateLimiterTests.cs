using SapAV.Core.Tests.TestSupport;
using SapAV.Core.VirusTotal;

namespace SapAV.Core.Tests.VirusTotal;

public sealed class VirusTotalRateLimiterTests
{
    [Fact]
    public void MinuteBudget_IsFourPerRollingMinute()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock();
        var limiter = new VirusTotalRateLimiter(dir.Path, clock);

        for (int i = 0; i < 4; i++)
        {
            Assert.True(limiter.TryAcquire().Allowed);
            clock.Advance(TimeSpan.FromSeconds(10)); // requests at 0, 10, 20, 30 s
        }

        var denied = limiter.TryAcquire(); // at 40 s
        Assert.False(denied.Allowed);
        Assert.Equal(RateLimitReason.MinuteBudget, denied.Reason);
        Assert.Equal(TimeSpan.FromSeconds(20), denied.RetryAfter); // the 0 s request leaves at 60 s
        Assert.False(limiter.Check().Allowed);

        clock.Advance(TimeSpan.FromSeconds(20)); // 60 s: one slot free, then full again
        Assert.True(limiter.TryAcquire().Allowed);
        Assert.False(limiter.TryAcquire().Allowed);
        Assert.Equal(5, limiter.UsedToday);
    }

    [Fact]
    public void DayBudget_StopsAtTheLimit_AndResetsAtUtcMidnight()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock { Now = new DateTimeOffset(2026, 11, 3, 0, 0, 0, TimeSpan.Zero) };
        var limiter = new VirusTotalRateLimiter(dir.Path, clock);

        for (int i = 0; i < 500; i++)
        {
            Assert.True(limiter.TryAcquire().Allowed);
            clock.Advance(TimeSpan.FromSeconds(1)); // 500 requests in 500 s break the minute budget...
            if (i % 4 == 3)
            {
                clock.Advance(TimeSpan.FromSeconds(60)); // ...so pace them
            }
        }

        var denied = limiter.TryAcquire();
        Assert.False(denied.Allowed);
        Assert.Equal(RateLimitReason.DayBudget, denied.Reason);
        Assert.Equal(new DateTimeOffset(2026, 11, 4, 0, 0, 0, TimeSpan.Zero), clock.Now + denied.RetryAfter);

        clock.Now = new DateTimeOffset(2026, 11, 4, 0, 0, 1, TimeSpan.Zero);
        Assert.True(limiter.TryAcquire().Allowed);
        Assert.Equal(1, limiter.UsedToday);
    }

    [Fact]
    public void Budgets_SurviveARestart_ButNotADayChange()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock();
        var first = new VirusTotalRateLimiter(dir.Path, clock, new VirusTotalRateLimitOptions { PerDay = 6 });
        for (int i = 0; i < 4; i++)
        {
            first.TryAcquire();
        }

        var restarted = new VirusTotalRateLimiter(dir.Path, clock, new VirusTotalRateLimitOptions { PerDay = 6 });
        Assert.Equal(4, restarted.UsedToday);
        Assert.Equal(RateLimitReason.MinuteBudget, restarted.TryAcquire().Reason); // the minute window came back too

        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.True(restarted.TryAcquire().Allowed);
        Assert.True(restarted.TryAcquire().Allowed);
        Assert.Equal(RateLimitReason.DayBudget, new VirusTotalRateLimiter(dir.Path, clock, new VirusTotalRateLimitOptions { PerDay = 6 }).Check().Reason);

        clock.Advance(TimeSpan.FromDays(1));
        Assert.Equal(0, new VirusTotalRateLimiter(dir.Path, clock).UsedToday);
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("""{"day": "yesterday", "count": 3, "recent": [], "blockedUntil": 0, "quotaStreak": 0}""")]
    [InlineData("""{"day": "2026-11-03", "count": "many", "recent": [], "blockedUntil": 0, "quotaStreak": 0}""")]
    public void CorruptUsageFile_StartsAtZero_WithoutThrowing(string content)
    {
        using var dir = new TempDirectory();
        File.WriteAllText(dir.File(VirusTotalRateLimiter.FileName), content);

        var limiter = new VirusTotalRateLimiter(dir.Path, new FakeClock());

        Assert.Equal(0, limiter.UsedToday);
        Assert.NotNull(limiter.LastProblem);
        Assert.True(limiter.TryAcquire().Allowed);
        Assert.Null(limiter.LastProblem); // the next save replaced the bad file
    }

    [Fact]
    public void QuotaAnswer_BacksOff_DoublingUntilMidnight_OrForRetryAfter()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock { Now = new DateTimeOffset(2026, 11, 3, 23, 50, 0, TimeSpan.Zero) };
        var limiter = new VirusTotalRateLimiter(dir.Path, clock);

        limiter.MarkQuotaExceeded();
        var first = limiter.Check();
        Assert.Equal((false, RateLimitReason.QuotaBackoff, TimeSpan.FromMinutes(1)), (first.Allowed, first.Reason, first.RetryAfter));

        clock.Advance(TimeSpan.FromMinutes(1));
        limiter.MarkQuotaExceeded(); // second hit in a row: 2 minutes
        Assert.Equal(TimeSpan.FromMinutes(2), limiter.Check().RetryAfter);
        clock.Advance(TimeSpan.FromMinutes(2));
        limiter.MarkQuotaExceeded(); // 4 minutes
        Assert.Equal(TimeSpan.FromMinutes(4), limiter.Check().RetryAfter);
        clock.Advance(TimeSpan.FromMinutes(4));
        limiter.MarkQuotaExceeded(); // 8 minutes, but the daily quota resets at midnight, 3 minutes away
        Assert.Equal(TimeSpan.FromMinutes(3), limiter.Check().RetryAfter);
        Assert.Equal(RateLimitReason.QuotaBackoff, new VirusTotalRateLimiter(dir.Path, clock).Check().Reason); // persisted

        clock.Advance(TimeSpan.FromMinutes(3));
        Assert.True(limiter.Check().Allowed);
        limiter.MarkSuccess();
        limiter.MarkQuotaExceeded(TimeSpan.FromSeconds(30)); // server's Retry-After wins
        Assert.Equal(TimeSpan.FromSeconds(30), limiter.Check().RetryAfter);
    }

    [Fact]
    public void ConcurrentAcquires_NeverExceedTheBudget()
    {
        using var dir = new TempDirectory();
        var limiter = new VirusTotalRateLimiter(dir.Path, new FakeClock());
        int allowed = 0;

        Parallel.For(0, 200, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ =>
        {
            if (limiter.TryAcquire().Allowed)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(4, allowed);
        Assert.Equal(4, limiter.UsedToday);
    }

    [Fact]
    public async Task WaitAsync_ReturnsAtOnceWhenTheWaitIsTooLong_AndHonoursCancellation()
    {
        using var dir = new TempDirectory();
        var limiter = new VirusTotalRateLimiter(dir.Path, new FakeClock(), new VirusTotalRateLimitOptions { PerMinute = 1 });
        Assert.True((await limiter.WaitAsync(TimeSpan.Zero)).Allowed);

        var started = System.Diagnostics.Stopwatch.StartNew();
        var tooLong = await limiter.WaitAsync(TimeSpan.FromSeconds(5)); // needs 60 s: no point waiting
        Assert.False(tooLong.Allowed);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(2));

        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => limiter.WaitAsync(TimeSpan.FromMinutes(5), cancel.Token)); // the fake clock never moves
        Assert.Equal(1, limiter.UsedToday);
    }
}
