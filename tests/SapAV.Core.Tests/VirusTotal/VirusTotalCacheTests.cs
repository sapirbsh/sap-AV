using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.VirusTotal;

namespace SapAV.Core.Tests.VirusTotal;

public sealed class VirusTotalCacheTests
{
    private static readonly VirusTotalReport Detected = new(5, 1, 60, 0, 70, DateTimeOffset.FromUnixTimeSeconds(1_760_000_000),
        ["EngineA: Trojan.Fake", "EngineB: Gen:Fake"], "trojan.fake");

    private static readonly VirusTotalReport Clean = new(0, 0, 66, 4, 72, null, [], null);

    private static void Sql(string databasePath, string sql)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    [Fact]
    public void Entry_RoundTrips_AllFields()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock();
        using var cache = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), clock);

        cache.Put(Vt.ShaA.ToUpperInvariant(), VirusTotalStatus.Found, Detected);
        var entry = cache.Get(Vt.ShaA)!;

        Assert.Equal(VirusTotalStatus.Found, entry.Status);
        Assert.Equal(Detected.Malicious, entry.Report!.Malicious);
        Assert.Equal(Detected.Labels, entry.Report.Labels);
        Assert.Equal(Detected.ThreatLabel, entry.Report.ThreatLabel);
        Assert.Equal(Detected.LastAnalysisDate, entry.Report.LastAnalysisDate);
        Assert.Equal(clock.Now, entry.FetchedAt);
    }

    [Theory]
    [InlineData(true, false, 7)]   // detected: 7 days
    [InlineData(false, false, 1)]  // clean: 1 day
    [InlineData(false, true, 1)]   // unknown (404): 1 day
    public void Ttl_DependsOnTheAnswer(bool detected, bool notFound, int days)
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock();
        using var cache = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), clock);
        cache.Put(Vt.ShaA, notFound ? VirusTotalStatus.NotFound : VirusTotalStatus.Found, notFound ? null : detected ? Detected : Clean);

        clock.Advance(TimeSpan.FromDays(days) - TimeSpan.FromMinutes(1));
        Assert.NotNull(cache.Get(Vt.ShaA));
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Null(cache.Get(Vt.ShaA));
        Assert.Equal(0, cache.Count()); // expired rows are deleted
    }

    [Theory]
    [InlineData(VirusTotalStatus.Transient)]
    [InlineData(VirusTotalStatus.Error)]
    [InlineData(VirusTotalStatus.BadKey)]
    [InlineData(VirusTotalStatus.QuotaExceeded)]
    public void FailedAnswers_AreNeverCached(VirusTotalStatus status)
    {
        using var dir = new TempDirectory();
        using var cache = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), new FakeClock());

        Assert.Null(cache.Put(Vt.ShaA, status, null));
        Assert.Equal(0, cache.Count());
    }

    [Theory]
    [InlineData("UPDATE entries SET malicious = 0, suspicious = 0")]                 // flagged file turned clean
    [InlineData("UPDATE entries SET expires_at = expires_at + 864000000000")]        // old answer kept alive
    [InlineData("UPDATE entries SET status = 1")]                                    // Found turned into NotFound
    [InlineData("UPDATE entries SET sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'")] // moved to another hash
    public void TamperedRow_IsDeletedAndCounted_NeverUsed(string tamper)
    {
        using var dir = new TempDirectory();
        using var cache = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), new FakeClock());
        cache.Put(Vt.ShaA, VirusTotalStatus.Found, Detected);

        Sql(cache.DatabasePath, tamper);

        Assert.Null(cache.Get(Vt.ShaA));
        Assert.Null(cache.Get(Vt.ShaB));
        Assert.Equal(1, cache.Tampered);
        Assert.Equal(0, cache.Count());
    }

    [Fact]
    public void RowsMadeWithAnotherKey_AreRefused()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock();
        using (var first = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), clock))
        {
            first.Put(Vt.ShaA, VirusTotalStatus.Found, Clean);
        }

        using var second = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), clock);

        Assert.Null(second.Get(Vt.ShaA));
        Assert.Equal(1, second.Tampered);
    }

    [Fact]
    public void CorruptDatabase_IsRebuilt_WithoutThrowing()
    {
        using var dir = new TempDirectory();
        File.WriteAllBytes(dir.File(VirusTotalCache.DatabaseName), RandomNumberGenerator.GetBytes(16 * 1024));

        using var cache = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), new FakeClock());

        Assert.Equal(1, cache.Rebuilds);
        Assert.NotNull(cache.LastProblem);
        Assert.NotNull(cache.Put(Vt.ShaA, VirusTotalStatus.NotFound, null));
        Assert.Equal(VirusTotalStatus.NotFound, cache.Get(Vt.ShaA)!.Status);
    }

    [Fact]
    public void Size_IsBoundedByMaxEntries_OldestOut()
    {
        using var dir = new TempDirectory();
        var clock = new FakeClock();
        using var cache = new VirusTotalCache(dir.Path, RandomNumberGenerator.GetBytes(32), clock, new VirusTotalCacheOptions { MaxEntries = 10 });
        for (int i = 0; i < 30; i++)
        {
            cache.Put(Vt.Sha(i), VirusTotalStatus.NotFound, null);
            clock.Advance(TimeSpan.FromSeconds(1));
        }

        cache.Prune();

        Assert.InRange(cache.Count(), 1, 10);
        Assert.NotNull(cache.Get(Vt.Sha(29)));
        Assert.Null(cache.Get(Vt.Sha(0)));
    }

    [Fact]
    public void MacKey_PersistsWithDpapi_AndACorruptKeyFileIsReplaced()
    {
        using var dir = new TempDirectory();
        var key = VirusTotalCache.LoadOrCreateMacKey(dir.Path);

        Assert.Equal(32, key.Length);
        Assert.Equal(key, VirusTotalCache.LoadOrCreateMacKey(dir.Path));
        Assert.True(File.ReadAllBytes(dir.File(VirusTotalCache.MacKeyFileName)).AsSpan().IndexOf(key) < 0); // stored protected

        File.WriteAllBytes(dir.File(VirusTotalCache.MacKeyFileName), [1, 2, 3, 4]);
        var replaced = VirusTotalCache.LoadOrCreateMacKey(dir.Path);
        Assert.Equal(32, replaced.Length);
        Assert.NotEqual(key, replaced);
    }
}
