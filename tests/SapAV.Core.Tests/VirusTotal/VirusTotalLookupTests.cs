using System.Net;
using System.Security.Cryptography;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.VirusTotal;

namespace SapAV.Core.Tests.VirusTotal;

public sealed class VirusTotalLookupTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly FakeClock _clock = new();
    private readonly List<VirusTotalCache> _caches = [];

    public void Dispose()
    {
        foreach (var cache in _caches)
        {
            cache.Dispose();
        }

        _dir.Dispose();
    }

    private VirusTotalLookup Lookup(FakeVtHandler handler, IVirusTotalKeySource? keys = null, VirusTotalClientOptions? options = null)
    {
        var cache = new VirusTotalCache(_dir.Path, RandomNumberGenerator.GetBytes(32), _clock);
        _caches.Add(cache);
        return new VirusTotalLookup(new VirusTotalClient(new HttpClient(handler), options), cache,
            new VirusTotalRateLimiter(_dir.Path, _clock), keys ?? new FakeKeySource(Vt.FakeKey));
    }

    [Fact]
    public async Task LiveAnswer_IsCached_AndTheNextLookupSendsNothing()
    {
        var handler = FakeVtHandler.Reports();
        var lookup = Lookup(handler);

        var live = await lookup.LookupAsync(Vt.ShaA);
        var cached = await lookup.LookupAsync(Vt.ShaA.ToUpperInvariant());

        Assert.Equal((VirusTotalOrigin.Live, VirusTotalStatus.Found), (live.Origin, live.Status));
        Assert.Equal((VirusTotalOrigin.Cache, VirusTotalStatus.Found), (cached.Origin, cached.Status));
        Assert.Equal(live.Report!.Malicious, cached.Report!.Malicious);
        Assert.Equal(_clock.Now, cached.FetchedAt);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task NoKey_And_InvalidHash_SendNothing()
    {
        var handler = FakeVtHandler.Reports();

        var noKey = await Lookup(handler, new FakeKeySource(null)).LookupAsync(Vt.ShaA);
        var invalid = await Lookup(handler).LookupAsync("C:\\Users\\me\\Downloads\\setup.exe");

        Assert.Equal(VirusTotalOrigin.NoKey, noKey.Origin);
        Assert.Equal(VirusTotalOrigin.InvalidHash, invalid.Origin);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefusedKey_StopsQuerying_UntilTheKeyChanges()
    {
        var handler = new FakeVtHandler(_ => Vt.Error(HttpStatusCode.Unauthorized, "WrongCredentialsError"));
        var keys = new FakeKeySource(Vt.FakeKey);
        var lookup = Lookup(handler, keys);

        var first = await lookup.LookupAsync(Vt.ShaA);
        var second = await lookup.LookupAsync(Vt.ShaB);
        Assert.Equal(VirusTotalOrigin.BadKey, first.Origin);
        Assert.Equal(VirusTotalOrigin.BadKey, second.Origin);
        Assert.True(lookup.KeyRejected);
        Assert.Equal(1, handler.Calls);

        keys.Key = VirusTotalApiKey.TryCreate(Vt.OtherFakeKey);
        Assert.False(lookup.KeyRejected);
        await lookup.LookupAsync(Vt.ShaB);
        Assert.Equal(2, handler.Calls);
        Assert.Equal(Vt.OtherFakeKey, handler.Requests[^1].Headers["x-apikey"]);
    }

    [Fact]
    public async Task Budget_AndQuotaAnswers_AreRateLimited_NotSent()
    {
        var handler = FakeVtHandler.Reports();
        var lookup = Lookup(handler);
        for (int i = 0; i < 4; i++)
        {
            Assert.Equal(VirusTotalOrigin.Live, (await lookup.LookupAsync(Vt.Sha(i))).Origin);
        }

        var fifth = await lookup.LookupAsync(Vt.Sha(4));
        Assert.Equal(VirusTotalOrigin.RateLimited, fifth.Origin);
        Assert.Equal(TimeSpan.FromMinutes(1), fifth.RetryAfter);
        Assert.Equal(VirusTotalOrigin.Cache, (await lookup.LookupAsync(Vt.Sha(0))).Origin); // the cache still answers
        Assert.Equal(4, handler.Calls);

        var quota = new FakeVtHandler(_ => Vt.Error(HttpStatusCode.TooManyRequests, "QuotaExceededError"));
        _clock.Advance(TimeSpan.FromMinutes(2));
        var quotaLookup = Lookup(quota);
        var hit = await quotaLookup.LookupAsync(Vt.ShaB);
        var after = await quotaLookup.LookupAsync(Vt.ShaB);
        Assert.Equal((VirusTotalOrigin.RateLimited, VirusTotalStatus.QuotaExceeded), (hit.Origin, hit.Status));
        Assert.Equal(VirusTotalOrigin.RateLimited, after.Origin); // backing off: not sent again
        Assert.Equal(1, quota.Calls);
    }

    [Fact]
    public async Task TransientFailures_AreNotes_NotCached_NotCancels()
    {
        int calls = 0;
        var handler = new FakeVtHandler(async (r, token) =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                await Task.Delay(Timeout.Infinite, token); // first request hangs until the client's timeout
            }

            return calls == 2 ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) : Vt.Json(HttpStatusCode.OK, Vt.Report(Vt.ShaA));
        });
        var lookup = Lookup(handler, options: new VirusTotalClientOptions { RequestTimeout = TimeSpan.FromMilliseconds(100) });

        var timedOut = await lookup.LookupAsync(Vt.ShaA);
        var serverDown = await lookup.LookupAsync(Vt.ShaA);
        var ok = await lookup.LookupAsync(Vt.ShaA);

        Assert.Equal((VirusTotalOrigin.Error, VirusTotalStatus.Transient), (timedOut.Origin, timedOut.Status));
        Assert.Equal((VirusTotalOrigin.Error, VirusTotalStatus.Transient), (serverDown.Origin, serverDown.Status));
        Assert.Equal(VirusTotalOrigin.Live, ok.Origin);
        Assert.All(new[] { timedOut, serverDown, ok }, r => Assert.DoesNotContain(Vt.FakeKey, r.ToString(), StringComparison.Ordinal));

        // Only the caller's own cancellation is a cancel.
        var hang = new FakeVtHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        _clock.Advance(TimeSpan.FromMinutes(2));
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Lookup(hang).LookupAsync(Vt.ShaB, cancellationToken: cancel.Token));
    }
}
