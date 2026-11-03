using SapAV.Core.Hashing;

namespace SapAV.Core.VirusTotal;

/// <summary>Where a <see cref="VirusTotalLookupResult"/> came from.</summary>
public enum VirusTotalOrigin
{
    /// <summary>A fresh, verified cache row; nothing was sent.</summary>
    Cache,

    /// <summary>VirusTotal answered now (Found / NotFound), and the answer was cached.</summary>
    Live,

    /// <summary>Not sent: the minute/day budget is used up or the quota back-off is running ("unchecked").</summary>
    RateLimited,

    /// <summary>Not sent: no API key is set.</summary>
    NoKey,

    /// <summary>VirusTotal refused the key (now or earlier). Nothing more is sent until the key changes.</summary>
    BadKey,

    /// <summary>Not sent: the value isn't a SHA-256.</summary>
    InvalidHash,

    /// <summary>Sent, but no usable answer (timeout, offline, 5xx, unexpected or refused response). Never cached.</summary>
    Error,
}

/// <summary>Result of <see cref="VirusTotalLookup.LookupAsync"/>. Never contains the API key.</summary>
/// <param name="Origin">Where it came from.</param>
/// <param name="Status">The VirusTotal answer (Found / NotFound for Cache and Live; the failing status otherwise), or null if nothing was sent.</param>
/// <param name="Report">The report when VirusTotal knows the file.</param>
/// <param name="FetchedAt">When VirusTotal gave the answer (cache or live), or null.</param>
/// <param name="RetryAfter">For RateLimited (and some errors): when it is worth asking again.</param>
/// <param name="Detail">One engine-written line for the scan note / log (review M4: an online failure is a note, never a scan failure).</param>
public sealed record VirusTotalLookupResult(
    VirusTotalOrigin Origin, VirusTotalStatus? Status, VirusTotalReport? Report, DateTimeOffset? FetchedAt, TimeSpan? RetryAfter, string Detail)
{
    /// <summary>A usable answer (cache or live).</summary>
    public bool HasAnswer => Origin is VirusTotalOrigin.Cache or VirusTotalOrigin.Live;
}

/// <summary>
/// The VirusTotal hash lookup (D2): cache, then key, then rate limiter, then the client. D3 wraps it in the engine's
/// <see cref="Scanning.IOnlineHashLookup"/> (when to look up, and how a report becomes a Detection).
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Order: hash check (nothing sent for a non-SHA-256), cache hit, no key, a key already refused, the limiter (non-blocking by
/// default, or waiting up to <c>maxWait</c>), then one request.</item>
/// <item>Found / NotFound are cached; a quota answer starts the limiter's back-off; 401/403 marks the key as refused (by its
/// fingerprint) so nothing more is sent until a different key is set or <see cref="ResetKeyRejection"/> is called.</item>
/// <item>Never throws, except <see cref="OperationCanceledException"/> when the caller's token is cancelled (a request timeout is an
/// <see cref="VirusTotalOrigin.Error"/>, not a cancel: review M4).</item>
/// </list>
/// Thread-safe. Two concurrent lookups of the same uncached hash both send a request (each uses budget).
/// </remarks>
public sealed class VirusTotalLookup
{
    private readonly VirusTotalClient _client;
    private readonly VirusTotalCache _cache;
    private readonly VirusTotalRateLimiter _limiter;
    private readonly IVirusTotalKeySource _keys;
    private string? _rejectedKey;

    public VirusTotalLookup(VirusTotalClient client, VirusTotalCache cache, VirusTotalRateLimiter limiter, IVirusTotalKeySource keys)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _limiter = limiter ?? throw new ArgumentNullException(nameof(limiter));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
    }

    /// <summary>True while the current key is one VirusTotal refused (for the status: "key rejected").</summary>
    public bool KeyRejected => _keys.GetKey() is { } key && Volatile.Read(ref _rejectedKey) == key.Fingerprint;

    /// <summary>Allows the current key to be tried again (e.g. the user says they fixed the account).</summary>
    public void ResetKeyRejection() => Volatile.Write(ref _rejectedKey, null);

    /// <param name="sha256">The file's SHA-256 (any case). Only this is ever sent.</param>
    /// <param name="maxWait">How long to wait for a rate-limit slot (default zero: don't wait, return RateLimited).</param>
    /// <param name="cancellationToken">Cancels the wait and the request.</param>
    /// <exception cref="OperationCanceledException">Only when <paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<VirusTotalLookupResult> LookupAsync(string? sha256, TimeSpan maxWait = default, CancellationToken cancellationToken = default)
    {
        if (!Sha256Hex.TryNormalize(sha256, out var hash))
        {
            return new VirusTotalLookupResult(VirusTotalOrigin.InvalidHash, null, null, null, null, "Not a SHA-256; nothing was sent to VirusTotal.");
        }

        if (_cache.Get(hash) is { } cached)
        {
            return new VirusTotalLookupResult(VirusTotalOrigin.Cache, cached.Status, cached.Report, cached.FetchedAt, null, Describe(cached.Status, cached.Report, "cached"));
        }

        var key = _keys.GetKey();
        if (key is null)
        {
            return new VirusTotalLookupResult(VirusTotalOrigin.NoKey, null, null, null, null, "VirusTotal is not checked: no API key is set.");
        }

        if (Volatile.Read(ref _rejectedKey) == key.Fingerprint)
        {
            return new VirusTotalLookupResult(VirusTotalOrigin.BadKey, VirusTotalStatus.BadKey, null, null, null, "VirusTotal is not checked: it refused the API key.");
        }

        var slot = maxWait > TimeSpan.Zero
            ? await _limiter.WaitAsync(maxWait, cancellationToken).ConfigureAwait(false)
            : _limiter.TryAcquire();
        if (!slot.Allowed)
        {
            return new VirusTotalLookupResult(VirusTotalOrigin.RateLimited, null, null, null, slot.RetryAfter, RateLimitedText(slot.Reason));
        }

        VirusTotalResponse response;
        try
        {
            response = await _client.LookupAsync(hash, key, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The client doesn't throw for network problems; anything else here is a bug, still only a note for the scan.
            return new VirusTotalLookupResult(VirusTotalOrigin.Error, VirusTotalStatus.Error, null, null, null, $"VirusTotal lookup failed ({ex.GetType().Name}).");
        }

        switch (response.Status)
        {
            case VirusTotalStatus.Found:
            case VirusTotalStatus.NotFound:
                _limiter.MarkSuccess();
                var stored = _cache.Put(hash, response.Status, response.Report);
                return new VirusTotalLookupResult(VirusTotalOrigin.Live, response.Status, response.Report,
                    stored?.FetchedAt, null, Describe(response.Status, response.Report, "live"));

            case VirusTotalStatus.QuotaExceeded:
                _limiter.MarkQuotaExceeded(response.RetryAfter);
                var after = _limiter.Check();
                return new VirusTotalLookupResult(VirusTotalOrigin.RateLimited, response.Status, null, null,
                    after.Allowed ? null : after.RetryAfter, response.Detail);

            case VirusTotalStatus.BadKey:
                Volatile.Write(ref _rejectedKey, key.Fingerprint);
                return new VirusTotalLookupResult(VirusTotalOrigin.BadKey, response.Status, null, null, null, response.Detail);

            default:
                return new VirusTotalLookupResult(VirusTotalOrigin.Error, response.Status, null, null, response.RetryAfter, response.Detail);
        }
    }

    private static string Describe(VirusTotalStatus status, VirusTotalReport? report, string source) => status == VirusTotalStatus.NotFound
        ? $"VirusTotal does not know this file ({source})."
        : $"VirusTotal: {report!.DetectionRatio} engines flagged the file ({source}).";

    private static string RateLimitedText(RateLimitReason reason) => reason switch
    {
        RateLimitReason.DayBudget => "VirusTotal not checked: the daily request budget is used up.",
        RateLimitReason.QuotaBackoff => "VirusTotal not checked: backing off after a quota answer.",
        _ => "VirusTotal not checked: the per-minute request budget is used up.",
    };
}
