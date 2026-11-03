using System.Text.Json;
using System.Text.Json.Serialization;

namespace SapAV.Core.VirusTotal;

/// <summary>Budgets of <see cref="VirusTotalRateLimiter"/> (VirusTotal public API: 4 requests/minute, 500/day).</summary>
public sealed record VirusTotalRateLimitOptions
{
    public int PerMinute { get; init; } = 4;

    public int PerDay { get; init; } = 500;

    /// <summary>First back-off after a quota answer without Retry-After; doubles per consecutive hit (default 1 minute).</summary>
    public TimeSpan QuotaBackoff { get; init; } = TimeSpan.FromMinutes(1);

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(PerMinute, 1, nameof(PerMinute));
        ArgumentOutOfRangeException.ThrowIfLessThan(PerDay, 1, nameof(PerDay));
        ArgumentOutOfRangeException.ThrowIfLessThan(QuotaBackoff, TimeSpan.FromSeconds(1), nameof(QuotaBackoff));
    }
}

/// <summary>Answer of <see cref="VirusTotalRateLimiter.Check"/> / <see cref="VirusTotalRateLimiter.TryAcquire"/>.</summary>
/// <param name="Allowed">A request may be (or, for TryAcquire, was reserved to be) sent now.</param>
/// <param name="RetryAfter">If not allowed: how long until the next slot frees up (zero if allowed).</param>
/// <param name="Reason">If not allowed: which budget is used up.</param>
public sealed record RateLimitDecision(bool Allowed, TimeSpan RetryAfter, RateLimitReason Reason);

public enum RateLimitReason
{
    None,
    MinuteBudget,
    DayBudget,
    QuotaBackoff,
}

/// <summary>
/// The VirusTotal request budget (D2): <see cref="VirusTotalRateLimitOptions.PerMinute"/> requests in any rolling 60 seconds and
/// <see cref="VirusTotalRateLimitOptions.PerDay"/> per UTC day, plus a back-off after the server says the quota is used up.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><b>Persistence</b>: the day counter, the minute window and the back-off are saved to <c>vt-usage.json</c> in the folder after
/// every change (write-to-temp + replace), so a restart doesn't reset the budget. A missing or unreadable file starts at zero for today
/// (the server-side quota still applies; the worst case is one 429). Write failures are kept in <see cref="LastProblem"/>.</item>
/// <item><b>Clock</b>: the injected <see cref="TimeProvider"/>. The day rolls over at UTC midnight. Window entries in the future
/// (the clock was set back) are dropped rather than blocking.</item>
/// <item><b>Threads</b>: every member is thread-safe; nothing blocks except <see cref="WaitAsync"/>, which waits at most the given time
/// and honours cancellation.</item>
/// </list>
/// </remarks>
public sealed class VirusTotalRateLimiter
{
    public const string FileName = "vt-usage.json";
    private const int MaxStateBytes = 4096;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly string _path;
    private readonly VirusTotalRateLimitOptions _options;
    private readonly TimeProvider _time;
    private readonly Lock _lock = new();
    private readonly List<DateTimeOffset> _recent = [];
    private DateOnly _day;
    private int _dayCount;
    private DateTimeOffset _blockedUntil;
    private int _quotaStreak;
    private string? _lastProblem;

    /// <param name="folder">Where <see cref="FileName"/> lives (the engine's protected data folder; tests use a temp folder).</param>
    public VirusTotalRateLimiter(string folder, TimeProvider time, VirusTotalRateLimitOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(folder);
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options ?? new VirusTotalRateLimitOptions();
        _options.Validate();
        _path = Path.Combine(folder, FileName);
        Load();
    }

    public int PerDay => _options.PerDay;

    /// <summary>Requests counted today (UTC), for the "today / 500" counter in the UI.</summary>
    public int UsedToday
    {
        get
        {
            lock (_lock)
            {
                Roll(_time.GetUtcNow());
                return _dayCount;
            }
        }
    }

    /// <summary>The last persistence problem (engine text), or null.</summary>
    public string? LastProblem => Volatile.Read(ref _lastProblem);

    /// <summary>Whether a request could be sent now, and if not, when. Reserves nothing.</summary>
    public RateLimitDecision Check()
    {
        lock (_lock)
        {
            return Decide(_time.GetUtcNow());
        }
    }

    /// <summary>Reserves one request if the budgets allow it now (the reservation counts even if the request then fails).</summary>
    public RateLimitDecision TryAcquire()
    {
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            var decision = Decide(now);
            if (decision.Allowed)
            {
                _recent.Add(now);
                _dayCount++;
                Save();
            }

            return decision;
        }
    }

    /// <summary>
    /// Waits up to <paramref name="maxWait"/> for a slot and reserves it. Returns the last decision: allowed, or not (the wait would
    /// be longer than <paramref name="maxWait"/>, or the day budget / back-off outlasts it, in which case it returns at once).
    /// </summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<RateLimitDecision> WaitAsync(TimeSpan maxWait, CancellationToken cancellationToken = default)
    {
        var deadline = _time.GetUtcNow() + (maxWait < TimeSpan.Zero ? TimeSpan.Zero : maxWait);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var decision = TryAcquire();
            var left = deadline - _time.GetUtcNow();
            if (decision.Allowed || decision.RetryAfter > left)
            {
                return decision;
            }

            // Short steps, so a clock change or a freed slot is seen; the TimeProvider's timer (a fake clock in tests may not tick it).
            var step = TimeSpan.FromTicks(Math.Clamp(decision.RetryAfter.Ticks, TimeSpan.FromMilliseconds(50).Ticks, TimeSpan.FromSeconds(1).Ticks));
            await Task.Delay(step, _time, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The server answered "quota exceeded". Blocks requests for <paramref name="retryAfter"/> if given, else for
    /// <see cref="VirusTotalRateLimitOptions.QuotaBackoff"/> doubled per consecutive hit; never past the next UTC midnight
    /// when the daily quota resets (except for an explicit Retry-After).
    /// </summary>
    public void MarkQuotaExceeded(TimeSpan? retryAfter = null)
    {
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            _quotaStreak = Math.Min(_quotaStreak + 1, 20);
            TimeSpan wait;
            if (retryAfter is { } explicitWait && explicitWait > TimeSpan.Zero)
            {
                wait = explicitWait;
            }
            else
            {
                var untilMidnight = NextUtcMidnight(now) - now;
                long doubled = _options.QuotaBackoff.Ticks << Math.Min(_quotaStreak - 1, 16);
                wait = TimeSpan.FromTicks(Math.Min(doubled, untilMidnight.Ticks));
            }

            var until = now + wait;
            if (until > _blockedUntil)
            {
                _blockedUntil = until;
            }

            Save();
        }
    }

    /// <summary>A request went through (not a quota answer): the quota back-off streak starts over.</summary>
    public void MarkSuccess()
    {
        lock (_lock)
        {
            if (_quotaStreak != 0)
            {
                _quotaStreak = 0;
                Save();
            }
        }
    }

    // ---- Core (caller holds the lock) ----

    private RateLimitDecision Decide(DateTimeOffset now)
    {
        Roll(now);
        if (_blockedUntil > now)
        {
            return new RateLimitDecision(false, _blockedUntil - now, RateLimitReason.QuotaBackoff);
        }

        if (_dayCount >= _options.PerDay)
        {
            return new RateLimitDecision(false, NextUtcMidnight(now) - now, RateLimitReason.DayBudget);
        }

        if (_recent.Count >= _options.PerMinute)
        {
            // The oldest of the last PerMinute requests leaves the window first.
            var frees = _recent[^_options.PerMinute] + Window;
            return new RateLimitDecision(false, frees - now, RateLimitReason.MinuteBudget);
        }

        return new RateLimitDecision(true, TimeSpan.Zero, RateLimitReason.None);
    }

    private void Roll(DateTimeOffset now)
    {
        _recent.RemoveAll(t => t <= now - Window || t > now + TimeSpan.FromSeconds(5));
        _recent.Sort();
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        if (today != _day)
        {
            _day = today;
            _dayCount = 0;
        }

        if (_blockedUntil > now + TimeSpan.FromDays(2))
        {
            _blockedUntil = default; // a back-off this long can only come from a clock change or a tampered file
        }
    }

    private static DateTimeOffset NextUtcMidnight(DateTimeOffset now) =>
        new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero).AddDays(1);

    // ---- Persistence ----

    private sealed record State(
        [property: JsonPropertyName("day")] string Day,
        [property: JsonPropertyName("count")] int Count,
        [property: JsonPropertyName("recent")] long[] Recent,
        [property: JsonPropertyName("blockedUntil")] long BlockedUntil,
        [property: JsonPropertyName("quotaStreak")] int QuotaStreak);

    private void Load()
    {
        var now = _time.GetUtcNow();
        _day = DateOnly.FromDateTime(now.UtcDateTime);
        try
        {
            var info = new FileInfo(_path);
            if (!info.Exists)
            {
                return;
            }

            if (info.Length > MaxStateBytes)
            {
                _lastProblem = "The VirusTotal usage file was too large; the counter starts at zero.";
                return;
            }

            var state = JsonSerializer.Deserialize<State>(File.ReadAllBytes(_path));
            if (state is null || state.Recent is null || state.Recent.Length > 64
                || !DateOnly.TryParseExact(state.Day, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var day))
            {
                _lastProblem = "The VirusTotal usage file was unreadable; the counter starts at zero.";
                return;
            }

            _day = day;
            _dayCount = Math.Clamp(state.Count, 0, _options.PerDay);
            _quotaStreak = Math.Clamp(state.QuotaStreak, 0, 20);
            _blockedUntil = FromMs(state.BlockedUntil);
            foreach (long ms in state.Recent)
            {
                _recent.Add(FromMs(ms));
            }

            Roll(now);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            _lastProblem = $"The VirusTotal usage file could not be read ({ex.GetType().Name}); the counter starts at zero.";
        }
    }

    private static DateTimeOffset FromMs(long ms) =>
        ms <= 0 || ms > DateTimeOffset.MaxValue.ToUnixTimeMilliseconds() ? default : DateTimeOffset.FromUnixTimeMilliseconds(ms);

    private void Save()
    {
        var state = new State(_day.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), _dayCount,
            [.. _recent.Select(t => t.ToUnixTimeMilliseconds())], _blockedUntil == default ? 0 : _blockedUntil.ToUnixTimeMilliseconds(), _quotaStreak);
        string temp = _path + ".tmp";
        try
        {
            File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(state));
            File.Move(temp, _path, overwrite: true);
            _lastProblem = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _lastProblem = $"The VirusTotal usage counter could not be saved ({ex.GetType().Name}); it is kept in memory.";
        }
    }
}
