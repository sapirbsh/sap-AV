using System.ComponentModel;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using SapAV.Core.Pipe;
using SapAV.Core.VirusTotal;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.VirusTotal;

/// <summary>Whether VirusTotal lookups can run now.</summary>
public enum VirusTotalActivity
{
    /// <summary>On, with a key: lookups run (subject to the cache and rate limit).</summary>
    Active,

    /// <summary>Turned off (the default).</summary>
    Off,

    /// <summary>Turned on, but no API key is set.</summary>
    NoKey,

    /// <summary>The protected folder or the cache can't be used (or a non-elevated debug run).</summary>
    Unavailable,
}

/// <summary>Outcome of a key or switch change over the pipe.</summary>
public enum VirusTotalChange
{
    Done,
    InvalidFormat,
    Failed,
    Unavailable,
}

/// <summary>The engine's VirusTotal: settings for the pipe, and the lookup for scans. Fake it in tests.</summary>
public interface IVirusTotalService
{
    VirusTotalActivity Activity { get; }

    /// <summary>The status for the pipe. Never contains the key.</summary>
    VirusTotalStatusInfo GetStatus();

    /// <summary>Stores a new key (validated) and allows it to be tried even if an earlier key was refused.</summary>
    VirusTotalChange SetKey(string? apiKey);

    VirusTotalChange ClearKey();

    VirusTotalChange SetEnabled(bool enabled);

    /// <summary>One lookup (cache, key, rate limit, request). Only the SHA-256 is sent. Never throws except for the caller's cancellation.</summary>
    Task<VirusTotalLookupResult> LookupAsync(string sha256, TimeSpan maxWait, CancellationToken cancellationToken);
}

/// <summary>
/// D3 wiring of the D2 VirusTotal parts. Everything lives in the protected <c>%ProgramData%\sap-AV\VirusTotal</c> folder
/// (<see cref="EngineDataSubfolder"/>: SYSTEM + Administrators only; a pre-existing wider or user-owned folder is refused):
/// <c>vt-apikey.bin</c> (machine DPAPI), <c>vt.db</c> + <c>vt-cache.key</c> (HMAC'd result cache), <c>vt-usage.json</c>
/// (the daily counter) and <c>vt-settings.json</c> (on/off).
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><b>Lazy</b>: nothing is created until the first status, lookup or change (resolving the host creates nothing). A
/// failure is logged, reported as <see cref="VirusTotalStatusInfo.LastProblem"/> and retried after
/// <see cref="VirusTotalOptions.RetryDelay"/>.</item>
/// <item><b>Not in a debug run</b>: a non-elevated console engine never touches <c>%ProgramData%</c> (it would create the data
/// root owned by the user, which the real service then refuses), so VirusTotal is unavailable there.</item>
/// <item><b>One long-lived HttpClient</b> (<see cref="VirusTotalClient.CreateHttpClient"/>: no redirects, nothing logs the
/// <c>x-apikey</c> header).</item>
/// <item>Core has no logger, so the key store's, cache's and limiter's problems and the cache's Tampered / Rebuilds counters
/// are logged here when they change.</item>
/// </list>
/// </remarks>
public sealed class VirusTotalService : IVirusTotalService, IDisposable
{
    private readonly VirusTotalOptions _options;
    private readonly ILogger _logger;
    private readonly TimeProvider _time;
    private readonly bool _protectedMode;
    private readonly bool _allowEnvironmentKey;
    private readonly QuarantineAccessPolicy _policy;
    private readonly Func<HttpClient> _http;
    private readonly bool? _parentIsDataRoot;
    private readonly Lock _lock = new();
    private State? _state;
    private DateTimeOffset _nextAttempt;
    private string? _initProblem;
    private string? _lookupProblem;
    private (long Tampered, int Rebuilds, string? Cache, string? Limiter, string? Store) _reported;

    public VirusTotalService(IOptions<VirusTotalOptions> options, ILogger<VirusTotalService> logger, TimeProvider time)
        : this(options.Value, logger, time, EngineAccount.IsProtected(), EngineAccount.AllowsDevelopmentKey(), QuarantineAccessPolicy.Default,
            VirusTotalClient.CreateHttpClient)
    {
    }

    /// <param name="protectedMode">False for a non-elevated debug run: never touches the data folder.</param>
    /// <param name="allowEnvironmentKey">Read <c>SAPAV_VIRUSTOTAL_APIKEY</c> when no key is stored (console runs only).</param>
    /// <param name="http">Creates the one HttpClient (tests: a fake handler).</param>
    /// <param name="parentIsDataRoot">Passed to <see cref="EngineDataSubfolder.Ensure"/> (null: when it is the real data root).</param>
    internal VirusTotalService(VirusTotalOptions options, ILogger logger, TimeProvider time, bool protectedMode, bool allowEnvironmentKey,
        QuarantineAccessPolicy policy, Func<HttpClient> http, bool? parentIsDataRoot = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _protectedMode = protectedMode;
        _allowEnvironmentKey = allowEnvironmentKey;
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _parentIsDataRoot = parentIsDataRoot;
    }

    /// <summary>True when unavailability is a problem worth a scan note (not a non-elevated debug run).</summary>
    internal bool ProtectedMode => _protectedMode;

    public VirusTotalActivity Activity
    {
        get
        {
            var state = TryGetState();
            if (state is null)
            {
                return VirusTotalActivity.Unavailable;
            }

            if (!Volatile.Read(ref state.Enabled))
            {
                return VirusTotalActivity.Off;
            }

            return state.Keys.GetKey() is null ? VirusTotalActivity.NoKey : VirusTotalActivity.Active;
        }
    }

    public VirusTotalStatusInfo GetStatus()
    {
        var state = TryGetState();
        if (state is null)
        {
            return new VirusTotalStatusInfo(false, false, false, false, false, 0, 0, Volatile.Read(ref _initProblem));
        }

        ReportProblems(state);
        string? problem = state.Keys.Store.LastProblem ?? state.SettingsProblem ?? state.Cache.LastProblem ?? state.Limiter.LastProblem
            ?? Volatile.Read(ref _lookupProblem);
        return new VirusTotalStatusInfo(true, Volatile.Read(ref state.Enabled), state.Keys.GetKey() is not null, state.Keys.FromEnvironment,
            state.Lookup.KeyRejected, state.Limiter.UsedToday, state.Limiter.PerDay, problem);
    }

    public VirusTotalChange SetKey(string? apiKey)
    {
        if (TryGetState() is not { } state)
        {
            return VirusTotalChange.Unavailable;
        }

        switch (state.Keys.Store.Set(apiKey))
        {
            case SetKeyResult.Saved:
                state.Lookup.ResetKeyRejection();
                Volatile.Write(ref _lookupProblem, null);
                _logger.LogInformation("The VirusTotal API key was set (id {KeyId}).", state.Keys.GetKey()?.Fingerprint);
                return VirusTotalChange.Done;
            case SetKeyResult.InvalidFormat:
                return VirusTotalChange.InvalidFormat;
            default:
                _logger.LogWarning("The VirusTotal API key could not be saved: {Problem}", state.Keys.Store.LastProblem);
                return VirusTotalChange.Failed;
        }
    }

    public VirusTotalChange ClearKey()
    {
        if (TryGetState() is not { } state)
        {
            return VirusTotalChange.Unavailable;
        }

        if (!state.Keys.Store.Clear())
        {
            _logger.LogWarning("The VirusTotal API key could not be removed: {Problem}", state.Keys.Store.LastProblem);
            return VirusTotalChange.Failed;
        }

        _logger.LogInformation("The VirusTotal API key was removed.");
        return VirusTotalChange.Done;
    }

    public VirusTotalChange SetEnabled(bool enabled)
    {
        if (TryGetState() is not { } state)
        {
            return VirusTotalChange.Unavailable;
        }

        try
        {
            VirusTotalSettings.SaveEnabled(state.Folder, enabled);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("The VirusTotal setting could not be saved ({Type}).", ex.GetType().Name);
            return VirusTotalChange.Failed;
        }

        Volatile.Write(ref state.Enabled, enabled);
        state.SettingsProblem = null;
        _logger.LogInformation("VirusTotal hash lookups turned {State}.", enabled ? "on" : "off");
        return VirusTotalChange.Done;
    }

    public async Task<VirusTotalLookupResult> LookupAsync(string sha256, TimeSpan maxWait, CancellationToken cancellationToken)
    {
        if (TryGetState() is not { } state)
        {
            return new VirusTotalLookupResult(VirusTotalOrigin.Error, null, null, null, null,
                "VirusTotal not checked: " + (Volatile.Read(ref _initProblem) ?? "it is not available."));
        }

        var result = await state.Lookup.LookupAsync(sha256, maxWait, cancellationToken).ConfigureAwait(false);
        if (result.Origin is VirusTotalOrigin.Error or VirusTotalOrigin.BadKey)
        {
            if (Volatile.Read(ref _lookupProblem) != result.Detail)
            {
                _logger.LogWarning("VirusTotal lookup: {Detail}", result.Detail);
            }

            Volatile.Write(ref _lookupProblem, result.Detail);
        }
        else if (result.Origin == VirusTotalOrigin.Live)
        {
            Volatile.Write(ref _lookupProblem, null);
        }

        ReportProblems(state);
        return result;
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _state?.Dispose();
            _state = null;
        }
    }

    private State? TryGetState()
    {
        if (Volatile.Read(ref _state) is { } ready)
        {
            return ready;
        }

        if (!_protectedMode)
        {
            Volatile.Write(ref _initProblem, "VirusTotal needs the engine to run as a service, as SYSTEM or elevated (the key and cache live in the protected data folder).");
            return null;
        }

        lock (_lock)
        {
            if (_state is not null || _time.GetUtcNow() < _nextAttempt)
            {
                return _state;
            }

            try
            {
                _state = Open();
                Volatile.Write(ref _initProblem, null);
                return _state;
            }
            catch (Exception ex) when (ex is QuarantineStoreException or IOException or UnauthorizedAccessException or SqliteException or Win32Exception)
            {
                _nextAttempt = _time.GetUtcNow() + _options.RetryDelay;
                string why = ex is QuarantineStoreException ? ex.Message : $"its data could not be opened ({ex.GetType().Name}).";
                Volatile.Write(ref _initProblem, why);
                _logger.LogError("VirusTotal is unavailable: {Why} Retrying after {Delay}.", why, _options.RetryDelay);
                return null;
            }
        }
    }

    private State Open()
    {
        string folder = EngineDataSubfolder.Ensure(_options.ResolvedFolder, _policy, "VirusTotal", _parentIsDataRoot);
        var cache = new VirusTotalCache(folder, VirusTotalCache.LoadOrCreateMacKey(folder), _time);
        try
        {
            var limiter = new VirusTotalRateLimiter(folder, _time);
            var keys = new EngineKeySource(new VirusTotalKeyStore(folder), _allowEnvironmentKey);
            var http = _http();
            var lookup = new VirusTotalLookup(new VirusTotalClient(http), cache, limiter, keys);
            bool enabled = VirusTotalSettings.LoadEnabled(folder, out var settingsProblem);
            if (keys.FromEnvironment)
            {
                _logger.LogWarning("VirusTotal uses the development API key from {Variable} (console run).", VirusTotalApiKey.EnvironmentVariable);
            }

            return new State(folder, cache, limiter, keys, lookup, http) { Enabled = enabled, SettingsProblem = settingsProblem };
        }
        catch
        {
            cache.Dispose();
            throw;
        }
    }

    /// <summary>Logs Core's problems and the cache's integrity counters once each time they change.</summary>
    private void ReportProblems(State state)
    {
        (long Tampered, int Rebuilds, string? Cache, string? Limiter, string? Store) now =
            (state.Cache.Tampered, state.Cache.Rebuilds, state.Cache.LastProblem, state.Limiter.LastProblem, state.Keys.Store.LastProblem);
        (long Tampered, int Rebuilds, string? Cache, string? Limiter, string? Store) before;
        lock (_lock)
        {
            before = _reported;
            _reported = now;
        }

        if (now.Tampered != before.Tampered || now.Rebuilds != before.Rebuilds)
        {
            _logger.LogWarning("VirusTotal cache integrity: {Tampered} rows failed their check, {Rebuilds} rebuilds.", now.Tampered, now.Rebuilds);
        }

        LogIfChanged("VirusTotal cache", before.Cache, now.Cache);
        LogIfChanged("VirusTotal usage counter", before.Limiter, now.Limiter);
        LogIfChanged("VirusTotal key store", before.Store, now.Store);
    }

    private void LogIfChanged(string what, string? before, string? now)
    {
        if (now is not null && now != before)
        {
            _logger.LogWarning("{What}: {Problem}", what, now);
        }
    }

    private sealed class State(string folder, VirusTotalCache cache, VirusTotalRateLimiter limiter, EngineKeySource keys, VirusTotalLookup lookup,
        HttpClient http) : IDisposable
    {
        public bool Enabled;

        public string Folder { get; } = folder;

        public VirusTotalCache Cache { get; } = cache;

        public VirusTotalRateLimiter Limiter { get; } = limiter;

        public EngineKeySource Keys { get; } = keys;

        public VirusTotalLookup Lookup { get; } = lookup;

        public string? SettingsProblem { get; set; }

        public void Dispose()
        {
            http.Dispose();
            Cache.Dispose();
        }
    }
}
