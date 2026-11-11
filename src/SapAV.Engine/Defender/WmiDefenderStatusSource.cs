using Microsoft.Extensions.Options;
using SapAV.Core.Defender;

namespace SapAV.Engine.Defender;

/// <summary>
/// The engine's <see cref="IDefenderStatusSource"/> (E5): reads <c>MSFT_MpComputerStatus</c>, <c>MSFT_MpPreference</c> and
/// Security Center's <c>AntiVirusProduct</c> through <see cref="IWmiReader"/>, plus <see cref="IDefenderEnvironment"/> (SKU,
/// account, registry fallback for hidden exclusions), in parallel, each bounded by <see cref="DefenderStatusOptions.QueryTimeout"/>.
/// Read-only: it never calls a Defender method (Set / Add / Remove) and never writes the registry.
/// </summary>
/// <remarks>
/// <para>
/// The engine runs as SYSTEM, so the exclusion lists are visible; run as a normal user (console debugging) WMI returns Defender's
/// "N/A" placeholder and the registry keys are denied, so the lists are <see cref="DefenderExclusionListState.Hidden"/>. Even a
/// reader that ignores its timeout can't block a scan: each read is also awaited for at most the timeout plus a short grace.
/// </para>
/// <para>
/// Concurrent callers share one in-flight collection (review L2), so a burst of callers never multiplies WMI calls. The shared
/// collection doesn't depend on any caller's token; a cancelled caller just stops waiting for it.
/// </para>
/// </remarks>
public sealed class WmiDefenderStatusSource : IDefenderStatusSource
{
    internal static readonly TimeSpan Grace = TimeSpan.FromSeconds(1);

    private readonly IWmiReader _reader;
    private readonly IDefenderEnvironment _environment;
    private readonly TimeProvider _time;
    private readonly DefenderStatusOptions _options;
    private readonly ILogger _logger;
    private readonly Lock _gate = new();
    private Task<DefenderStatusSnapshot>? _inFlight;
    private int _lastAvailability = -1;

    public WmiDefenderStatusSource(IWmiReader reader, IDefenderEnvironment environment, TimeProvider time,
        IOptions<DefenderStatusOptions> options, ILogger<WmiDefenderStatusSource> logger)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<DefenderStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Task<DefenderStatusSnapshot> shared;
        lock (_gate)
        {
            if (_inFlight is null || _inFlight.IsCompleted)
            {
                _inFlight = Task.Run(CollectAsync, CancellationToken.None);
            }

            shared = _inFlight;
        }

        return shared.WaitAsync(cancellationToken);
    }

    private async Task<DefenderStatusSnapshot> CollectAsync()
    {
        try
        {
            return await CollectCoreAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Never an exception for callers (the contract); an unexpected bug becomes a Failed snapshot.
            _logger.LogError(ex, "Defender status collection failed unexpectedly");
            return new DefenderStatusSnapshot
            {
                CollectedAt = _time.GetUtcNow(),
                ComputerStatusRead = DefenderReadState.Failed,
                PreferenceRead = DefenderReadState.Failed,
                Detail = ex.GetType().Name,
            };
        }
    }

    private async Task<DefenderStatusSnapshot> CollectCoreAsync()
    {
        var timeout = _options.EffectiveQueryTimeout;

        var status = ReadAsync(DefenderStatusMapper.DefenderNamespace, DefenderStatusMapper.ComputerStatusClass,
            DefenderStatusMapper.ComputerStatusProperties, timeout);
        var preference = ReadAsync(DefenderStatusMapper.DefenderNamespace, DefenderStatusMapper.PreferenceClass,
            DefenderStatusMapper.PreferenceProperties, timeout);
        var securityCenter = ReadAsync(DefenderStatusMapper.SecurityCenterNamespace, DefenderStatusMapper.AntivirusProductClass,
            DefenderStatusMapper.AntivirusProductProperties, timeout);
        var environment = ReadEnvironmentAsync(timeout);
        await Task.WhenAll(status, preference, securityCenter, environment).ConfigureAwait(false);

        var snapshot = DefenderStatusMapper.Map(await status.ConfigureAwait(false), await preference.ConfigureAwait(false),
            await securityCenter.ConfigureAwait(false), _time.GetUtcNow(), await environment.ConfigureAwait(false));
        LogIfChanged(snapshot);
        return snapshot;
    }

    private async Task<WmiReadResult> ReadAsync(string ns, string className, IReadOnlyCollection<string> properties, TimeSpan timeout)
    {
        try
        {
            var query = new WmiClassQuery(ns, className, properties, timeout);
            return await _reader.ReadAsync(query, CancellationToken.None).WaitAsync(timeout + Grace, _time).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return WmiReadResult.Failure(WmiReadStatus.TimedOut, "the WMI reader didn't return");
        }
        catch (Exception ex)
        {
            // A reader is not supposed to throw; if one does, it is a failed read, never an exception for the caller.
            return WmiReadResult.Failure(WmiReadStatus.Failed, ex.GetType().Name);
        }
    }

    private async Task<DefenderEnvironmentInfo> ReadEnvironmentAsync(TimeSpan timeout)
    {
        try
        {
            return await Task.Run(_environment.Read).WaitAsync(timeout + Grace, _time).ConfigureAwait(false) ?? DefenderEnvironmentInfo.Unknown;
        }
        catch (Exception)
        {
            return DefenderEnvironmentInfo.Unknown; // never fatal: the SKU, account and fallback just stay unknown
        }
    }

    private void LogIfChanged(DefenderStatusSnapshot snapshot)
    {
        int current = (int)snapshot.Availability;
        if (Interlocked.Exchange(ref _lastAvailability, current) == current)
        {
            return;
        }

        if (snapshot.Availability == DefenderReadState.Available)
        {
            _logger.LogInformation("Defender status readable (running mode {Mode}, active antivirus: {Active})",
                snapshot.Protection.RunningMode, snapshot.DefenderIsActiveAntivirus?.ToString() ?? "unknown");
        }
        else
        {
            _logger.LogWarning("Defender status not fully readable: {Availability} ({Detail})", snapshot.Availability, snapshot.Detail);
        }
    }
}
