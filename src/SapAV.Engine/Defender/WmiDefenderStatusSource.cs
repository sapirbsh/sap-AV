using Microsoft.Extensions.Options;
using SapAV.Core.Defender;

namespace SapAV.Engine.Defender;

/// <summary>
/// The engine's <see cref="IDefenderStatusSource"/> (E5): reads <c>MSFT_MpComputerStatus</c>, <c>MSFT_MpPreference</c> and
/// Security Center's <c>AntiVirusProduct</c> through <see cref="IWmiReader"/>, in parallel, each bounded by
/// <see cref="DefenderStatusOptions.QueryTimeout"/>. Read-only: it never calls a Defender method (Set / Add / Remove).
/// </summary>
/// <remarks>
/// The engine runs as SYSTEM, so the exclusion lists are visible; run as a normal user (console debugging) they come back as
/// Defender's "N/A" placeholder and are reported as <see cref="DefenderExclusionListState.Hidden"/>. Even a reader that ignores
/// its timeout can't block a scan: each read is also awaited for at most the timeout plus a short grace.
/// </remarks>
public sealed class WmiDefenderStatusSource : IDefenderStatusSource
{
    internal static readonly TimeSpan Grace = TimeSpan.FromSeconds(1);

    private readonly IWmiReader _reader;
    private readonly TimeProvider _time;
    private readonly DefenderStatusOptions _options;
    private readonly ILogger _logger;
    private int _lastAvailability = -1;

    public WmiDefenderStatusSource(IWmiReader reader, TimeProvider time, IOptions<DefenderStatusOptions> options, ILogger<WmiDefenderStatusSource> logger)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<DefenderStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var timeout = _options.EffectiveQueryTimeout;

        var status = ReadAsync(DefenderStatusMapper.DefenderNamespace, DefenderStatusMapper.ComputerStatusClass,
            DefenderStatusMapper.ComputerStatusProperties, timeout, cancellationToken);
        var preference = ReadAsync(DefenderStatusMapper.DefenderNamespace, DefenderStatusMapper.PreferenceClass,
            DefenderStatusMapper.PreferenceProperties, timeout, cancellationToken);
        var securityCenter = ReadAsync(DefenderStatusMapper.SecurityCenterNamespace, DefenderStatusMapper.AntivirusProductClass,
            DefenderStatusMapper.AntivirusProductProperties, timeout, cancellationToken);
        await Task.WhenAll(status, preference, securityCenter).ConfigureAwait(false);

        var snapshot = DefenderStatusMapper.Map(await status.ConfigureAwait(false), await preference.ConfigureAwait(false),
            await securityCenter.ConfigureAwait(false), _time.GetUtcNow());
        LogIfChanged(snapshot);
        return snapshot;
    }

    private async Task<WmiReadResult> ReadAsync(string ns, string className, IReadOnlyCollection<string> properties, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            var query = new WmiClassQuery(ns, className, properties, timeout);
            return await _reader.ReadAsync(query, cancellationToken).WaitAsync(timeout + Grace, _time, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
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
