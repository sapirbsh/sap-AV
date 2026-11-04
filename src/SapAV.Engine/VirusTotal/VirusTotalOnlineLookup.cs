using Microsoft.Extensions.Options;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.VirusTotal;

namespace SapAV.Engine.VirusTotal;

/// <summary>
/// The engine's <see cref="IOnlineHashLookup"/> (D3), called by the scan broker after the sandboxed worker's local verdict:
/// <list type="number">
/// <item><see cref="OnlineLookupPolicy"/> (never trusted-signed; real time = risky extensions; scans = Suspicious only).</item>
/// <item>The switch and key: off → nothing (the user's choice, no note); on without a key, or unavailable → a note.</item>
/// <item>Real time only (review D3 M3): a reserve for scans and a per-owner daily share (<see cref="VirusTotalOptions.ScanReserve"/>,
/// <see cref="VirusTotalOptions.RealTimeOwnerShare"/>), so one user's downloads can't use up the day for everyone.</item>
/// <item>The lookup (cache, rate limit, request; only the SHA-256 is sent), never waiting longer than the trigger's max wait.</item>
/// <item><see cref="VirusTotalVerdict.Map"/>: a detection with T1204.002 and/or a note. A non-answer is never Clean and never a failure.</item>
/// </list>
/// Never throws except for the caller's cancellation (anything else becomes a note).
/// </summary>
public sealed class VirusTotalOnlineLookup : IOnlineHashLookup
{
    private readonly IVirusTotalService _service;
    private readonly VirusTotalOptions _options;
    private readonly bool _noteWhenUnavailable;
    private readonly VirusTotalDayBudget _owners;

    public VirusTotalOnlineLookup(IVirusTotalService service, IOptions<VirusTotalOptions> options, TimeProvider time)
        : this(service, options.Value, (service as VirusTotalService)?.ProtectedMode ?? true, time)
    {
    }

    /// <param name="noteWhenUnavailable">False in a non-elevated debug run, where "unavailable" is expected.</param>
    internal VirusTotalOnlineLookup(IVirusTotalService service, VirusTotalOptions options, bool noteWhenUnavailable, TimeProvider? time = null)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _noteWhenUnavailable = noteWhenUnavailable;
        _owners = new VirusTotalDayBudget(time ?? TimeProvider.System);
    }

    internal VirusTotalDayBudget OwnerBudget => _owners;

    public async Task<OnlineLookupOutcome> LookupAsync(OnlineLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (OnlineLookupPolicy.Decide(request) != OnlineLookupDecision.Query)
        {
            return OnlineLookupOutcome.None;
        }

        switch (_service.Activity)
        {
            case VirusTotalActivity.Off:
                return OnlineLookupOutcome.None;
            case VirusTotalActivity.NoKey:
                return Note(ScanNoteLevel.Information, "VirusTotal not checked: it is turned on but no API key is set.");
            case VirusTotalActivity.Unavailable:
                return _noteWhenUnavailable
                    ? Note(ScanNoteLevel.Warning, "VirusTotal not checked: " + (_service.GetStatus().LastProblem ?? "it is not available."))
                    : OnlineLookupOutcome.None;
        }

        bool realTime = request.Item.Trigger == ScanTrigger.RealTime;
        string? taken = null;
        if (realTime && RealTimeRefusal(out taken) is { } refusal)
        {
            return refusal;
        }

        var maxWait = realTime ? _options.RealTimeMaxWait : _options.ScanMaxWait;
        VirusTotalLookupResult result;
        try
        {
            result = await _service.LookupAsync(request.Sha256, maxWait, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Refund(taken);
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Refund(taken);
            return Note(ScanNoteLevel.Warning, $"VirusTotal not checked: the lookup failed ({ex.GetType().Name}).");
        }

        if (!WasSent(result))
        {
            Refund(taken);
        }

        return VirusTotalVerdict.Map(result, _options);
    }

    /// <summary>
    /// Review D3 M3, real time only: the scan reserve (real time stops at <c>PerDay - ScanReserve</c> requests today) and the
    /// owner's share (<c>PerDay / RealTimeOwnerShare</c> per owner per UTC day; files with no user owner use the engine's share).
    /// Null when the request may go; <paramref name="taken"/> is then the owner count to refund if nothing is sent.
    /// </summary>
    private OnlineLookupOutcome? RealTimeRefusal(out string? taken)
    {
        taken = null;
        var status = _service.GetStatus();
        int realTimeLimit = Math.Max(0, status.PerDay - Math.Min(_options.ScanReserve, status.PerDay));
        if (status.UsedToday >= realTimeLimit)
        {
            return Note(ScanNoteLevel.Information,
                $"VirusTotal not checked: real-time scanning has used its part of today's budget ({realTimeLimit} of {status.PerDay}); the rest is kept for scans.");
        }

        int ownerCap = Math.Max(1, status.PerDay / _options.RealTimeOwnerShare);
        string owner = OnlineLookupOwner.Current ?? VirusTotalDayBudget.EngineKey;
        if (!_owners.TryTake(owner, ownerCap, out var key))
        {
            return Note(ScanNoteLevel.Information,
                $"VirusTotal not checked: the files of this user have used their share of today's budget ({ownerCap} requests).");
        }

        taken = key;
        return null;
    }

    /// <summary>A request went out (or may have): a live answer, an error after sending, a quota or key answer from the server.</summary>
    private static bool WasSent(VirusTotalLookupResult result) => result.Origin switch
    {
        VirusTotalOrigin.Live or VirusTotalOrigin.Error or VirusTotalOrigin.BadKey => true,
        VirusTotalOrigin.RateLimited => result.Status == VirusTotalStatus.QuotaExceeded,
        _ => false,
    };

    private void Refund(string? taken)
    {
        if (taken is not null)
        {
            _owners.Refund(taken);
        }
    }

    private static OnlineLookupOutcome Note(ScanNoteLevel level, string text) => new(null, new ScanNote(level, text));
}
