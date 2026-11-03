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

    public VirusTotalOnlineLookup(IVirusTotalService service, IOptions<VirusTotalOptions> options)
        : this(service, options.Value, (service as VirusTotalService)?.ProtectedMode ?? true)
    {
    }

    /// <param name="noteWhenUnavailable">False in a non-elevated debug run, where "unavailable" is expected.</param>
    internal VirusTotalOnlineLookup(IVirusTotalService service, VirusTotalOptions options, bool noteWhenUnavailable)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _noteWhenUnavailable = noteWhenUnavailable;
    }

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

        var maxWait = request.Item.Trigger == ScanTrigger.RealTime ? _options.RealTimeMaxWait : _options.ScanMaxWait;
        VirusTotalLookupResult result;
        try
        {
            result = await _service.LookupAsync(request.Sha256, maxWait, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Note(ScanNoteLevel.Warning, $"VirusTotal not checked: the lookup failed ({ex.GetType().Name}).");
        }

        return VirusTotalVerdict.Map(result, _options);
    }

    private static OnlineLookupOutcome Note(ScanNoteLevel level, string text) => new(null, new ScanNote(level, text));
}
