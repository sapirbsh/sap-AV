using Microsoft.Win32.SafeHandles;
using SapAV.Core.Alerts;
using SapAV.Core.Scanning;
using SapAV.Engine.Alerts;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning.Native;

namespace SapAV.Engine.Scanning;

/// <summary>
/// The per-file step after a scan (B3): the quarantine decision, then the alert through the <see cref="IAlertDispatcher"/>
/// (bounded, aggregated, never blocking scanning).
/// </summary>
/// <remarks>
/// <para><b>Auto-quarantine</b> only for a scanned <b>Malicious</b> verdict (never Suspicious or PUP), only outside
/// protected locations (<see cref="AutoQuarantinePolicy"/>), only within the rate limit (<see cref="AutoQuarantineLimiter"/>;
/// the first refusal of a burst raises <see cref="AlertType.AutoQuarantineBurst"/>). Anything refused is
/// <see cref="ScanFileAction.NeedsUserConfirmation"/>; the file stays in place and B4 lets the user decide.</para>
/// <para><b>Bound to the scanned object.</b> The quarantine goes through the scan's own handle: it is reopened with
/// <c>ReOpenFile</c> (same file object, no path lookup) for read + DELETE + WRITE_DAC with share Read | Delete only, so
/// no writer can have it open (review B2 follow-up Low: the handle overload can't check the caller's sharing itself). A
/// file opened in the shared fallback (a writer had it open) fails that reopen and is reported Locked, not moved.</para>
/// <para>The alert ID is fixed before quarantining (it goes into the quarantine metadata), and the alert is written once,
/// with the action that was actually taken.</para>
/// <para><b>Budgets</b> (section B M1 / M2, <see cref="ScanBudget"/>): alerts and the auto-quarantine rate limit count
/// against the job's budget (the engine's per trigger, or the requesting user's), and a standard user's auto-quarantines
/// also against that user's quarantine quota. Note (review B4 L8): auto-quarantine of a Malicious file in a standard
/// user's job doesn't need DELETE for that user (as in a Full Scan); the quota and rate limit bound what it can cause.</para>
/// </remarks>
internal sealed class ScanVerdictHandler : IScanVerdictHandler
{
    private const uint QuarantineAccess = ScanNative.GenericRead | ScanNative.Delete | ScanNative.WriteDac;
    private const uint QuarantineShare = ScanNative.FileShareRead | ScanNative.FileShareDelete;

    private readonly IAlertDispatcher _alerts;
    private readonly IQuarantineService? _quarantine;
    private readonly AutoQuarantinePolicy _policy;
    private readonly AutoQuarantineLimiter _limiter;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public ScanVerdictHandler(
        IAlertDispatcher alerts, IQuarantineService? quarantine, AutoQuarantinePolicy policy, AutoQuarantineLimiter limiter,
        TimeProvider time, ILogger logger)
    {
        _alerts = alerts ?? throw new ArgumentNullException(nameof(alerts));
        _quarantine = quarantine;
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _limiter = limiter ?? throw new ArgumentNullException(nameof(limiter));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>The alert dispatcher (job-level alerts, e.g. the rules warning, go through it too).</summary>
    public IAlertDispatcher Alerts => _alerts;

    public async Task<ScanVerdictOutcome> HandleAsync(FileScanReport report, OpenedScanFile? opened, ScanBudget? budget, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        budget ??= new ScanBudget(report.Result.Item.Trigger);
        var alert = ScanAlerts.ForFile(report, AlertAction.None);
        if (alert is null)
        {
            return ScanVerdictOutcome.Nothing; // Clean or not scanned
        }

        var outcome = AutoQuarantinePolicy.IsEligibleVerdict(report)
            ? await DecideAndQuarantineAsync(report, opened, alert.AlertId, budget, cancellationToken).ConfigureAwait(false)
            : ScanVerdictOutcome.Nothing;

        _alerts.Post(ScanAlerts.WithAction(alert, ToAlertAction(outcome.Action)), budget.Alerts);
        return outcome with { AlertId = alert.AlertId };
    }

    public void JobFinished(ScanJob job) => _alerts.FlushSummary();

    private async Task<ScanVerdictOutcome> DecideAndQuarantineAsync(
        FileScanReport report, OpenedScanFile? opened, Guid alertId, ScanBudget budget, CancellationToken cancellationToken)
    {
        if (_policy.ProtectedReason(report, opened) is { } why)
        {
            _logger.LogWarning("Not quarantining {Path} automatically: {Why}. It needs the user's confirmation.", report.Result.Item.Path, why);
            return new(ScanFileAction.NeedsUserConfirmation, $"Not quarantined automatically: {why}. Confirm to quarantine it.");
        }

        if (_quarantine is not { IsAvailable: true } quarantine)
        {
            return new(ScanFileAction.QuarantineFailed, "The quarantine store is not available.");
        }

        if (!_limiter.TryAcquire(budget.Alerts.Key, out bool firstRefusal))
        {
            if (firstRefusal)
            {
                _alerts.Post(ScanAlerts.AutoQuarantineBurst(report.Result.Item.Path, report.Result.Item.Trigger, _limiter.MaxPerWindow,
                    _limiter.Window, _time.GetUtcNow()), budget.Alerts, health: true);
            }

            return new(ScanFileAction.NeedsUserConfirmation,
                $"Not quarantined automatically: more than {_limiter.MaxPerWindow} Malicious files in {_limiter.Window}. Confirm to quarantine it.");
        }

        QuarantineResult result;
        try
        {
            result = await QuarantineThroughScanHandleAsync(quarantine, report, opened!, alertId, budget.Quota, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException))
        {
            _logger.LogError(ex, "Quarantining {Path} failed unexpectedly; the file was left in place.", report.Result.Item.Path);
            return new(ScanFileAction.QuarantineFailed, $"Quarantine failed ({ex.GetType().Name}); the file was left in place.");
        }

        return OnQuarantineResult(report, result, budget);
    }

    private ScanVerdictOutcome OnQuarantineResult(FileScanReport report, QuarantineResult result, ScanBudget budget)
    {
        switch (result.Status)
        {
            case QuarantineStatus.Quarantined:
                return new(ScanFileAction.Quarantined, null, result.Entry?.Id);

            case QuarantineStatus.StoreFull:
                _alerts.Post(ScanAlerts.StoreFull(report.Result.Item.Path, report.Result.Verdict!.Value, report.Result.Item.Trigger,
                    result.Reason, _time.GetUtcNow()), budget.Alerts, health: true);
                return new(ScanFileAction.StoreFull, $"Not quarantined: {result.Reason}");

            default:
                return new(ScanFileAction.QuarantineFailed, $"Not quarantined ({result.Status}): {result.Reason}");
        }
    }

    private static async Task<QuarantineResult> QuarantineThroughScanHandleAsync(
        IQuarantineService quarantine, FileScanReport report, OpenedScanFile opened, Guid alertId, Quarantine.QuarantineRequester? requester,
        CancellationToken cancellationToken)
    {
        using SafeFileHandle? handle = ScanNative.ReOpen(opened.Handle, QuarantineAccess, QuarantineShare, out int error);
        if (handle is null)
        {
            return error switch
            {
                ScanNative.ErrorSharingViolation => new(QuarantineStatus.Locked,
                    "Another program has the file open for writing or without delete sharing; it was left in place."),
                ScanNative.ErrorAccessDenied => new(QuarantineStatus.AccessDenied, "The engine may not move or lock down this file."),
                _ => new(QuarantineStatus.Failed, $"The scanned file could not be reopened for quarantine (Win32 error {error})."),
            };
        }

        // The reopened handle (writers denied) now holds the scanned object; the scan's read handle isn't needed any more.
        opened.Dispose();
        return await quarantine.QuarantineHandleAsync(handle, report, alertId, cancellationToken, requester).ConfigureAwait(false);
    }

    private static AlertAction ToAlertAction(ScanFileAction action) => action switch
    {
        ScanFileAction.Quarantined => AlertAction.Quarantined,
        ScanFileAction.NeedsUserConfirmation => AlertAction.NeedsUserConfirmation,
        ScanFileAction.QuarantineFailed or ScanFileAction.StoreFull => AlertAction.QuarantineFailed,
        _ => AlertAction.None,
    };
}
