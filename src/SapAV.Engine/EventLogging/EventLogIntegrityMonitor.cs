using SapAV.Engine.Alerts;

namespace SapAV.Engine.EventLogging;

/// <summary>
/// Review B6 M2: the alert sink trusts the log's registration, but a GPO or <c>wevtutil sl sap-AV /ca:...</c> could widen
/// the log's security descriptor (CustomSD) later, so users could forge or flood events again, and the message DLL could
/// be moved somewhere writable. At startup and every <see cref="EventLogAlertSink.RecheckInterval"/> this reads the
/// <b>actual</b> CustomSD back (<see cref="EventLogCustomSd.IsExpected"/>) and re-checks the message DLL's location; on a
/// mismatch it logs an error and raises a "log integrity degraded" health alert
/// (<see cref="Core.Alerts.AlertType.EventLogIntegrityDegraded"/>, event 9009). Alerts keep being written (the log is
/// still the one only the engine's account is meant to write); nothing is changed here, the installer fixes it.
/// A log that isn't installed is skipped (the sink already warns about that).
/// </summary>
internal sealed class EventLogIntegrityMonitor(
    IWindowsEventLog eventLog, IMessageFileLocationCheck messageFiles, IAlertDispatcher alerts, TimeProvider time,
    ILogger<EventLogIntegrityMonitor> logger) : BackgroundService
{
    private bool _degraded;

    public string LogName { get; init; } = AlertEventCatalog.LogName;

    public string SourceName { get; init; } = AlertEventCatalog.SourceName;

    internal TimeSpan Interval { get; init; } = EventLogAlertSink.RecheckInterval;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                Check();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                logger.LogWarning(ex, "Checking the integrity of the '{Log}' event log failed; retrying later.", LogName);
            }

            try
            {
                await Task.Delay(Interval, time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Checks once; returns the problem (also logged and alerted), or null if the log is as installed or not installed.</summary>
    internal string? Check()
    {
        if (!eventLog.LogExists(LogName))
        {
            return null;
        }

        var problems = new List<string>();
        if (!EventLogCustomSd.IsExpected(eventLog.ReadLogSettings(LogName)?.CustomSd))
        {
            problems.Add("its security descriptor (CustomSD) is not the restricted SYSTEM + Administrators one, so others may be able to write or clear events.");
        }

        if (eventLog.ReadMessageFile(SourceName, LogName) is { Length: > 0 } messageFile && messageFiles.FindProblem(messageFile) is { } where)
        {
            problems.Add("its message DLL is in an unsafe place: " + where);
        }

        if (problems.Count == 0)
        {
            if (_degraded)
            {
                logger.LogInformation("The '{Log}' event log's integrity is restored.", LogName);
                _degraded = false;
            }

            return null;
        }

        string problem = string.Join(" ", problems);
        _degraded = true;
        logger.LogError("Event log integrity degraded for '{Log}': {Problem}", LogName, problem);
        alerts.Post(ScanAlerts.EventLogIntegrityDegraded(LogName, problem, time.GetUtcNow()), health: true);
        return problem;
    }
}
