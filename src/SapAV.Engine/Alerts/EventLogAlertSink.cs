using SapAV.Core.Alerts;
using SapAV.Engine.EventLogging;

namespace SapAV.Engine.Alerts;

/// <summary>
/// Writes each alert to the Windows Event Log (Application log, source "sap-AV"), as JSON
/// (<see cref="AlertEventMessage"/>) with the event ID and entry type from <see cref="AlertEventCatalog"/>.
/// </summary>
/// <remarks>
/// <para>
/// The source is registered only by the elevated service installer command (<see cref="EventLogSourceInstaller"/>);
/// this sink never registers it. Writes go through <see cref="IWindowsEventLog.ReportEvent"/> (ReportEventW), which
/// can't create a source, and before <b>every</b> write the registration is checked again (a registry read, inside the
/// lock; nothing is cached as "ready"). So if an administrator removes the source while the service runs, the next
/// alert is skipped instead of re-registering it.
/// </para>
/// <para>
/// If the source is missing or bound to another log, the alert is skipped, a warning is logged <b>once</b> (until the
/// source is usable again), and the check is repeated at most every <see cref="RecheckInterval"/>. A failed write
/// (log full, access denied, ...) is logged (the first failure as a warning, repeats at debug level) and never
/// thrown. Thread-safe: writes are serialised, as they are rare and fast.
/// </para>
/// </remarks>
public sealed class EventLogAlertSink : IAlertSink
{
    /// <summary>How long a missing or misplaced source is trusted to stay that way before it is checked again.</summary>
    public static readonly TimeSpan RecheckInterval = TimeSpan.FromMinutes(5);

    private readonly IWindowsEventLog _eventLog;
    private readonly ILogger<EventLogAlertSink> _logger;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private readonly int _maxMessageChars = AlertEventMessage.MaxMessageChars;

    private DateTimeOffset _skipUntil = DateTimeOffset.MinValue;
    private bool _unavailableLogged;
    private bool _writeFailureLogged;

    public EventLogAlertSink(IWindowsEventLog eventLog, ILogger<EventLogAlertSink> logger, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(eventLog);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(time);
        _eventLog = eventLog;
        _logger = logger;
        _time = time;
    }

    /// <summary>Event source name; "sap-AV" except in tests.</summary>
    public string SourceName { get; init; } = AlertEventCatalog.SourceName;

    /// <summary>Message cap (see <see cref="AlertEventMessage.Format"/>).</summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Not between <see cref="AlertEventMessage.MinMessageChars"/> and <see cref="AlertEventMessage.EventLogStringLimit"/>.
    /// </exception>
    public int MaxMessageChars
    {
        get => _maxMessageChars;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, AlertEventMessage.MinMessageChars);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, AlertEventMessage.EventLogStringLimit);
            _maxMessageChars = value;
        }
    }

    public ValueTask WriteAsync(Alert alert, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(alert);
        cancellationToken.ThrowIfCancellationRequested();
        TryWrite(alert);
        return ValueTask.CompletedTask;
    }

    /// <summary>Writes the alert; false if it was skipped (source unavailable) or the write failed. Never throws for I/O.</summary>
    public bool TryWrite(Alert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        var definition = AlertEventCatalog.For(alert.Type);
        var message = AlertEventMessage.Format(alert, _maxMessageChars);

        lock (_gate)
        {
            if (!SourceUsable())
            {
                return false;
            }

            try
            {
                _eventLog.ReportEvent(SourceName, AlertEventCatalog.LogName, message, definition.EntryType, definition.EventId);
                _writeFailureLogged = false;
                return true;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                LogWriteFailure(ex, alert);
                return false;
            }
        }
    }

    /// <summary>Checks the registration now (no cached "ready"), unless it was found unusable less than <see cref="RecheckInterval"/> ago.</summary>
    private bool SourceUsable()
    {
        var now = _time.GetUtcNow();
        if (now < _skipUntil)
        {
            return false;
        }

        string? log;
        try
        {
            log = _eventLog.FindLogForSource(SourceName);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Unavailable(now, $"its registration could not be read ({ex.GetType().Name}: {ex.Message})");
        }

        if (log is null)
        {
            return Unavailable(now, "it is not registered");
        }

        if (!string.Equals(log, AlertEventCatalog.LogName, StringComparison.OrdinalIgnoreCase))
        {
            return Unavailable(now, $"it is registered in the '{log}' log instead of {AlertEventCatalog.LogName}");
        }

        if (_unavailableLogged)
        {
            _logger.LogInformation("Event Log source '{Source}' is registered now; alerts are written to the Event Log again.", SourceName);
            _unavailableLogged = false;
        }

        return true;
    }

    private bool Unavailable(DateTimeOffset now, string why)
    {
        _skipUntil = now + RecheckInterval;
        if (!_unavailableLogged)
        {
            _unavailableLogged = true;
            _logger.LogWarning(
                "Alerts are not written to the Windows Event Log: source '{Source}' can't be used because {Why}. " +
                "Register it from an elevated prompt with: SapAV.Engine {Command}",
                SourceName, why, EngineCommands.InstallEventLogSource);
        }

        return false;
    }

    private void LogWriteFailure(Exception ex, Alert alert)
    {
        if (!_writeFailureLogged)
        {
            _writeFailureLogged = true;
            _logger.LogWarning(ex, "Writing alert {AlertId} to the Windows Event Log failed.", alert.AlertId);
        }
        else
        {
            _logger.LogDebug(ex, "Writing alert {AlertId} to the Windows Event Log failed again.", alert.AlertId);
        }
    }
}
