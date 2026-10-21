using SapAV.Core.Alerts;
using SapAV.Engine.EventLogging;

namespace SapAV.Engine.Alerts;

/// <summary>
/// Writes each alert to the Windows Event Log (Application log, source "sap-AV"), as JSON
/// (<see cref="AlertEventMessage"/>) with the event ID and entry type from <see cref="AlertEventCatalog"/>.
/// </summary>
/// <remarks>
/// <para>
/// The source is registered by the service installer (<see cref="EventLogSourceInstaller"/>), never here: an
/// unregistered source makes <c>EventLog.WriteEntry</c> try to register it, which a service must not do silently.
/// So before writing, the sink checks that the source exists and belongs to the Application log. If not, the
/// alert is skipped, a warning is logged <b>once</b> (until the source shows up again), and the check is repeated
/// at most every <see cref="RecheckInterval"/>.
/// </para>
/// <para>
/// A failed write (log full, access denied, ...) is logged (the first failure as a warning, repeats at debug level)
/// and never thrown. Thread-safe: writes are serialised, as they are rare and fast.
/// </para>
/// </remarks>
public sealed class EventLogAlertSink : IAlertSink
{
    /// <summary>How long a missing or misplaced source is trusted before it is checked again.</summary>
    public static readonly TimeSpan RecheckInterval = TimeSpan.FromMinutes(5);

    private readonly IWindowsEventLog _eventLog;
    private readonly ILogger<EventLogAlertSink> _logger;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();

    private bool _sourceReady;
    private DateTimeOffset _nextCheck = DateTimeOffset.MinValue;
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
    public int MaxMessageChars { get; init; } = AlertEventMessage.MaxMessageChars;

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
        var message = AlertEventMessage.Format(alert, MaxMessageChars);

        lock (_gate)
        {
            if (!EnsureSource())
            {
                return false;
            }

            try
            {
                _eventLog.WriteEntry(SourceName, AlertEventCatalog.LogName, message, definition.EntryType, definition.EventId);
                _writeFailureLogged = false;
                return true;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                LogWriteFailure(ex, alert);
                _sourceReady = false; // check the registration again before the next write
                _nextCheck = DateTimeOffset.MinValue;
                return false;
            }
        }
    }

    private bool EnsureSource()
    {
        if (_sourceReady)
        {
            return true;
        }

        var now = _time.GetUtcNow();
        if (now < _nextCheck)
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

        _sourceReady = true;
        return true;
    }

    private bool Unavailable(DateTimeOffset now, string why)
    {
        _nextCheck = now + RecheckInterval;
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
