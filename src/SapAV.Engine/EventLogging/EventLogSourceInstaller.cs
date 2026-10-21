namespace SapAV.Engine.EventLogging;

/// <summary>Outcome of <see cref="EventLogSourceInstaller.Install"/>.</summary>
public enum EventLogSourceInstallResult
{
    /// <summary>The source was missing and has been registered.</summary>
    Created,

    /// <summary>The source was already registered in the expected log; nothing changed.</summary>
    AlreadyRegistered,

    /// <summary>Refused: the source is registered in a different log. Nothing changed.</summary>
    RegisteredInOtherLog,
}

/// <summary>Outcome of <see cref="EventLogSourceInstaller.Uninstall"/>.</summary>
public enum EventLogSourceUninstallResult
{
    /// <summary>The source was registered in the expected log and has been removed.</summary>
    Removed,

    /// <summary>The source wasn't registered; nothing changed.</summary>
    NotRegistered,

    /// <summary>Refused: the source belongs to a different log (not ours to remove). Nothing changed.</summary>
    RegisteredInOtherLog,
}

/// <summary>
/// Registers the "sap-AV" Event Log source in the Application log (ROADMAP X2). Idempotent.
/// </summary>
/// <remarks>
/// Writing the registration needs admin rights, so this runs from the service installer path
/// (<c>SapAV.Engine --install-eventlog-source</c>, see <see cref="EngineCommands"/>), never at normal service
/// startup. System.Diagnostics.EventLog registers its default message file (a pass-through "%1" message), so
/// Event Viewer shows the JSON message as the event description.
/// </remarks>
public sealed class EventLogSourceInstaller
{
    private readonly IWindowsEventLog _eventLog;

    public EventLogSourceInstaller(
        IWindowsEventLog eventLog,
        string source = Alerts.AlertEventCatalog.SourceName,
        string logName = Alerts.AlertEventCatalog.LogName)
    {
        ArgumentNullException.ThrowIfNull(eventLog);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(logName);
        _eventLog = eventLog;
        Source = source;
        LogName = logName;
    }

    public string Source { get; }

    public string LogName { get; }

    /// <summary>Creates the source if missing; no-op if present; refuses if it is bound to a different log.</summary>
    /// <param name="registeredLog">The log the source is in afterwards (or the other log, when refused).</param>
    /// <exception cref="System.Security.SecurityException">Not running elevated (from the real Event Log API).</exception>
    public EventLogSourceInstallResult Install(out string? registeredLog)
    {
        registeredLog = _eventLog.FindLogForSource(Source);
        if (registeredLog is not null)
        {
            return IsExpectedLog(registeredLog)
                ? EventLogSourceInstallResult.AlreadyRegistered
                : EventLogSourceInstallResult.RegisteredInOtherLog;
        }

        _eventLog.CreateSource(Source, LogName);
        registeredLog = LogName;
        return EventLogSourceInstallResult.Created;
    }

    /// <summary>Removes the source if it is registered in our log; no-op if missing; refuses for another log.</summary>
    /// <exception cref="System.Security.SecurityException">Not running elevated (from the real Event Log API).</exception>
    public EventLogSourceUninstallResult Uninstall(out string? registeredLog)
    {
        registeredLog = _eventLog.FindLogForSource(Source);
        if (registeredLog is null)
        {
            return EventLogSourceUninstallResult.NotRegistered;
        }

        if (!IsExpectedLog(registeredLog))
        {
            return EventLogSourceUninstallResult.RegisteredInOtherLog;
        }

        _eventLog.DeleteSource(Source);
        return EventLogSourceUninstallResult.Removed;
    }

    private bool IsExpectedLog(string log) => string.Equals(log, LogName, StringComparison.OrdinalIgnoreCase);
}
