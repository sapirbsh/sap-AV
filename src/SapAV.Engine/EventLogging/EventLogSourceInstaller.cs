using System.Diagnostics;

namespace SapAV.Engine.EventLogging;

/// <summary>Outcome of <see cref="EventLogSourceInstaller.Install"/>.</summary>
public enum EventLogSourceInstallResult
{
    /// <summary>The log and source were missing and have been created.</summary>
    Created,

    /// <summary>The source was in the Application log (B1's layout); it was removed there and created in the dedicated log.</summary>
    Migrated,

    /// <summary>The source was already in the dedicated log; its settings and message file were written again.</summary>
    AlreadyRegistered,

    /// <summary>Refused: the source is registered in a log other than ours or Application. Nothing changed.</summary>
    RegisteredInOtherLog,

    /// <summary>Refused: the message DLL is not in an admin-only location (B1 review M3). Nothing changed.</summary>
    MessageFileNotProtected,
}

/// <summary>Outcome of <see cref="EventLogSourceInstaller.Uninstall"/>.</summary>
public enum EventLogSourceUninstallResult
{
    /// <summary>The dedicated log and/or a leftover Application-log source were removed.</summary>
    Removed,

    /// <summary>Neither was registered; nothing changed.</summary>
    NotRegistered,

    /// <summary>Refused: the source belongs to a different log (not ours to remove). Nothing changed.</summary>
    RegisteredInOtherLog,
}

/// <summary>What <see cref="EventLogSourceInstaller.Install"/> did.</summary>
/// <param name="Detail">The other log (<see cref="EventLogSourceInstallResult.RegisteredInOtherLog"/>) or the reason the message file was refused.</param>
public sealed record EventLogInstallOutcome(EventLogSourceInstallResult Result, string? Detail = null);

/// <summary>What <see cref="EventLogSourceInstaller.Uninstall"/> did.</summary>
/// <param name="OtherLog">The conflicting log, for <see cref="EventLogSourceUninstallResult.RegisteredInOtherLog"/>.</param>
public sealed record EventLogUninstallOutcome(EventLogSourceUninstallResult Result, string? OtherLog = null);

/// <summary>
/// Registers the "sap-AV" source in its own, dedicated "sap-AV" event log (ROADMAP B6 / X2 M1) with a restricted
/// <c>CustomSD</c> (<see cref="EventLogCustomSd"/>), so only SYSTEM and Administrators can write alerts. Idempotent.
/// </summary>
/// <remarks>
/// <para>
/// Writing the registration needs admin rights, so this runs from the service installer path
/// (<c>SapAV.Engine --install-eventlog-source</c>, see <see cref="EngineCommands"/>), never at normal service startup.
/// </para>
/// <para>
/// Install, in this order (each step is safe to repeat, so a rerun completes an interrupted install):
/// <list type="number">
/// <item>Refuse unless the message DLL is in an admin-only location (<see cref="IMessageFileLocationCheck"/>, B1 M3).</item>
/// <item>Refuse if the source is registered in any log other than ours and Application.</item>
/// <item>Migration: if the source is in Application (B1), remove it there first. Until step 4 is done, the source is
/// missing and the running engine skips alerts (it never writes to Application).</item>
/// <item>Create the log (or rewrite its settings) with CustomSD, then create the source with the checked message file.</item>
/// <item>A freshly created log is cleared once, so nothing written in the moment before its CustomSD took effect survives.</item>
/// <item>Read the CustomSD and the message file back; a mismatch is an error.</item>
/// </list>
/// Uninstall removes the dedicated log (with the source) and a leftover Application-log source, and refuses (changing
/// nothing) if the source is in some other log.
/// </para>
/// </remarks>
public sealed class EventLogSourceInstaller
{
    /// <summary>B1's log: a source found there is migrated, never left in place.</summary>
    public const string LegacyLogName = "Application";

    private readonly IWindowsEventLog _eventLog;
    private readonly IMessageFileLocationCheck _locationCheck;

    /// <param name="messageFile">
    /// The message DLL to register; default <see cref="DefaultMessageFile"/>. The service installer (D3) may pass a copy
    /// in a protected folder.
    /// </param>
    public EventLogSourceInstaller(
        IWindowsEventLog eventLog,
        IMessageFileLocationCheck? locationCheck = null,
        string source = Alerts.AlertEventCatalog.SourceName,
        string logName = Alerts.AlertEventCatalog.LogName,
        string? messageFile = null)
    {
        ArgumentNullException.ThrowIfNull(eventLog);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(logName);
        if (WindowsEventLog.IsBuiltInLog(logName))
        {
            throw new ArgumentException($"The alerts need a dedicated log, not the built-in '{logName}' log.", nameof(logName));
        }

        _eventLog = eventLog;
        _locationCheck = locationCheck ?? MessageFileLocationCheck.Instance;
        Source = source;
        LogName = logName;
        MessageFile = messageFile ?? DefaultMessageFile();
    }

    public string Source { get; }

    public string LogName { get; }

    public string MessageFile { get; }

    /// <summary>The log settings written: always <see cref="EventLogSettings.Default"/> (restricted CustomSD, 20 MB, overwrite).</summary>
    public EventLogSettings Settings => EventLogSettings.Default;

    /// <summary>
    /// The pass-through ("%1") message DLL that ships next to System.Diagnostics.EventLog.dll, i.e. the one
    /// <c>EventLog.CreateEventSource</c> would register by default.
    /// </summary>
    public static string DefaultMessageFile()
    {
        var folder = Path.GetDirectoryName(typeof(EventLog).Assembly.Location);
        return Path.Combine(string.IsNullOrEmpty(folder) ? AppContext.BaseDirectory : folder,
            "System.Diagnostics.EventLog.Messages.dll");
    }

    /// <summary>Creates, migrates or re-applies the registration; refuses (changing nothing) as described in the remarks.</summary>
    /// <exception cref="System.Security.SecurityException">Not running elevated (from the registry API).</exception>
    /// <exception cref="InvalidOperationException">The settings read back differ from what was written.</exception>
    public EventLogInstallOutcome Install()
    {
        if (_locationCheck.FindProblem(MessageFile) is { } problem)
        {
            return new(EventLogSourceInstallResult.MessageFileNotProtected, problem);
        }

        var logs = _eventLog.FindLogsForSource(Source);
        if (logs.FirstOrDefault(l => !IsOurLog(l) && !IsLegacyLog(l)) is { } other)
        {
            return new(EventLogSourceInstallResult.RegisteredInOtherLog, other);
        }

        bool migrating = logs.Any(IsLegacyLog);
        if (migrating)
        {
            _eventLog.DeleteSource(Source, LegacyLogName);
        }

        bool logCreated = !_eventLog.LogExists(LogName);
        _eventLog.WriteLogSettings(LogName, Settings);
        _eventLog.WriteSource(Source, LogName, MessageFile);
        if (logCreated)
        {
            _eventLog.ClearLog(LogName);
        }

        Verify();
        return new(migrating ? EventLogSourceInstallResult.Migrated
            : logCreated || !logs.Any(IsOurLog) ? EventLogSourceInstallResult.Created
            : EventLogSourceInstallResult.AlreadyRegistered);
    }

    /// <summary>Removes the dedicated log and a leftover Application source; no-op if neither exists; refuses for another log.</summary>
    /// <exception cref="System.Security.SecurityException">Not running elevated (from the registry API).</exception>
    public EventLogUninstallOutcome Uninstall()
    {
        var logs = _eventLog.FindLogsForSource(Source);
        if (logs.FirstOrDefault(l => !IsOurLog(l) && !IsLegacyLog(l)) is { } other)
        {
            return new(EventLogSourceUninstallResult.RegisteredInOtherLog, other);
        }

        bool removed = false;
        if (logs.Any(IsLegacyLog))
        {
            _eventLog.DeleteSource(Source, LegacyLogName);
            removed = true;
        }

        if (_eventLog.LogExists(LogName))
        {
            _eventLog.DeleteLog(LogName);
            removed = true;
        }

        return new(removed ? EventLogSourceUninstallResult.Removed : EventLogSourceUninstallResult.NotRegistered);
    }

    private void Verify()
    {
        var settings = _eventLog.ReadLogSettings(LogName);
        if (settings is null || !EventLogCustomSd.IsExpected(settings.CustomSd) || settings.MaxSizeBytes != Settings.MaxSizeBytes
            || settings.RetentionSeconds != Settings.RetentionSeconds || settings.AutoBackup != Settings.AutoBackup)
        {
            throw new InvalidOperationException(
                $"The '{LogName}' log's settings read back differ from the ones written (CustomSD '{settings?.CustomSd}').");
        }

        var logs = _eventLog.FindLogsForSource(Source);
        if (logs.Count != 1 || !IsOurLog(logs[0])
            || !string.Equals(_eventLog.ReadMessageFile(Source, LogName), MessageFile, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Source '{Source}' did not end up registered only in the '{LogName}' log with the checked message file.");
        }
    }

    private bool IsOurLog(string log) => string.Equals(log, LogName, StringComparison.OrdinalIgnoreCase);

    private static bool IsLegacyLog(string log) => string.Equals(log, LegacyLogName, StringComparison.OrdinalIgnoreCase);
}
