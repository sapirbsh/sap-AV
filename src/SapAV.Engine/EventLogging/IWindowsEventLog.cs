using System.Diagnostics;

namespace SapAV.Engine.EventLogging;

/// <summary>
/// The few Windows Event Log operations the engine needs, behind an interface so tests use a fake
/// (no admin rights, no real registration). Implemented by <see cref="WindowsEventLog"/>.
/// </summary>
/// <remarks>
/// Only <see cref="FindLogsForSource"/> and <see cref="ReportEvent"/> are for the running engine. Everything else changes
/// HKLM and is used only by <see cref="EventLogSourceInstaller"/> from the elevated installer commands.
/// </remarks>
public interface IWindowsEventLog
{
    /// <summary>
    /// Every log the event source is registered in (normally none or one, e.g. "sap-AV"). Only reads the registry, so it
    /// works without admin rights; logs that can't be read (the Security log for a normal user) are skipped.
    /// </summary>
    IReadOnlyList<string> FindLogsForSource(string source);

    /// <summary>True if the classic log <paramref name="logName"/> is registered.</summary>
    bool LogExists(string logName);

    /// <summary>The log's settings, or null if the log isn't registered. Values that are missing read as null / 0.</summary>
    EventLogSettings? ReadLogSettings(string logName);

    /// <summary>
    /// Creates the log if missing and writes <paramref name="settings"/> to it (CustomSD first), then applies them to the
    /// running Event Log service. Needs admin rights.
    /// </summary>
    void WriteLogSettings(string logName, EventLogSettings settings);

    /// <summary>Creates or updates the source under <paramref name="logName"/> with its message file. Needs admin rights.</summary>
    void WriteSource(string source, string logName, string messageFile);

    /// <summary>The source's registered message file, or null if the source isn't registered in that log.</summary>
    string? ReadMessageFile(string source, string logName);

    /// <summary>Removes <paramref name="source"/> from <paramref name="logName"/> only (no-op if missing). Needs admin rights.</summary>
    void DeleteSource(string source, string logName);

    /// <summary>Removes the log's registration with all its sources (no-op if missing). Needs admin rights.</summary>
    void DeleteLog(string logName);

    /// <summary>Clears every event in the log (no-op if the service hasn't loaded it). Needs clear rights.</summary>
    void ClearLog(string logName);

    /// <summary>
    /// Writes one entry with ReportEvent. Must never register the source: callers check <see cref="FindLogsForSource"/>
    /// first, and a missing source is skipped, not created.
    /// </summary>
    void ReportEvent(string source, string logName, string message, EventLogEntryType entryType, int eventId);
}
