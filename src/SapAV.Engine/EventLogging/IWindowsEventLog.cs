using System.Diagnostics;

namespace SapAV.Engine.EventLogging;

/// <summary>
/// The few Windows Event Log operations the engine needs, behind an interface so tests use a fake
/// (no admin rights, no real registration). Implemented by <see cref="WindowsEventLog"/>.
/// </summary>
public interface IWindowsEventLog
{
    /// <summary>
    /// The log the event source is registered in (e.g. "Application"), or null if it isn't registered.
    /// Only reads the registry, so it works without admin rights.
    /// </summary>
    string? FindLogForSource(string source);

    /// <summary>Registers <paramref name="source"/> in <paramref name="logName"/>. Needs admin rights.</summary>
    void CreateSource(string source, string logName);

    /// <summary>Removes the registration of <paramref name="source"/>. Needs admin rights.</summary>
    void DeleteSource(string source);

    /// <summary>
    /// Writes one entry with ReportEvent. Must never register the source: callers check <see cref="FindLogForSource"/>
    /// first, and a missing source is skipped, not created.
    /// </summary>
    void ReportEvent(string source, string logName, string message, EventLogEntryType entryType, int eventId);
}
