using System.Diagnostics;
using System.Security;
using Microsoft.Win32;

namespace SapAV.Engine.EventLogging;

/// <summary>The real <see cref="IWindowsEventLog"/> (System.Diagnostics.EventLog plus a read-only registry lookup).</summary>
public sealed class WindowsEventLog : IWindowsEventLog
{
    private const string EventLogKey = @"SYSTEM\CurrentControlSet\Services\EventLog";

    /// <remarks>
    /// <see cref="EventLog.SourceExists(string)"/> and <see cref="EventLog.LogNameFromSourceName"/> throw a
    /// <see cref="SecurityException"/> for a normal user when the source is missing, because they can't search the
    /// Security log. This lookup skips logs it can't open instead. A source can't be registered in a log we can't
    /// read and also be the one we write to, so skipping is safe.
    /// </remarks>
    public string? FindLogForSource(string source)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        using var root = Registry.LocalMachine.OpenSubKey(EventLogKey, writable: false);
        if (root is null)
        {
            return null;
        }

        foreach (var logName in root.GetSubKeyNames())
        {
            try
            {
                using var log = root.OpenSubKey(logName, writable: false);
                using var entry = log?.OpenSubKey(source, writable: false);
                if (entry is not null)
                {
                    return logName;
                }
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                // e.g. the Security log for a non-admin: skip it.
            }
        }

        return null;
    }

    public void CreateSource(string source, string logName) =>
        EventLog.CreateEventSource(new EventSourceCreationData(source, logName));

    public void DeleteSource(string source) => EventLog.DeleteEventSource(source);

    public void WriteEntry(string source, string logName, string message, EventLogEntryType entryType, int eventId)
    {
        using var log = new EventLog(logName, ".", source);
        log.WriteEntry(message, entryType, eventId);
    }
}
