using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.EventLogging;

/// <summary>The real <see cref="IWindowsEventLog"/>: a read-only registry lookup, ReportEvent, and the installer calls.</summary>
/// <remarks>
/// <para>
/// <b>Writing never registers a source.</b> <see cref="ReportEvent"/> goes straight to <c>RegisterEventSourceW</c> →
/// <c>ReportEventW</c> → <c>DeregisterEventSource</c>. These functions only open a handle and append a record; they
/// never create the registry key under <c>EventLog\&lt;log&gt;</c>. (For an unknown source, Windows writes to the
/// Application log with no message file; callers check <see cref="FindLogForSource"/> first.) The managed
/// <c>EventLog.WriteEntry</c> / <c>WriteEvent</c> are <b>not</b> used anywhere in the engine: their
/// <c>VerifyAndCreateSource</c> calls <c>CreateEventSource</c> for a missing source, which as SYSTEM silently
/// re-registers a source an administrator just removed. A test (EventLogApiUsageTests) enforces this.
/// </para>
/// <para>
/// <see cref="CreateSource"/> and <see cref="DeleteSource"/> are the only registration calls; they are used only by
/// <see cref="EventLogSourceInstaller"/> from the elevated <c>--install-eventlog-source</c> /
/// <c>--uninstall-eventlog-source</c> commands.
/// </para>
/// </remarks>
public sealed class WindowsEventLog : IWindowsEventLog
{
    private const string EventLogKey = @"SYSTEM\CurrentControlSet\Services\EventLog";

    /// <remarks>
    /// <c>EventLog.SourceExists</c> and <c>EventLog.LogNameFromSourceName</c> throw a <see cref="SecurityException"/>
    /// for a normal user when the source is missing, because they can't search the Security log. This lookup skips
    /// logs it can't open instead.
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

    /// <summary>Registers the source (admin only). Only for <see cref="EventLogSourceInstaller"/>.</summary>
    public void CreateSource(string source, string logName) =>
        EventLog.CreateEventSource(new EventSourceCreationData(source, logName));

    /// <summary>Removes the source registration (admin only). Only for <see cref="EventLogSourceInstaller"/>.</summary>
    public void DeleteSource(string source) => EventLog.DeleteEventSource(source);

    /// <remarks>
    /// The event ID is passed to ReportEventW as is, the same as <c>EventLog.WriteEntry(message, type, eventID)</c>
    /// does (it also accepts only 0-65535): severity, customer and facility bits stay 0, so Event Viewer shows
    /// exactly 1001 / 1002 / 1003 / 3001, and the default .NET message file renders it as "%1" = our message.
    /// <paramref name="logName"/> is not passed to Windows (the registration decides the log); callers verify it
    /// with <see cref="FindLogForSource"/>.
    /// </remarks>
    /// <exception cref="Win32Exception">RegisterEventSourceW or ReportEventW failed (e.g. access denied, log full).</exception>
    public void ReportEvent(string source, string logName, string message, EventLogEntryType entryType, int eventId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentOutOfRangeException.ThrowIfNegative(eventId);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(eventId, ushort.MaxValue);
        if (!Enum.IsDefined(entryType))
        {
            throw new ArgumentOutOfRangeException(nameof(entryType), entryType, "Undefined entry type.");
        }

        using var handle = RegisterEventSourceW(null, source);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        // EventLogEntryType values are the EVENTLOG_*_TYPE constants (Error 1, Warning 2, Information 4).
        if (!ReportEventW(handle, (ushort)entryType, 0, (uint)eventId, IntPtr.Zero, 1, 0, [message], IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
    }

    [DllImport("advapi32.dll", EntryPoint = "RegisterEventSourceW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern EventSourceHandle RegisterEventSourceW(string? uncServerName, string sourceName);

    [DllImport("advapi32.dll", EntryPoint = "ReportEventW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReportEventW(
        EventSourceHandle eventLog, ushort type, ushort category, uint eventId, IntPtr userSid,
        ushort numStrings, uint dataSize, string[] strings, IntPtr rawData);

    [DllImport("advapi32.dll", EntryPoint = "DeregisterEventSource", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeregisterEventSource(IntPtr eventLog);

    private sealed class EventSourceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public EventSourceHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => DeregisterEventSource(handle);
    }
}
