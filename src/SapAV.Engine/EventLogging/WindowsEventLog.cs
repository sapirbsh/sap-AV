using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.EventLogging;

/// <summary>The real <see cref="IWindowsEventLog"/>: registry reads, ReportEvent, and the installer's registry writes.</summary>
/// <remarks>
/// <para>
/// <b>Writing never registers a source.</b> <see cref="ReportEvent"/> goes straight to <c>RegisterEventSourceW</c> →
/// <c>ReportEventW</c> → <c>DeregisterEventSource</c>. These functions only open a handle and append a record; they
/// never create the registry key under <c>EventLog\&lt;log&gt;</c>. (For an unknown source, Windows writes to the
/// Application log with no message file; callers check <see cref="FindLogsForSource"/> first.) The managed
/// <c>EventLog.WriteEntry</c> / <c>WriteEvent</c> are <b>not</b> used anywhere in the engine: their
/// <c>VerifyAndCreateSource</c> calls <c>CreateEventSource</c> for a missing source, which as SYSTEM silently
/// re-registers a source an administrator just removed. A test (EventLogApiUsageTests) enforces this.
/// </para>
/// <para>
/// The registration methods write the classic Event Log registry layout directly (B6), instead of
/// <c>EventLog.CreateEventSource</c>, so the installer controls the order: the log key gets its restricted
/// <c>CustomSD</c> <b>before</b> the source exists, and the message file is the one the installer checked. This is the
/// only file in src/ that touches <c>Services\EventLog</c> (also enforced by EventLogApiUsageTests); it is used for
/// writes only by <see cref="EventLogSourceInstaller"/> from the elevated <c>--install-eventlog-source</c> /
/// <c>--uninstall-eventlog-source</c> commands.
/// </para>
/// </remarks>
public sealed class WindowsEventLog : IWindowsEventLog
{
    private const string EventLogKey = @"SYSTEM\CurrentControlSet\Services\EventLog";

    /// <summary>How long <see cref="WriteLogSettings"/> waits for the service to load a new log before relying on the registry.</summary>
    private static readonly TimeSpan ServiceLoadWait = TimeSpan.FromSeconds(5);

    /// <summary>The built-in logs: never deleted, whatever a caller passes.</summary>
    private static readonly HashSet<string> BuiltInLogs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Application", "System", "Security", "Setup", "ForwardedEvents", "HardwareEvents", "Internet Explorer",
        "Key Management Service", "Windows PowerShell", "State", "Parameters",
    };

    /// <summary>True for Windows' own classic logs (Application, System, Security, ...).</summary>
    public static bool IsBuiltInLog(string logName) => BuiltInLogs.Contains(logName);

    /// <remarks>
    /// <c>EventLog.SourceExists</c> and <c>EventLog.LogNameFromSourceName</c> throw a <see cref="SecurityException"/>
    /// for a normal user when the source is missing, because they can't search the Security log. This lookup skips
    /// logs it can't open instead.
    /// </remarks>
    public IReadOnlyList<string> FindLogsForSource(string source)
    {
        ValidateName(source, nameof(source));
        using var root = Registry.LocalMachine.OpenSubKey(EventLogKey, writable: false);
        if (root is null)
        {
            return [];
        }

        var found = new List<string>();
        foreach (var logName in root.GetSubKeyNames())
        {
            try
            {
                using var log = root.OpenSubKey(logName, writable: false);
                using var entry = log?.OpenSubKey(source, writable: false);
                if (entry is not null)
                {
                    found.Add(logName);
                }
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                // e.g. the Security log for a non-admin: skip it.
            }
        }

        return found;
    }

    public bool LogExists(string logName)
    {
        ValidateName(logName, nameof(logName));
        using var log = Registry.LocalMachine.OpenSubKey($@"{EventLogKey}\{logName}", writable: false);
        return log is not null;
    }

    public EventLogSettings? ReadLogSettings(string logName)
    {
        ValidateName(logName, nameof(logName));
        using var log = Registry.LocalMachine.OpenSubKey($@"{EventLogKey}\{logName}", writable: false);
        if (log is null)
        {
            return null;
        }

        return new EventLogSettings(
            log.GetValue("CustomSD") as string ?? string.Empty,
            log.GetValue("MaxSize") is int size ? size : 0,
            log.GetValue("Retention") is int retention ? retention : 0,
            log.GetValue("AutoBackupLogFiles") is int backup && backup != 0);
    }

    /// <remarks>
    /// CustomSD is written first, right after the key is created, then the other values. The Event Log service notices a
    /// new log key asynchronously; in case it loaded the log in the moment before CustomSD was set, the settings are also
    /// pushed to it with <see cref="EventLogConfiguration.SaveChanges"/> (EvtSaveChannelConfig). If the service hasn't
    /// loaded the log within <see cref="ServiceLoadWait"/>, it reads the registry values when it does.
    /// </remarks>
    public void WriteLogSettings(string logName, EventLogSettings settings)
    {
        ValidateName(logName, nameof(logName));
        ArgumentNullException.ThrowIfNull(settings);
        using (var root = OpenEventLogRoot())
        using (var log = root.CreateSubKey(logName, writable: true))
        {
            log.SetValue("CustomSD", settings.CustomSd, RegistryValueKind.String);
            log.SetValue("MaxSize", settings.MaxSizeBytes, RegistryValueKind.DWord);
            log.SetValue("Retention", settings.RetentionSeconds, RegistryValueKind.DWord);
            log.SetValue("AutoBackupLogFiles", settings.AutoBackup ? 1 : 0, RegistryValueKind.DWord);
        }

        ApplyToService(logName, settings);
    }

    public void WriteSource(string source, string logName, string messageFile)
    {
        ValidateName(source, nameof(source));
        ValidateName(logName, nameof(logName));
        ArgumentException.ThrowIfNullOrWhiteSpace(messageFile);
        using var root = OpenEventLogRoot();
        using var log = root.OpenSubKey(logName, writable: true)
                        ?? throw new InvalidOperationException($"The '{logName}' log is not registered.");
        using var entry = log.CreateSubKey(source, writable: true);
        entry.SetValue("EventMessageFile", messageFile, RegistryValueKind.ExpandString);
    }

    public string? ReadMessageFile(string source, string logName)
    {
        ValidateName(source, nameof(source));
        ValidateName(logName, nameof(logName));
        using var entry = Registry.LocalMachine.OpenSubKey($@"{EventLogKey}\{logName}\{source}", writable: false);
        return entry?.GetValue("EventMessageFile", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
    }

    public void DeleteSource(string source, string logName)
    {
        ValidateName(source, nameof(source));
        ValidateName(logName, nameof(logName));
        using var root = OpenEventLogRoot();
        using var log = root.OpenSubKey(logName, writable: true);
        log?.DeleteSubKeyTree(source, throwOnMissingSubKey: false);
    }

    /// <remarks>Only the registration is removed; the .evtx file stays (held by the service), as evidence.</remarks>
    public void DeleteLog(string logName)
    {
        ValidateName(logName, nameof(logName));
        if (IsBuiltInLog(logName))
        {
            throw new ArgumentException($"Refusing to delete the built-in '{logName}' log.", nameof(logName));
        }

        using var root = OpenEventLogRoot();
        root.DeleteSubKeyTree(logName, throwOnMissingSubKey: false);
    }

    public void ClearLog(string logName)
    {
        ValidateName(logName, nameof(logName));
        try
        {
            EventLogSession.GlobalSession.ClearLog(logName);
        }
        catch (EventLogNotFoundException)
        {
            // Not loaded by the service yet: nothing can have been written to it.
        }
    }

    /// <remarks>
    /// The event ID is passed to ReportEventW as is, the same as <c>EventLog.WriteEntry(message, type, eventID)</c>
    /// does (it also accepts only 0-65535): severity, customer and facility bits stay 0, so Event Viewer shows
    /// exactly 1001 / 1002 / 1003 / 3001, and the default .NET message file renders it as "%1" = our message.
    /// <paramref name="logName"/> is not passed to Windows (the registration decides the log); callers verify it
    /// with <see cref="FindLogsForSource"/>. On the sap-AV log, RegisterEventSourceW fails with ERROR_ACCESS_DENIED for
    /// anyone but SYSTEM and Administrators (its CustomSD, <see cref="EventLogCustomSd"/>).
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

    private static RegistryKey OpenEventLogRoot() =>
        Registry.LocalMachine.OpenSubKey(EventLogKey, writable: true)
        ?? throw new InvalidOperationException($@"HKLM\{EventLogKey} does not exist.");

    private static void ApplyToService(string logName, EventLogSettings settings)
    {
        var deadline = DateTime.UtcNow + ServiceLoadWait;
        while (true)
        {
            try
            {
                using var config = new EventLogConfiguration(logName);
                config.SecurityDescriptor = settings.CustomSd;
                config.MaximumSizeInBytes = settings.MaxSizeBytes;
                config.LogMode = settings.AutoBackup ? EventLogMode.AutoBackup
                    : settings.RetentionSeconds == 0 ? EventLogMode.Circular
                    : EventLogMode.Retain;
                config.SaveChanges();
                return;
            }
            catch (EventLogNotFoundException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(100);
            }
            catch (EventLogNotFoundException)
            {
                return; // not loaded yet: the service reads the registry values when it loads the log
            }
        }
    }

    /// <summary>A log or source name is one registry key name: no path separators or control characters.</summary>
    private static void ValidateName(string name, string paramName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name, paramName);
        if (name.Length > 255 || name.Any(c => c is '\\' or '/' || char.IsControl(c)))
        {
            throw new ArgumentException("Not a valid Event Log name.", paramName);
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
