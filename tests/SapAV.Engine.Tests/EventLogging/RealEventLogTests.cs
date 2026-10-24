using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using Microsoft.Win32;
using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.EventLogging;

/// <summary>
/// Against the real Windows Event Log. Runs only when elevated <b>and</b> opted in with <c>SAPAV_TEST_ALLOW_HKLM=1</c>,
/// so it skips on normal runs and in CI (GitHub's windows-latest is elevated, but doesn't opt in).
/// </summary>
/// <remarks>
/// It uses a throwaway <c>sap-AV-test-*</c> log + source (never "sap-AV", so a real installation isn't touched), first
/// removes stale ones left by an earlier crashed run (both B6 logs and B1-style Application sources), and removes its own
/// in <c>finally</c>. Left behind on purpose: the one test entry in the throwaway .evtx file under
/// <c>%SystemRoot%\System32\winevt\Logs</c> (the service keeps the file; it is not registry state) and the System-log
/// "log cleared" record.
/// </remarks>
public sealed class RealEventLogTests
{
    private const string TestPrefix = "sap-AV-test-";
    private const int ErrorAccessDenied = 5;

    [RequiresFact(Requires.RunningElevated, Requires.HklmWritesAllowed)]
    public void MigrateFromApplication_RestrictedCustomSd_NonAdminCantWrite_ProcessWritesAndReadsBack_Uninstall()
    {
        var eventLog = new WindowsEventLog();
        SweepStale(eventLog);

        var name = TestPrefix + Guid.NewGuid().ToString("N")[..12];
        var messageFile = ProtectedMessageFile();
        var installer = new EventLogSourceInstaller(eventLog, source: name, logName: name, messageFile: messageFile);
        var alert = SampleAlerts.Create();
        Exception? cleanupFailure = null;
        try
        {
            // A B1-style registration in the Application log, to be migrated.
            WriteLegacyApplicationSource(name, messageFile);
            Assert.Equal(["Application"], eventLog.FindLogsForSource(name));

            Assert.Equal(EventLogSourceInstallResult.Migrated, installer.Install().Result);
            Assert.Equal(EventLogSourceInstallResult.AlreadyRegistered, installer.Install().Result);
            Assert.Equal([name], eventLog.FindLogsForSource(name));

            // The CustomSD, read back from the registry and from the running Event Log service.
            var settings = eventLog.ReadLogSettings(name)!;
            Assert.True(EventLogCustomSd.IsExpected(settings.CustomSd), settings.CustomSd);
            Assert.Equal((EventLogSettings.Default.MaxSizeBytes, 0), (settings.MaxSizeBytes, settings.RetentionSeconds));
            Assert.True(EventLogCustomSd.IsExpected(ServiceSecurityDescriptor(name)));

            // A non-admin token can't write into it. Done before the process writes, so no earlier connection is reused.
            using (var nonAdmin = FilteredToken.CreateNonAdmin())
            {
                var denied = Assert.Throws<Win32Exception>(() => WindowsIdentity.RunImpersonated(nonAdmin,
                    () => eventLog.ReportEvent(name, name, "forged", EventLogEntryType.Error, AlertEventCatalog.MaliciousFileEventId)));
                Assert.Equal(ErrorAccessDenied, denied.NativeErrorCode);
            }

            // The elevated process (Administrators) can, through the sink.
            var sink = new EventLogAlertSink(eventLog, new ListLogger<EventLogAlertSink>(), TimeProvider.System) { SourceName = name, LogName = name };
            Assert.True(sink.TryWrite(alert));

            var records = ReadBack(name);
            var record = Assert.Single(records);
            Assert.Equal(AlertEventCatalog.MaliciousFileEventId, record.Id);
            Assert.Equal((byte)StandardEventLevel.Error, record.Level);
            Assert.Contains(alert.AlertId.ToString(), record.Properties[0].Value as string);
            foreach (var r in records)
            {
                r.Dispose();
            }
        }
        finally
        {
            // Never let a cleanup error replace the real assertion failure; report it only if the test passed.
            try
            {
                installer.Uninstall();
            }
            catch (Exception ex)
            {
                cleanupFailure = ex;
            }
        }

        Assert.Null(cleanupFailure);
        Assert.Empty(eventLog.FindLogsForSource(name));
        Assert.False(eventLog.LogExists(name));
    }

    /// <summary>
    /// Positive control for the test above (B6 review L3): the same filtered (non-admin) token that is refused by the sap-AV
    /// log CAN write to a throwaway log whose security descriptor allows Authenticated Users, so the refusal there comes from
    /// the CustomSD and not from the token being unable to write to any event log.
    /// </summary>
    [RequiresFact(Requires.RunningElevated, Requires.HklmWritesAllowed)]
    public void PositiveControl_FilteredToken_CanWriteToALogWhoseSdAllowsIt()
    {
        var eventLog = new WindowsEventLog();
        SweepStale(eventLog);

        var name = TestPrefix + "ctl-" + Guid.NewGuid().ToString("N")[..12];
        const string message = "sap-AV positive control entry";
        try
        {
            // A throwaway log + source whose SD lets Authenticated Users write: the same registration path as the real
            // installer, only the CustomSD differs (the Windows default for custom logs is not a stable thing to rely on).
            const string ordinarySd = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;AU)";
            eventLog.WriteLogSettings(name, new EventLogSettings(ordinarySd, 1024 * 1024, 0, false));
            eventLog.WriteSource(name, name, ProtectedMessageFile());
            _ = ServiceSecurityDescriptor(name); // wait until the service has loaded the new log

            using (var nonAdmin = FilteredToken.CreateNonAdmin())
            {
                WindowsIdentity.RunImpersonated(nonAdmin,
                    () => eventLog.ReportEvent(name, name, message, EventLogEntryType.Information, AlertEventCatalog.MaliciousFileEventId));
            }

            var records = ReadBack(name);
            try
            {
                Assert.Contains(records, r => r.Id == AlertEventCatalog.MaliciousFileEventId && r.Properties[0].Value as string == message);
            }
            finally
            {
                foreach (var r in records)
                {
                    r.Dispose();
                }
            }
        }
        finally
        {
            eventLog.DeleteLog(name);
        }

        Assert.False(eventLog.LogExists(name));
    }

    /// <summary>The .NET Framework 4 pass-through message DLL: in an admin-only Windows folder on every Windows 10/11.</summary>
    private static string ProtectedMessageFile()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll");
        Assert.True(File.Exists(path), $"Expected the .NET Framework message DLL at {path}.");
        Assert.Null(MessageFileLocationCheck.Instance.FindProblem(path));
        return path;
    }

    private static void WriteLegacyApplicationSource(string source, string messageFile)
    {
        using var entry = Registry.LocalMachine.CreateSubKey($@"SYSTEM\CurrentControlSet\Services\EventLog\Application\{source}");
        entry.SetValue("EventMessageFile", messageFile, RegistryValueKind.ExpandString);
    }

    private static void SweepStale(WindowsEventLog eventLog)
    {
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog");
        foreach (var log in root?.GetSubKeyNames() ?? [])
        {
            if (log.StartsWith(TestPrefix, StringComparison.OrdinalIgnoreCase))
            {
                eventLog.DeleteLog(log);
            }
        }

        using var application = root?.OpenSubKey("Application");
        foreach (var source in application?.GetSubKeyNames() ?? [])
        {
            if (source.StartsWith(TestPrefix, StringComparison.OrdinalIgnoreCase))
            {
                eventLog.DeleteSource(source, "Application");
            }
        }
    }

    private static string? ServiceSecurityDescriptor(string logName)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                using var config = new EventLogConfiguration(logName);
                return config.SecurityDescriptor;
            }
            catch (EventLogNotFoundException) when (attempt < 50)
            {
                Thread.Sleep(100);
            }
        }
    }

    private static List<EventRecord> ReadBack(string logName)
    {
        var query = new EventLogQuery(logName, PathType.LogName);
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                var records = new List<EventRecord>();
                using var reader = new EventLogReader(query);
                while (reader.ReadEvent() is { } record)
                {
                    records.Add(record);
                }

                if (records.Count > 0 || attempt >= 30)
                {
                    return records;
                }
            }
            catch (EventLogNotFoundException) when (attempt < 30)
            {
            }

            Thread.Sleep(100);
        }
    }
}
