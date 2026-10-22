using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.EventLogging;

/// <summary>
/// Against the real Windows Event Log. Runs only when elevated <b>and</b> opted in with <c>SAPAV_TEST_ALLOW_HKLM=1</c>,
/// so it skips on normal runs and in CI (GitHub's windows-latest is elevated, but doesn't opt in).
/// It uses a throwaway <c>sap-AV-test-*</c> source (never "sap-AV", so a real installation isn't touched),
/// first removes stale ones left by an earlier crashed run, and removes its own at the end.
/// The written entry stays in the Application log, because single entries can't be deleted; it is harmless.
/// </summary>
public sealed class RealEventLogTests
{
    private const string TestSourcePrefix = "sap-AV-test-";

    [RequiresFact(Requires.RunningElevated, Requires.HklmWritesAllowed)]
    public void InstallWriteReadBackUninstall()
    {
        var eventLog = new WindowsEventLog();
        SweepStaleTestSources(eventLog);

        var source = TestSourcePrefix + Guid.NewGuid().ToString("N")[..12];
        var installer = new EventLogSourceInstaller(eventLog, source);
        var alert = SampleAlerts.Create();
        Exception? cleanupFailure = null;
        try
        {
            Assert.Equal(EventLogSourceInstallResult.Created, installer.Install(out _));
            Assert.Equal(EventLogSourceInstallResult.AlreadyRegistered, installer.Install(out _));
            Assert.Equal("Application", eventLog.FindLogForSource(source));

            var sink = new EventLogAlertSink(eventLog, new ListLogger<EventLogAlertSink>(), TimeProvider.System) { SourceName = source };
            Assert.True(sink.TryWrite(alert));

            using var record = ReadBack(source);
            Assert.NotNull(record);
            Assert.Equal(AlertEventCatalog.MaliciousFileEventId, record.Id);
            Assert.Equal((byte)StandardEventLevel.Error, record.Level);
            Assert.Contains(alert.AlertId.ToString(), record.Properties[0].Value as string);
        }
        finally
        {
            // Never let a cleanup error replace the real assertion failure; report it only if the test passed.
            try
            {
                installer.Uninstall(out _);
            }
            catch (Exception ex)
            {
                cleanupFailure = ex;
            }
        }

        Assert.Null(cleanupFailure);
        Assert.Null(eventLog.FindLogForSource(source));
    }

    private static void SweepStaleTestSources(WindowsEventLog eventLog)
    {
        using var application = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog\Application");
        foreach (var name in application?.GetSubKeyNames() ?? [])
        {
            if (name.StartsWith(TestSourcePrefix, StringComparison.OrdinalIgnoreCase))
            {
                eventLog.DeleteSource(name);
            }
        }
    }

    private static EventRecord? ReadBack(string source)
    {
        var query = new EventLogQuery("Application", PathType.LogName, $"*[System[Provider[@Name='{source}']]]");
        for (int attempt = 0; attempt < 20; attempt++)
        {
            using var reader = new EventLogReader(query);
            if (reader.ReadEvent() is { } record)
            {
                return record;
            }

            Thread.Sleep(100);
        }

        return null;
    }
}
