using System.Diagnostics.Eventing.Reader;
using SapAV.Core.Alerts;
using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.EventLogging;

/// <summary>
/// Against the real Windows Event Log. Needs an elevated test run, so it skips on normal runs and in CI.
/// Uses its own throwaway source name (never "sap-AV", so a real installation isn't touched) and always removes it.
/// The written entry stays in the Application log (single entries can't be deleted); it is harmless.
/// </summary>
public sealed class RealEventLogTests
{
    [RequiresFact(Requires.RunningElevated)]
    public void InstallWriteReadBackUninstall()
    {
        var source = "sap-AV-test-" + Guid.NewGuid().ToString("N")[..12];
        var eventLog = new WindowsEventLog();
        var installer = new EventLogSourceInstaller(eventLog, source);
        var alert = SampleAlerts.Create();
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
            installer.Uninstall(out _);
        }

        Assert.Null(eventLog.FindLogForSource(source));
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
