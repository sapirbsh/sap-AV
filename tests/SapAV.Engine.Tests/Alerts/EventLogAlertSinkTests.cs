using System.Diagnostics;
using System.Security;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SapAV.Core.Alerts;
using SapAV.Engine.Alerts;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Alerts;

public sealed class EventLogAlertSinkTests
{
    private readonly FakeWindowsEventLog _eventLog = new();
    private readonly ListLogger<EventLogAlertSink> _logger = new();
    private readonly ManualTime _time = new();

    private EventLogAlertSink Sink() => new(_eventLog, _logger, _time);

    private void Register(string log = "sap-AV") => _eventLog.Register("sap-AV", log);

    [Fact]
    public async Task Write_RegisteredSource_WritesJsonWithTheCatalogIdAndEntryType()
    {
        Register();
        var alert = SampleAlerts.Create(AlertType.SuspiciousFile);

        await Sink().WriteAsync(alert);

        var entry = Assert.Single(_eventLog.Entries);
        Assert.Equal(("sap-AV", "sap-AV", 1002, EventLogEntryType.Warning),
            (entry.Source, entry.LogName, entry.EventId, entry.EntryType));
        Assert.Equal(alert, JsonSerializer.Deserialize<Alert>(entry.Message));
    }

    [Fact]
    public void Write_MissingSource_SkipsAndWarnsOnce_ThenRecovers_AfterTheRecheckInterval()
    {
        var sink = Sink();

        Assert.False(sink.TryWrite(SampleAlerts.Create()));
        Register(); // installer runs while the service is up
        Assert.False(sink.TryWrite(SampleAlerts.Create())); // not checked again yet
        Assert.Equal(1, _logger.Count(LogLevel.Warning));
        Assert.Contains("--install-eventlog-source", _logger.Lines[0].Message);

        _time.Now += EventLogAlertSink.RecheckInterval;
        Assert.True(sink.TryWrite(SampleAlerts.Create()));
        Assert.Single(_eventLog.Entries);
        Assert.Equal(1, _logger.Count(LogLevel.Information));
        Assert.Empty(_eventLog.Changes); // the sink never registers the source itself
    }

    [Fact]
    public void Write_SourceRemovedWhileRunning_NextWriteIsSkipped_NeverReRegistered()
    {
        Register();
        var sink = Sink();
        Assert.True(sink.TryWrite(SampleAlerts.Create()));

        _eventLog.Unregister("sap-AV"); // admin ran --uninstall-eventlog-source while the service is up

        Assert.False(sink.TryWrite(SampleAlerts.Create()));
        Assert.Single(_eventLog.Entries);
        Assert.Empty(_eventLog.FindLogsForSource("sap-AV"));
        Assert.Empty(_eventLog.Changes);
    }

    [Theory]
    [InlineData(AlertEventMessage.MinMessageChars - 1)]
    [InlineData(AlertEventMessage.EventLogStringLimit + 1)]
    public void MaxMessageChars_OutsideTheDocumentedRange_IsRejected(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new EventLogAlertSink(_eventLog, _logger, _time) { MaxMessageChars = value });
    }

    [Fact]
    public void Write_SourceInAnotherLog_IsNotUsed()
    {
        Register("System");

        Assert.False(Sink().TryWrite(SampleAlerts.Create()));
        Assert.Empty(_eventLog.Entries);
        Assert.Contains("'System'", Assert.Single(_logger.Lines).Message);
    }

    [Fact]
    public void Write_Failure_IsLoggedNotThrown_FirstAsWarningThenDebug()
    {
        Register();
        _eventLog.Failure = new SecurityException("access denied");
        var sink = Sink();

        Assert.False(sink.TryWrite(SampleAlerts.Create()));
        Assert.False(sink.TryWrite(SampleAlerts.Create()));

        Assert.Equal(1, _logger.Count(LogLevel.Warning));
        Assert.Equal(1, _logger.Count(LogLevel.Debug));
    }

    [Fact]
    public void Write_RegistryLookupThrows_DegradesGracefully()
    {
        _eventLog.LookupFailure = new UnauthorizedAccessException("registry denied");

        Assert.False(Sink().TryWrite(SampleAlerts.Create()));
        Assert.Equal(1, _logger.Count(LogLevel.Warning));
    }

    [Fact]
    public void Write_SourceStillInTheApplicationLog_IsSkippedWithOneHealthWarning_NeverWrittenThere()
    {
        Register("Application"); // installed by B1, --install-eventlog-source not rerun yet
        var sink = Sink();

        Assert.False(sink.TryWrite(SampleAlerts.Create()));
        _time.Now += EventLogAlertSink.RecheckInterval;
        Assert.False(sink.TryWrite(SampleAlerts.Create()));

        Assert.Empty(_eventLog.Entries);
        var warning = Assert.Single(_logger.Lines);
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains("not migrated", warning.Message);
        Assert.Contains("--install-eventlog-source", warning.Message);
        Assert.Empty(_eventLog.Changes);
    }

    [Fact]
    public void Write_SourceInTheDedicatedLogAndAnother_IsNotUsed()
    {
        Register();
        Register("Application");

        Assert.False(Sink().TryWrite(SampleAlerts.Create()));
        Assert.Empty(_eventLog.Entries);
        Assert.Contains("more than one log", Assert.Single(_logger.Lines).Message);
    }

    [Fact]
    public void Write_ConfiguredLogName_IsTheOneCheckedAndWritten()
    {
        Register("sap-AV-test-log");

        Assert.True(new EventLogAlertSink(_eventLog, _logger, _time) { LogName = "sap-AV-test-log" }.TryWrite(SampleAlerts.Create()));
        Assert.Equal("sap-AV-test-log", Assert.Single(_eventLog.Entries).LogName);
    }
}
