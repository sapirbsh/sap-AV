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

    private void Register(string log = "Application") => _eventLog.Sources["sap-AV"] = log;

    [Fact]
    public async Task Write_RegisteredSource_WritesJsonWithTheCatalogIdAndEntryType()
    {
        Register();
        var alert = SampleAlerts.Create(AlertType.SuspiciousFile);

        await Sink().WriteAsync(alert);

        var entry = Assert.Single(_eventLog.Entries);
        Assert.Equal(("sap-AV", "Application", 1002, EventLogEntryType.Warning),
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
        Assert.Equal(0, _eventLog.CreateCalls); // the sink never registers the source itself
    }

    [Fact]
    public void Write_SourceRemovedWhileRunning_NextWriteIsSkipped_NeverReRegistered()
    {
        Register();
        var sink = Sink();
        Assert.True(sink.TryWrite(SampleAlerts.Create()));

        _eventLog.Sources.Remove("sap-AV"); // admin ran --uninstall-eventlog-source while the service is up

        Assert.False(sink.TryWrite(SampleAlerts.Create()));
        Assert.Single(_eventLog.Entries);
        Assert.Empty(_eventLog.Sources);
        Assert.Equal(0, _eventLog.CreateCalls);
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
        var sink = new EventLogAlertSink(new ThrowingLookup(), _logger, _time);

        Assert.False(sink.TryWrite(SampleAlerts.Create()));
        Assert.Equal(1, _logger.Count(LogLevel.Warning));
    }

    private sealed class ThrowingLookup : SapAV.Engine.EventLogging.IWindowsEventLog
    {
        public string? FindLogForSource(string source) => throw new UnauthorizedAccessException("registry denied");

        public void CreateSource(string source, string logName) => throw new NotSupportedException();

        public void DeleteSource(string source) => throw new NotSupportedException();

        public void ReportEvent(string source, string logName, string message, EventLogEntryType entryType, int eventId) =>
            throw new NotSupportedException();
    }
}
