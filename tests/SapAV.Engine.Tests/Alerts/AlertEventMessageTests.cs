using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Alerts;
using SapAV.Engine.Alerts;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Alerts;

public sealed class AlertEventMessageTests
{
    [Theory]
    [InlineData(AlertType.MaliciousFile, 1001, EventLogEntryType.Error)]
    [InlineData(AlertType.SuspiciousFile, 1002, EventLogEntryType.Warning)]
    [InlineData(AlertType.PotentiallyUnwantedFile, 1003, EventLogEntryType.Warning)]
    [InlineData(AlertType.QuarantineRestored, 3001, EventLogEntryType.Information)]
    public void Catalog_HasFixedEventIdAndEntryType(AlertType type, int eventId, EventLogEntryType entryType)
    {
        Assert.Equal(new AlertEventDefinition(eventId, entryType), AlertEventCatalog.For(type));
    }

    [Fact]
    public void Catalog_CoversEveryAlertType_WithUniqueIds()
    {
        var ids = Enum.GetValues<AlertType>().Select(t => AlertEventCatalog.For(t).EventId).ToArray();

        Assert.Equal(ids.Length, ids.Distinct().Count());
        Assert.Throws<ArgumentOutOfRangeException>(() => AlertEventCatalog.For((AlertType)99));
    }

    [Fact]
    public void Format_SmallAlert_IsTheFullAlertJson_OnOneAsciiLine()
    {
        var alert = SampleAlerts.Create(path: "C:\\Users\\\u05D3\u05E0\u05D4\\Downloads\\inv\u202Efdp.exe");

        var message = AlertEventMessage.Format(alert);

        Assert.Equal(alert, JsonSerializer.Deserialize<Alert>(message));
        Assert.All(message, c => Assert.InRange(c, ' ', '~')); // ASCII only: no raw bidi, no line breaks
        Assert.Contains("\\u202E", message);
        Assert.DoesNotContain("Omitted", message);
    }

    [Fact]
    public void Format_PercentSigns_AreEscaped_SoFormatMessageCantExpandThem()
    {
        var alert = SampleAlerts.Create(path: @"C:\Users\test\Downloads\%%1001 %1 100%.exe", reasons: ["matched %%3001"]);

        var message = AlertEventMessage.Format(alert);

        Assert.DoesNotContain('%', message);
        Assert.Contains(@"\u0025\u00251001", message);
        Assert.Equal(alert, JsonSerializer.Deserialize<Alert>(message));
    }

    [Fact]
    public void Format_ManyLongReasons_DropsReasonsFromTheEnd_KeepsIdentifyingFields()
    {
        var reasons = Enumerable.Range(0, 200).Select(i => $"reason {i:D3} " + new string('r', 1000)).ToArray();
        var alert = SampleAlerts.Create(reasons: reasons);

        var message = AlertEventMessage.Format(alert);
        var node = JsonNode.Parse(message)!.AsObject();
        var copy = JsonSerializer.Deserialize<Alert>(message)!;

        Assert.InRange(message.Length, 1, AlertEventMessage.MaxMessageChars);
        Assert.Equal(reasons.Take(copy.Reasons.Count), copy.Reasons); // a prefix: worst-first order kept
        Assert.InRange(copy.Reasons.Count, 20, 199);
        Assert.Equal(200 - copy.Reasons.Count, (int)node["ReasonsOmitted"]!);
        Assert.Equal((alert.AlertId, alert.Sha256, alert.FilePath, alert.TechniqueId, alert.SourceUrl),
            (copy.AlertId, copy.Sha256, copy.FilePath, copy.TechniqueId, copy.SourceUrl));
    }

    [Fact]
    public void Format_PathNearTheWindowsLimit_IsShortenedInTheMiddle_OnlyAsALastResort()
    {
        // 32,000 non-ASCII characters escape to ~192 KB of JSON.
        var path = @"C:\" + new string('\u05D0', 16_000) + @"\" + new string('\u05D1', 15_990) + ".exe";
        var alert = SampleAlerts.Create(path: path);

        var message = AlertEventMessage.Format(alert);
        var node = JsonNode.Parse(message)!.AsObject();
        var copy = JsonSerializer.Deserialize<Alert>(message)!;

        Assert.InRange(message.Length, 1, AlertEventMessage.MaxMessageChars);
        Assert.True((bool)node["FilePathTruncated"]!);
        Assert.True((bool)node["SourceUrlOmitted"]!);
        Assert.StartsWith(@"C:\", copy.FilePath);
        Assert.EndsWith(".exe", copy.FilePath);
        Assert.Contains("\u2026", copy.FilePath);
        Assert.Equal((alert.AlertId, alert.Sha256, alert.Type), (copy.AlertId, copy.Sha256, copy.Type));
    }
}
