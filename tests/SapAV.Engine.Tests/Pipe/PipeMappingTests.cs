using System.Text;
using System.Text.Json;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

public sealed class PipeMappingTests
{
    [Fact]
    public void EveryEngineEnumValue_HasAWireName()
    {
        foreach (var v in Enum.GetValues<ScanJobState>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<ScanFileAction>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<QuarantineStatus>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<RestoreStatus>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
        foreach (var v in Enum.GetValues<QuarantineEntryIntegrity>()) { Assert.Equal(v.ToString(), PipeMapping.Map(v).ToString()); }
    }

    [Fact]
    public void ResultDetail_NeverCarriesScanWorkerText()
    {
        var notScanned = new ScanJobFileResult(@"C:\x\a.bin", ScanStatus.Error, null, ScanFileAction.None,
            "The scan worker could not scan the file: <secret file content from the worker>", null, null, null);
        var refused = new ScanJobFileResult(@"C:\x\b.bin", ScanStatus.Scanned, Verdict.Malicious, ScanFileAction.NeedsUserConfirmation,
            "Not quarantined automatically: protected system folder.\u200B\r\nFAKE", null, null, null);

        Assert.Equal("Not scanned (Error).", PipeMapping.Result(0, notScanned).Detail);
        Assert.Equal("Not quarantined automatically: protected system folder.\uFFFD  FAKE", PipeMapping.Result(1, refused).Detail);
    }

    [Fact]
    public void QuarantineReasons_AreCappedAndInvisibleCharactersMapped_PathsKeptExactButFlagged()
    {
        var entry = RecordingQuarantine.Entry("C:\\x\\inv\u202Efdp.exe",
            reasons: [.. Enumerable.Range(0, 20).Select(i => $"rule {i} \u2063" + new string('r', 500))]);

        var item = PipeMapping.Item(entry);

        Assert.Equal(PipeMapping.MaxReasons, item.Reasons.Count);
        Assert.All(item.Reasons, r =>
        {
            Assert.True(r.Length <= PipeMapping.MaxReasonLength);
            Assert.DoesNotContain('\u2063', r);
        });
        Assert.Equal("C:\\x\\inv\u202Efdp.exe", item.OriginalPath!.Value);
        Assert.True(item.OriginalPath.HasHiddenCharacters);
    }

    [Fact]
    public void ServerFrames_RoundTripWithTheStrictOptions_AndEscapeBidi()
    {
        var progress = new JobProgressInfo(Guid.NewGuid(), JobState.Running, 3, null, 1, 10, null, WirePath.From("C:\\a\u202Eb"), null,
            TimeSpan.FromSeconds(2), new JobCountersInfo(1, 0, 0, 0, 0, 0, 0, 0));
        var frame = new PipeFrame(PipeFrameKind.Event, Event: PipeEventKind.JobProgress, Body: PipeJson.ToElement(progress));

        byte[] bytes = PipeJson.Serialize(frame, PipeProtocol.MaxServerFrameBytes);
        var back = JsonSerializer.Deserialize<PipeFrame>(bytes, PipeJson.Options)!;

        Assert.Contains("\\u202E", Encoding.UTF8.GetString(bytes), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(progress.CurrentFile, PipeJson.Body<JobProgressInfo>(back.Body).CurrentFile);
    }
}
