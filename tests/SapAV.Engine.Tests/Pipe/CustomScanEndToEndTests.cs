using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Engine.Tests.TestSupport;
using static SapAV.Engine.Tests.Pipe.PipeEndToEndTests;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>
/// C1 end to end: a Custom Scan of a folder and of a single file through the real pipe, the real scan worker
/// (unsandboxed test mode), the real verdict handler and quarantine; the results carry what the results screen needs.
/// The "malware" is a synthetic marker string that a test YARA rule flags.
/// </summary>
public sealed class CustomScanEndToEndTests
{
    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

    private static byte[] Marker() => [.. "sapav-b5-marker plus some padding text"u8];

    private static void WriteMotw(string path) =>
        File.WriteAllText(path + ":Zone.Identifier",
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://user:secret@downloads.example.test/files/dropper.bin?token=abc123#frag\r\n");

    [Fact]
    public async Task FolderScan_ByAStandardUser_ResultsCarryTemplatedReasons_Techniques_Signature_Url_Hash_AndAction()
    {
        await using var engine = new RealEngine(container: null);
        var dropper = engine.Quarantine.WriteFile("dropper.bin", Marker());
        WriteMotw(dropper);
        engine.Quarantine.WriteFile("readme.txt", "plain text"u8.ToArray());
        var client = await engine.ConnectAsync(new FakeClientIdentity());

        var created = await client.CreateScanAsync([engine.Quarantine.Files], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        await client.StartScanAsync(created.JobId, Timeout());
        await engine.ReadUntilAsync(client, JobState.Completed);
        Assert.True(engine.Dispatcher.Drain(TimeSpan.FromSeconds(30)));
        var details = await client.GetScanAsync(created.JobId, cancellationToken: Timeout());

        Assert.Equal(ScanTrigger.CustomScan, details.Summary.Trigger);
        var bad = Assert.Single(details.Results);
        Assert.Equal((ScanStatus.Scanned, Verdict.Malicious, FileAction.Quarantined), (bad.Status, bad.Verdict, bad.Action));
        Assert.NotNull(bad.Sha256);
        Assert.Null(bad.NotScannedReason);
        var reason = Assert.Single(bad.Reasons);
        Assert.StartsWith("Malicious: a YARA rule matched (MITRE ATT&CK T", reason, StringComparison.Ordinal);
        Assert.DoesNotContain("B5_Marker", reason, StringComparison.Ordinal); // worker text never reaches a standard user
        Assert.NotEmpty(bad.TechniqueIds);
        Assert.NotNull(bad.SignatureStatus);
        Assert.Equal("downloads.example.test", bad.SourceUrl); // review C1 M1: a standard user gets the host only
        var alert = Assert.Single(engine.Sink.Alerts);
        Assert.Equal((ScanTrigger.CustomScan, AlertAction.Quarantined), (alert.Trigger, alert.Action));
    }

    [Fact]
    public async Task FileScan_ByAnAdministrator_GetsTheScannerReasonText()
    {
        await using var engine = new RealEngine(container: null);
        var dropper = engine.Quarantine.WriteFile("single.bin", Marker());
        var client = await engine.ConnectAsync(new FakeClientIdentity(isAdmin: true));

        var created = await client.CreateScanAsync([dropper], Timeout());
        await client.SubscribeAsync(created.JobId, Timeout());
        await client.StartScanAsync(created.JobId, Timeout());
        await engine.ReadUntilAsync(client, JobState.Completed);
        var details = await client.GetScanAsync(created.JobId, cancellationToken: Timeout());

        var bad = Assert.Single(details.Results);
        Assert.Equal(Verdict.Malicious, bad.Verdict);
        Assert.Contains(bad.Reasons, r => r.Contains("B5_Marker", StringComparison.Ordinal));
        Assert.Null(bad.SourceUrl);
        Assert.Equal(1, details.Progress.FilesDone);
    }
}
