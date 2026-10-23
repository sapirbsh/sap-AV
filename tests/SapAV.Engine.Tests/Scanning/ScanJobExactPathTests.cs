using System.Text;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// B3 review H1: names ending in a dot or space. Win32 normalisation strips them, so they must neither hide behind an
/// excluded folder, nor be unlistable, nor be judged by the harmless file of the stripped name.
/// </summary>
public sealed class ScanJobExactPathTests
{
    /// <summary>Creates a file at an exact path (\\?\ form, so trailing dots/spaces stay).</summary>
    private static string WriteExact(string path, string content)
    {
        Directory.CreateDirectory(@"\\?\" + Path.GetDirectoryName(path));
        File.WriteAllText(@"\\?\" + path, content);
        return path;
    }

    /// <summary>The fake broker judges by content: "PAYLOAD" is Malicious, everything else Clean.</summary>
    private static void JudgeByContent(FakeScanBroker broker) =>
        broker.OnScan = (item, file, _) =>
        {
            var report = FakeScanBroker.Judge(item, file, TimeProvider.System);
            var bytes = new byte[RandomAccess.GetLength(file.Handle)];
            RandomAccess.Read(file.Handle, bytes, 0);
            if (!Encoding.ASCII.GetString(bytes).Contains("PAYLOAD", StringComparison.Ordinal))
            {
                return Task.FromResult<FileScanReport?>(report with { Result = ScanResult.Clean(item, DateTimeOffset.UtcNow, report.Result.Sha256) });
            }

            var detection = new Detection(Verdict.Malicious, "YARA rule Payload matched", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara);
            return Task.FromResult<FileScanReport?>(report with { Result = new ScanResult(item, [detection], DateTimeOffset.UtcNow, report.Result.Sha256) });
        };

    [Fact]
    public async Task ExcludedFolderLookalike_WithATrailingDot_IsScanned_NotExcluded()
    {
        using var h = new ScanJobHarness();
        h.Excluded.Add(Path.Combine(h.Root, "sap-AV"));
        h.Write(@"sap-AV\rules\self.yar", "rule");
        WriteExact(Path.Combine(h.Root, "sap-AV.", "dropped.exe"), "PAYLOAD");
        JudgeByContent(h.Broker);

        var (job, _) = h.Start();
        await JobWait.Done(job);

        var result = Assert.Single(job.Results);
        Assert.EndsWith(@"sap-AV.\dropped.exe", result.Path, StringComparison.Ordinal);
        Assert.Equal(Verdict.Malicious, result.Verdict);
        Assert.Equal(1, job.GetProgress().Counters.Excluded); // only the real folder

        var set = new FolderSet([@"C:\ProgramData\sap-AV"]);
        Assert.False(set.Contains(@"C:\ProgramData\sap-AV.\x.exe"));
        Assert.False(set.Contains(@"\\?\C:\ProgramData\sap-AV \x.exe"));
        Assert.True(set.Contains(@"\\?\c:\programdata\SAP-AV\x.exe"));
        Assert.True(set.Contains(@"C:\ProgramData\other\..\sap-AV\x.exe"));
    }

    [Fact]
    public async Task FoldersEndingInADotOrSpace_AreListed_AndTheirFilesScanned()
    {
        using var h = new ScanJobHarness();
        WriteExact(Path.Combine(h.Root, "x.", "inner.bin"), "PAYLOAD");
        WriteExact(Path.Combine(h.Root, "y ", "deeper.", "inner2.bin"), "PAYLOAD");
        JudgeByContent(h.Broker);

        var (job, _) = h.Start();
        await JobWait.Done(job);

        Assert.Equal(0, job.Skipped.UnreadableFolders);
        Assert.Equal(2, job.GetProgress().Counters.Malicious);
        Assert.All(job.Results, r => Assert.Equal(ScanStatus.Scanned, r.Status));
    }

    [Fact]
    public async Task TrailingDotPayload_NextToAHarmlessDecoy_IsJudgedItself_NeverAsTheDecoy()
    {
        using var h = new ScanJobHarness();
        var decoy = h.Write("evil.exe", "harmless");
        var payload = WriteExact(decoy + ".", "PAYLOAD");
        JudgeByContent(h.Broker);

        var (walked, _) = h.Start();                // found by the walk
        var (direct, _) = h.Start(payload);         // and given as a plain root path
        await JobWait.Done(walked);
        await JobWait.Done(direct);

        foreach (var job in new[] { walked, direct })
        {
            var result = Assert.Single(job.Results); // the decoy is Clean and only counted
            Assert.EndsWith("evil.exe.", result.Path, StringComparison.Ordinal);
            Assert.True(result.Verdict == Verdict.Malicious || result.Status != ScanStatus.Scanned);
        }

        Assert.Equal(1, walked.GetProgress().Counters.Clean);
    }

    [Fact]
    public void Open_OfATrailingDotName_ReachesThatFile_AndAMismatchedHandleIsNotJudged()
    {
        using var h = new ScanJobHarness();
        var decoy = h.Write("tool.exe", "harmless");
        var payload = WriteExact(decoy + ".", "PAYLOAD");

        using (var opened = ScanFileOpener.Open(new ScanItem(payload, ScanTrigger.CustomScan), [], TimeProvider.System, out _)!)
        {
            Assert.EndsWith("tool.exe.", opened.Identity!.FinalPath, StringComparison.Ordinal); // SecureFile opened it exactly
            Assert.Null(ScanFilePipeline.DifferentFile(new ScanItem(payload, ScanTrigger.CustomScan), opened));
            Assert.StartsWith(@"\\?\", ScanFilePipeline.Canonical(new ScanItem(payload, ScanTrigger.CustomScan), opened).Path, StringComparison.Ordinal);
        }

        using var decoyHandle = ScanFileOpener.Open(new ScanItem(decoy, ScanTrigger.CustomScan), [], TimeProvider.System, out _)!;
        var why = ScanFilePipeline.DifferentFile(new ScanItem(payload, ScanTrigger.CustomScan), decoyHandle);
        Assert.Contains("reached a different file", why, StringComparison.Ordinal);
    }
}
