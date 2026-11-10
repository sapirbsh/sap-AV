using System.Text;
using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Tests.Persistence;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Heuristics;

/// <summary>
/// E3: static infostealer / miner heuristics. Synthetic names, synthetic command lines, synthetic PE images analysed in memory
/// (never written to disk), RFC 5737 / example.org addresses and an obviously fake wallet. No real miner or stealer is involved.
/// </summary>
public sealed class ThreatPackHeuristicsTests
{
    private const string AppData = @"C:\Users\alice\AppData\Roaming\";

    /// <summary>A syntactically valid, obviously fake Monero address (95 base58 characters).</summary>
    private static readonly string FakeWallet = "4A" + new string('x', 93);

    private static readonly FileHeuristics Heuristics = new();

    private static byte[] Pe => SyntheticPe.Build(new byte[8192]); // low entropy: only the rules under test fire

    private static HeuristicResult Analyze(string path, byte[] content, Core.Signatures.SignatureCheckResult? signature) =>
        Heuristics.Analyze(content, path, new HeuristicContext(signature));

    private static HeuristicKind[] Kinds(HeuristicResult r) => r.Findings.Select(f => f.Kind).ToArray();

    // ---- Random names ----

    [Theory]
    [InlineData("xk3j9qz7.exe")]
    [InlineData("qwrtzpsdfgh.exe")]
    [InlineData("3f2a9c1e7b4d.exe")]
    [InlineData("0f8fad5b-d9cb-469f-a165-70867728950e.exe")]
    [InlineData("a1b2c3d4e5.dll")]
    public void MachineGeneratedNames_AreRecognized(string name) => Assert.NotNull(FileNameRules.RandomNameReason(name));

    [Theory]
    [InlineData("Discord.exe")]
    [InlineData("Update.exe")]
    [InlineData("ms-teams.exe")]
    [InlineData("Code.exe")]
    [InlineData("unins000.exe")]
    [InlineData("python3.exe")]
    [InlineData("steamwebhelper.exe")]
    [InlineData("chrome_proxy.exe")]
    [InlineData("OneDriveSetup.exe")]
    [InlineData("20231102.exe")]
    [InlineData("vcredist.exe")]
    public void RealProgramNames_AreNotRandom(string name) => Assert.Null(FileNameRules.RandomNameReason(name));

    [Fact]
    public void RandomNamedUnsignedProgram_InAppData_IsSuspicious_AsAnInfostealer()
    {
        var result = Analyze(AppData + "xk3j9qz7.exe", Pe, SyntheticPe.Unsigned());

        Assert.Contains(HeuristicKind.RandomNameAppDataExecutable, Kinds(result));
        Assert.Equal(60, result.Score); // random name 30 + unsigned 15 + AppData 15: all three are needed
        Assert.Equal((Verdict.Suspicious, ThreatCategory.Infostealer, MitreTechniqueIds.MaliciousFile),
            (result.Detection!.Verdict, result.Detection.Category, result.Detection.TechniqueId));
    }

    [Fact]
    public void RandomName_IsExempt_WhenSigned_OutsideAppData_InTemp_OrNotAProgram()
    {
        Assert.DoesNotContain(HeuristicKind.RandomNameAppDataExecutable, Kinds(Analyze(AppData + "xk3j9qz7.exe", Pe, SyntheticPe.TrustedSignature())));
        Assert.False(Analyze(AppData + "xk3j9qz7.exe", Pe, SyntheticPe.TrustedSignature()).IsSuspicious);
        Assert.DoesNotContain(HeuristicKind.RandomNameAppDataExecutable, Kinds(Analyze(@"C:\Program Files\Vendor\xk3j9qz7.exe", Pe, SyntheticPe.Unsigned())));
        Assert.DoesNotContain(HeuristicKind.RandomNameAppDataExecutable, Kinds(Analyze(@"C:\Users\alice\AppData\Local\Temp\xk3j9qz7.exe", Pe, SyntheticPe.Unsigned())));
        Assert.Empty(Analyze(AppData + "xk3j9qz7.dat", "plain data"u8.ToArray(), SyntheticPe.Unsigned()).Findings);
    }

    [Theory]
    [InlineData(@"C:\Users\alice\AppData\Local\Discord\app-1.0.9000\Discord.exe")]
    [InlineData(@"C:\Users\alice\AppData\Local\Microsoft\Teams\Update.exe")]
    [InlineData(@"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe")]
    public void PerUserInstalls_InAppData_StayClean_EvenIfTheSignatureCouldNotBeTrusted(string path)
    {
        Assert.False(Analyze(path, Pe, SyntheticPe.TrustedSignature()).IsSuspicious);
        Assert.False(Analyze(path, Pe, SyntheticPe.Unsigned()).IsSuspicious); // unsigned 15 + AppData 15 only
    }

    // ---- Miner names ----

    [Theory]
    [InlineData("xmrig.exe", true)]
    [InlineData(@"C:\Users\alice\Downloads\xmrig-6.21.0-msvc-win64.exe", true)]
    [InlineData("SRBMiner-MULTI.exe", true)]
    [InlineData("t-rex.exe", true)]
    [InlineData("nbminer", true)]
    [InlineData("minecraft.exe", false)]
    [InlineData("miner.exe", false)]
    [InlineData("trex.exe", false)]
    [InlineData("notepad.exe", false)]
    public void KnownMinerNames_AreRecognized(string name, bool expected) => Assert.Equal(expected, MinerRules.IsMinerName(name));

    [Fact]
    public void UnsignedProgramNamedLikeAMiner_IsSuspicious_AsAMiner_ButNotWhenSigned()
    {
        var unsigned = Analyze(@"D:\Games\Tools\xmrig.exe", Pe, SyntheticPe.Unsigned());

        Assert.Equal((Verdict.Suspicious, ThreatCategory.Miner, MitreTechniqueIds.ComputeHijacking),
            (unsigned.Detection!.Verdict, unsigned.Detection.Category, unsigned.Detection.TechniqueId));
        Assert.DoesNotContain(HeuristicKind.MinerProgramName, Kinds(Analyze(@"D:\Games\Tools\xmrig.exe", Pe, SyntheticPe.TrustedSignature())));
    }

    // ---- Miner command lines ----

    [Theory]
    [InlineData("svc.exe -o pool.example.org:3333 -u {wallet} -p x")]
    [InlineData(@"C:\Users\alice\AppData\Roaming\x\host.exe --url=stratum+tcp://203.0.113.5:4444")]
    [InlineData("updater.exe --donate-level 1 --background")]
    [InlineData("helper.exe -o 198.51.100.7:14444 -a rx/0")]
    [InlineData("helper.exe --url gulf.moneroocean.example:10128 --cpu-max-threads-hint=50 --randomx-1gb-pages")]
    [InlineData("xmrig.exe --coin monero")]
    public void MinerCommandLines_AreRecognized(string commandLine)
    {
        var analysis = MinerRules.AnalyzeCommandLine(commandLine.Replace("{wallet}", FakeWallet, StringComparison.Ordinal));

        Assert.True(analysis.IsMiner, $"{commandLine}: score {analysis.Score} ({string.Join(", ", analysis.Reasons)})");
        Assert.Equal((ThreatCategory.Miner, "T1496.001"), (analysis.Category, analysis.TechniqueId));
        Assert.DoesNotContain(analysis.Reasons, r => r.Contains("example", StringComparison.Ordinal)); // engine text, never the line itself
    }

    [Theory]
    [InlineData("curl.exe -o out.txt https://example.org/file")]
    [InlineData("app.exe --url https://example.org:4444/api")]
    [InlineData("backup.exe -o D:\\backup -u alice")]
    [InlineData("node.exe server.js --port 3333")]
    [InlineData("ffmpeg.exe -i in.mp4 -a 128k -o out.mp3")]
    [InlineData("")]
    [InlineData(null)]
    public void OrdinaryCommandLines_AreNotMiners(string? commandLine) => Assert.False(MinerRules.AnalyzeCommandLine(commandLine).IsMiner);

    [Fact]
    public void ScriptThatStartsAMiner_IsSuspicious_InUtf8OrUtf16_AndAHarmlessScriptIsNot()
    {
        const string script = "@echo off\r\nstart /min \"\" helper.exe -o stratum+tcp://pool.example.org:3333 -u worker1\r\n";
        byte[] utf16 = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes(script)];

        foreach (var content in new[] { Encoding.UTF8.GetBytes(script), utf16 })
        {
            var result = Analyze(AppData + "run.bat", content, null);
            Assert.Contains(HeuristicKind.MinerScript, Kinds(result));
            Assert.Equal(ThreatCategory.Miner, result.Detection!.Category);
        }

        Assert.False(Analyze(AppData + "run.bat", "@echo off\r\necho hello -o out.txt\r\n"u8.ToArray(), null).IsSuspicious);
    }

    [Fact]
    public void NewHeuristicKinds_CrossTheWorkerWire_ByName()
    {
        var item = new Core.Models.ScanItem(AppData + "xk3j9qz7.exe", Core.Models.ScanTrigger.CustomScan);
        var heuristics = Analyze(item.Path, Pe, SyntheticPe.Unsigned());
        var report = new Core.Scanning.FileScanReport(new ScanResult(item, [heuristics.Detection!], DateTimeOffset.UnixEpoch),
            Core.Hashing.HashResult.NotHashed(Core.Hashing.HashFailureReason.TooLarge, "big", 1), null, null, null, heuristics, []);

        var back = WireReportCodec.FromWire(WorkerJson.Deserialize<WireScanReport>(WorkerJson.Serialize(WireReportCodec.ToWire(report), WorkerLimits.MaxResponseBytes)),
            item, DateTimeOffset.UnixEpoch);

        Assert.Contains(back.Heuristics!.Findings, f => f.Kind == HeuristicKind.RandomNameAppDataExecutable && f.Category == ThreatCategory.Infostealer);
        Assert.Equal(ThreatCategory.Infostealer, Assert.Single(back.Result.Detections).Category);
    }

    // ---- Persistence entries ----

    private static PersistenceEntry Run(string target, string arguments) =>
        new(PersistenceKind.RunKey, Judging.Sid, Judging.UserRun, "Svc", $"\"{target}\" {arguments}", ResolvedCommand.Resolved(target, arguments), true);

    [Fact]
    public void AutostartThatStartsAMiner_IsSuspicious_WithTheMinerCategoryAndTechnique()
    {
        const string target = AppData + @"Svc\svchost32.exe";
        var entry = Run(target, "-o pool.example.org:3333 -a rx/0 --donate-level 1");

        var judgement = Judging.Run(entry, Judging.Report(target, signature: Judging.VendorSigned()));

        Assert.Equal(Verdict.Suspicious, judgement.Verdict);
        Assert.True(judgement.Has(PersistenceRuleIds.MinerCommandLine));
        var own = Assert.Single(judgement.Detections);
        Assert.Equal(ThreatCategory.Miner, own.Category);
        Assert.Contains(MitreTechniqueIds.ComputeHijacking, own.SecondaryTechniqueIds);
        Assert.Equal(MitreTechniqueIds.RegistryRunKeysStartupFolder, judgement.TechniqueId); // the entry kind stays primary
    }

    [Fact]
    public void OrdinaryAutostart_WithAnOutputOption_HasNoMinerSignal()
    {
        const string target = @"C:\Program Files\Contoso\app.exe";
        var judgement = Judging.Run(Run(target, "--minimized -o C:\\logs -u alice"), Judging.Report(target, signature: Judging.VendorSigned()));

        Assert.Equal(Verdict.Clean, judgement.Verdict);
        Assert.False(judgement.Has(PersistenceRuleIds.MinerCommandLine));
    }
}
