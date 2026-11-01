using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Core.Tests.TestSupport;
using static SapAV.Core.Tests.Persistence.Judging;

namespace SapAV.Core.Tests.Persistence;

/// <summary>
/// Section C review H4: an autostart entry is Clean only when what it runs was scanned. Each row goes from the raw command line
/// through the real resolver into the judge: Unverified or Suspicious, never silently Clean.
/// </summary>
public class UnverifiedOutcomeTests
{
    private const string Cmd = @"C:\Windows\System32\cmd.exe";
    private const string Evil = @"C:\Users\u\evil.exe";

    private static readonly EnvironmentBlock Machine = new(new Dictionary<string, string>
    {
        ["SystemRoot"] = @"C:\Windows",
        ["Path"] = @"C:\Windows\system32;C:\Windows;C:\Tools;C:\Windows\System32\WindowsPowerShell\v1.0",
    });

    private readonly FakeProbe _probe = new(
        Cmd, @"C:\Windows\System32\notepad.exe", Evil, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");

    private ResolvedCommand Resolve(string commandLine) => new CommandLineResolver(_probe).Resolve(commandLine, Machine);

    private static PersistenceEntry RunEntry(ResolvedCommand resolution, string? command = null) =>
        new(PersistenceKind.RunKey, null, MachineRun, "App", command ?? "cmd", resolution, enabled: true);

    private static PersistenceJudgement JudgeScanned(ResolvedCommand resolution, params string[] scanned)
    {
        var reports = scanned.ToDictionary(p => p, p => Report(p, signature: VendorSigned()), StringComparer.OrdinalIgnoreCase);
        var target = resolution.TargetPath is { } t ? reports.GetValueOrDefault(t) : null;
        var host = resolution.HostPath is { } h ? reports.GetValueOrDefault(h) : null;
        return Judge.Judge(RunEntry(resolution), target, host, new FakeAcl(), reports);
    }

    [Theory]
    [InlineData(@"\\server\share\evil.exe", TargetUnresolvedReason.NetworkPath)]
    [InlineData(@"\\.\C:\evil.exe", TargetUnresolvedReason.DevicePath)]
    [InlineData(@"\??\C:\evil.exe", TargetUnresolvedReason.DevicePath)]
    public void UncAndDeviceTargets_ScoreStrong_RemotePayloadAtTheTopLevel(string command, TargetUnresolvedReason reason)
    {
        var resolved = Resolve(command);

        Assert.Equal(reason, resolved.UnresolvedReason);
        Assert.Contains(ResolutionFlag.RemotePayload, resolved.Flags);
        var judgement = JudgeScanned(resolved);
        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (judgement.Verdict, judgement.Priority));
        Assert.True(judgement.Has(PersistenceRuleIds.RemotePayload));
        Assert.True(judgement.IsUnverified); // Suspicious, and also not scanned
    }

    [Theory]
    [InlineData(@"C:evil.exe", TargetUnresolvedReason.NotFullyQualified)]
    [InlineData(@"C:evil.exe /run", TargetUnresolvedReason.NotFullyQualified)] // not "confirmed missing"
    [InlineData(@"sub\evil.exe", TargetUnresolvedReason.NotFullyQualified)]
    [InlineData(@"cmd /c cmd /c cmd /c cmd /c C:\Users\u\evil.exe", TargetUnresolvedReason.NestingTooDeep)]
    public void RelativeTargetsAndTooMuchNesting_AreUnverified_NotMissing(string command, TargetUnresolvedReason reason)
    {
        var resolved = Resolve(command);
        Assert.Equal(reason, resolved.UnresolvedReason);
        Assert.DoesNotContain(ResolutionFlag.TargetNotFound, resolved.Flags);

        var judgement = JudgeScanned(resolved);

        Assert.Equal(PersistenceOutcome.Unverified, judgement.Outcome);
        Assert.Contains(reason.ToString(), Assert.Single(judgement.UnverifiedReasons));
        Assert.Equal(PersistencePriority.Normal, judgement.Priority);
        Assert.Empty(judgement.Detections); // no alert from this alone
    }

    [Fact]
    public void AChain_ResolvesEveryCommand_AndAMaliciousLaterCommandIsCarried()
    {
        var resolved = Resolve(@"cmd /c notepad.exe & C:\Users\u\evil.exe /x && C:\Tools\missing.exe || del C:\x");

        Assert.Equal(@"C:\Windows\System32\notepad.exe", resolved.TargetPath);
        Assert.Contains(ResolutionFlag.InlineCommand, resolved.Flags);
        Assert.Equal([Evil, @"C:\Tools\missing.exe", null], resolved.Additional.Select(a => a.TargetPath));
        Assert.Equal(TargetUnresolvedReason.InlineCommand, resolved.Additional[2].UnresolvedReason);

        var reports = new Dictionary<string, FileScanReport>(StringComparer.OrdinalIgnoreCase)
        {
            [Evil] = Report(Evil, Verdict.Malicious),
            [Cmd] = Report(Cmd, signature: MicrosoftSigned()),
        };
        var judgement = Judge.Judge(RunEntry(resolved), Report(resolved.TargetPath!, signature: MicrosoftSigned()), reports[Cmd], new FakeAcl(), reports);

        Assert.Equal(Verdict.Malicious, judgement.Verdict);
        Assert.Contains(judgement.Detections, d => d.Verdict == Verdict.Malicious);
    }

    [Fact]
    public void AChainWhoseLaterCommandWasntScanned_IsNeverClean()
    {
        var resolved = Resolve(@"cmd /c notepad.exe & C:\Users\u\evil.exe");

        var judgement = JudgeScanned(resolved, resolved.TargetPath!, Cmd); // evil.exe has no report

        Assert.NotEqual(PersistenceOutcome.Clean, judgement.Outcome);
        Assert.Contains(judgement.UnverifiedReasons, r => r.Contains("evil.exe", StringComparison.Ordinal));
    }

    [Fact]
    public void AMissingCommandInAChain_DoesntMakeTheNextOneMissing()
    {
        var resolved = Resolve(@"cmd /c nosuch.exe & C:\Users\u\evil.exe");

        Assert.Equal(Evil, resolved.TargetPath);
        Assert.DoesNotContain(ResolutionFlag.TargetNotFound, resolved.Flags);
        Assert.Contains(resolved.Additional, a => a.UnresolvedReason == TargetUnresolvedReason.NotFoundOnSearchPath);
    }

    [Fact]
    public void AVeryLongChain_EndsInAnUnverifiedEntry()
    {
        string chain = "cmd /c " + string.Join(" & ", Enumerable.Repeat(Evil, 40));

        var resolved = Resolve(chain);

        Assert.Contains(resolved.Additional, a => a.UnresolvedReason == TargetUnresolvedReason.SearchLimitReached);
        Assert.Equal(PersistenceOutcome.Unverified, JudgeScanned(resolved, Evil, Cmd).Outcome);
    }

    [Fact]
    public void AnUnknownProbeAnswer_IsNotConfirmedMissing_TheTargetGoesToTheScan()
    {
        // A junction, a DACL or a lock: the probe can't tell, so the path is scanned (and that scan reports the failure).
        var probe = new UnknownProbe();
        var resolved = new CommandLineResolver(probe).Resolve(@"C:\Program Files\App\run.exe /x", Machine);

        Assert.Equal(@"C:\Program.exe", resolved.TargetPath); // the first candidate CreateProcess would try: it can't be ruled out
        Assert.DoesNotContain(ResolutionFlag.TargetNotFound, resolved.Flags);
    }

    [Fact]
    public void MoreCandidatesThanTheCap_IsUnverified_NotMissing()
    {
        string path = @"C:\" + string.Join(' ', Enumerable.Range(0, CommandLineResolver.MaxCandidates + 4).Select(i => "d" + i)) + @"\evil.exe";

        var resolved = Resolve(path);

        Assert.Equal(TargetUnresolvedReason.SearchLimitReached, resolved.UnresolvedReason);
        Assert.DoesNotContain(ResolutionFlag.TargetNotFound, resolved.Flags);
    }

    [Theory]
    [InlineData(HashFailureReason.AccessDenied, true)] // a DACL that denies SYSTEM
    [InlineData(HashFailureReason.NotRegularFile, true)] // a junction on the way, refused by the hardened open
    [InlineData(HashFailureReason.Locked, false)]
    [InlineData(HashFailureReason.TooLarge, false)]
    public void ATargetThatCantBeScanned_IsUnverified_AndUnreadableOnesScoreToo(HashFailureReason failure, bool scores)
    {
        var hash = HashResult.NotHashed(failure, "nope");
        var item = new ScanItem(Evil, ScanTrigger.Persistence);
        var report = new FileScanReport(ScanResult.NotScanned(item, hash.Status, DateTimeOffset.UtcNow), hash, null, null, null, null, []);

        var judgement = Run(Entry(Evil), report);

        Assert.Equal(PersistenceOutcome.Unverified, judgement.Outcome);
        Assert.Equal(scores, judgement.Has(PersistenceRuleIds.TargetUnreadable));
    }

    [Fact]
    public void ConfirmedMissing_AndAnEmptyCommand_AreNotUnverified()
    {
        Assert.Equal(PersistenceOutcome.Clean, Run(Entry(Evil), NotFound(Evil)).Outcome);
        Assert.Equal(PersistenceOutcome.Clean, Run(Entry(null, unresolved: TargetUnresolvedReason.NotFoundOnSearchPath)).Outcome);
        Assert.Equal(PersistenceOutcome.Clean, Run(Entry(null, unresolved: TargetUnresolvedReason.EmptyCommand)).Outcome);
        Assert.Equal(PersistenceOutcome.Clean, Run(Entry(Evil), Report(Evil, signature: VendorSigned())).Outcome);
    }

    [Fact]
    public void ADisabledUnverifiedEntry_IsLowPriority()
    {
        var judgement = Run(Entry(Evil, enabled: false));

        Assert.Equal(PersistenceOutcome.Unverified, judgement.Outcome);
        Assert.Equal(PersistencePriority.Low, judgement.Priority);
    }

    [Theory]
    [InlineData(@"powershell -w hidden -enc AAAA")]
    [InlineData(@"powershell -enc AAAA -WindowStyle Hidden")]
    [InlineData(@"powershell -nop -win 1 -e AAAA")]
    public void HiddenPlusEncodedPowerShell_ReachesSuspicious(string command)
    {
        var judgement = JudgeScanned(Resolve(command));

        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (judgement.Verdict, judgement.Priority));
    }

    [Theory]
    [InlineData(@"powershell -enc AAAA")]
    [InlineData(@"powershell -w hidden -Command Get-Date")]
    public void EncodedOrHiddenAlone_StaysBelowTheThreshold_ButIsUnverified(string command)
    {
        var judgement = JudgeScanned(Resolve(command));

        Assert.Equal(PersistenceOutcome.Unverified, judgement.Outcome);
    }

    [Theory]
    [InlineData("/x")]
    [InlineData("-Command evil")]
    public void WinlogonDefaultWithArguments_IsNotTheDefault(string arguments)
    {
        const string explorer = @"C:\Windows\explorer.exe";
        var entry = new PersistenceEntry(PersistenceKind.WinlogonShell, null, MachineRun, "Shell", "explorer.exe " + arguments,
            ResolvedCommand.Resolved(explorer, arguments), true);

        Assert.True(Run(entry, Report(explorer, signature: MicrosoftSigned())).Has(PersistenceRuleIds.WinlogonModified));
        Assert.False(Run(Entry(explorer, PersistenceKind.WinlogonShell, valueName: "Shell"), Report(explorer, signature: MicrosoftSigned())).Has(PersistenceRuleIds.WinlogonModified));
    }

    [Fact]
    public void WorkingDirectory_FindsABareName_BeforeTheSystemFolders_AndARelativeScript()
    {
        var resolver = new CommandLineResolver(_probe);

        var bare = resolver.ResolveProgram("evil.exe", null, Machine, @"C:\Users\u");
        var relative = resolver.ResolveProgram(@"sub\tool.exe", null, Machine, @"C:\Users\u");
        var script = resolver.ResolveProgram(@"C:\Windows\System32\wscript.exe", "x.vbs", Machine, @"C:\Users\u");
        var noFolder = resolver.ResolveProgram("evil.exe", null, Machine);

        Assert.Equal(Evil, bare.TargetPath);
        Assert.Contains(ResolutionFlag.ResolvedFromWorkingDirectory, bare.Flags);
        Assert.Equal(@"C:\Users\u\sub\tool.exe", relative.TargetPath);
        Assert.Equal(@"C:\Users\u\x.vbs", script.TargetPath);
        Assert.Equal(TargetUnresolvedReason.NotFoundOnSearchPath, noFolder.UnresolvedReason);
    }

    [Fact]
    public void ANetworkWorkingDirectory_MakesARelativeTargetRemote_ButABareSystemToolIsStillFound()
    {
        var resolver = new CommandLineResolver(_probe);

        var relative = resolver.ResolveProgram(@"sub\tool.exe", null, Machine, @"\\server\share");
        var tool = resolver.ResolveProgram("cmd.exe", null, Machine, @"\\server\share");

        Assert.Equal(TargetUnresolvedReason.NetworkPath, relative.UnresolvedReason);
        Assert.Contains(ResolutionFlag.RemotePayload, relative.Flags);
        Assert.Equal(Cmd, tool.TargetPath);
    }

    [Fact]
    public void ResolvedCommand_WithAdditional_SurvivesJson_AndRejectsNesting()
    {
        var original = Resolve(@"cmd /c notepad.exe & C:\Users\u\evil.exe");

        var back = System.Text.Json.JsonSerializer.Deserialize<ResolvedCommand>(System.Text.Json.JsonSerializer.Serialize(original));

        Assert.Equal(original, back);
        var nested = ResolvedCommand.Resolved(Evil).WithAdditional([ResolvedCommand.Resolved(Cmd)]);
        Assert.Throws<ArgumentException>(() => new ResolvedCommand(Evil, null, null, "", null, [nested]));
    }

    [Fact]
    public void Shortcuts_HonourHasExpString_AndReportEveryCandidate()
    {
        var environment = new EnvironmentBlock(new Dictionary<string, string> { ["windir"] = @"C:\Windows", ["SystemRoot"] = @"C:\Windows" });
        byte[] ignoredBlock = new ShellLinkBuilder { IdListPath = @"C:\Tools\real.exe", EnvironmentTarget = @"%windir%\notepad.exe", OmitHasExpString = true }.Build();
        byte[] usedBlock = new ShellLinkBuilder { IdListPath = @"C:\Tools\real.exe", LocalBasePath = @"C:\Users\u\other.exe", EnvironmentTarget = @"%windir%\notepad.exe" }.Build();

        var ignored = ShellLinkTarget.Select(ShellLinkParser.Parse(ignoredBlock, out _)!, environment, @"C:\Startup");
        var used = ShellLinkTarget.Select(ShellLinkParser.Parse(usedBlock, out _)!, environment, @"C:\Startup");

        Assert.Equal(@"C:\Tools\real.exe", ignored.Path); // the shell ignores the block, so must the engine
        Assert.False(ignored.Mismatch);
        Assert.Equal(@"C:\Windows\notepad.exe", used.Path);
        Assert.True(used.Mismatch);
        Assert.Equal([@"C:\Tools\real.exe", @"C:\Users\u\other.exe"], used.Others);
    }

    [Fact]
    public void Shortcuts_The32And64BitProgramFolders_AreNoMismatch()
    {
        var environment = new EnvironmentBlock(new Dictionary<string, string>
        {
            ["ProgramFiles"] = @"C:\Program Files", ["ProgramFiles(x86)"] = @"C:\Program Files (x86)", ["SystemRoot"] = @"C:\Windows",
        });
        byte[] link = new ShellLinkBuilder { IdListPath = @"C:\Program Files (x86)\App\a.exe", EnvironmentTarget = @"%ProgramFiles%\App\a.exe" }.Build();

        var target = ShellLinkTarget.Select(ShellLinkParser.Parse(link, out _)!, environment, @"C:\Startup");

        Assert.False(target.Mismatch);
        Assert.Empty(target.Others);
    }

    [Fact]
    public void AShortcutMismatch_ScoresStrong()
    {
        var judgement = Run(Entry(Evil, flags: ResolutionFlag.ShortcutTargetMismatch), Report(Evil, signature: VendorSigned()));

        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (judgement.Verdict, judgement.Priority));
        Assert.True(judgement.Has(PersistenceRuleIds.ShortcutTargetMismatch));
    }
private sealed class FakeProbe(params string[] existing) : IPathProbe    {        private readonly HashSet<string> _existing = new(existing, StringComparer.OrdinalIgnoreCase);        public bool FileExists(string path) => _existing.Contains(path);    }

    private sealed class UnknownProbe : IPathProbe
    {
        public bool FileExists(string path) => false;

        public PathProbeResult Probe(string path) => PathProbeResult.Unknown;
    }
}
