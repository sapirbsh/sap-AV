using SapAV.Core.Defender;
using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Defender;

/// <summary>E5 (rules): Defender exclusion, protection-state and tamper rules on synthetic snapshots.</summary>
public class DefenderRulesTests
{
    private static readonly RegisteredAntivirus DefenderOnly = new("Microsoft Defender Antivirus", IsDefender: true, Enabled: true);
    private static readonly RegisteredAntivirus OtherAv = new("Other AV", IsDefender: false, Enabled: true);

    private static DefenderStatusSnapshot Healthy(
        IEnumerable<string>? paths = null, IEnumerable<string>? extensions = null, IEnumerable<string>? processes = null) => new()
    {
        CollectedAt = new DateTimeOffset(2026, 11, 11, 12, 0, 0, TimeSpan.Zero),
        ComputerStatusRead = DefenderReadState.Available,
        PreferenceRead = DefenderReadState.Available,
        Protection = new DefenderProtectionState
        {
            AntimalwareServiceEnabled = true, AntivirusEnabled = true, AntispywareEnabled = true, RealTimeProtectionEnabled = true,
            OnAccessProtectionEnabled = true, BehaviorMonitorEnabled = true, IoavProtectionEnabled = true, TamperProtected = true,
            RunningMode = DefenderRunningMode.Normal,
        },
        Preferences = new DefenderPreferenceFlags { RealtimeMonitoringDisabled = false, BehaviorMonitoringDisabled = false, IoavProtectionDisabled = false },
        Exclusions = new DefenderExclusions
        {
            Paths = DefenderExclusionList.Known(paths ?? []),
            Extensions = DefenderExclusionList.Known(extensions ?? []),
            Processes = DefenderExclusionList.Known(processes ?? []),
            IpAddresses = DefenderExclusionList.Known([]),
        },
        RegisteredAntivirus = [DefenderOnly],
        DefenderIsActiveAntivirus = true,
        ActiveAntivirusDecidedBy = DefenderActiveSource.RunningMode,
        DefenderExpected = true,
        CollectedAsSystem = true,
    };

    private static DefenderStatusSnapshot Unread(DefenderReadState state, bool? expected, IReadOnlyList<RegisteredAntivirus>? av) => new()
    {
        CollectedAt = DateTimeOffset.UnixEpoch,
        ComputerStatusRead = state,
        PreferenceRead = state,
        RegisteredAntivirus = av,
        DefenderExpected = expected,
    };

    private static DefenderFinding Single(DefenderAssessment a) => Assert.Single(a.Findings);

    [Fact]
    public void HealthySnapshot_IsClean_AndFullyVerified()
    {
        var a = DefenderRules.Evaluate(Healthy());

        Assert.Empty(a.Findings);
        Assert.Empty(a.Unverified);
        Assert.Equal(DefenderOutcome.Clean, a.Outcome);
    }

    [Theory]
    [InlineData(@"C:\")]
    [InlineData(@"D:")]
    [InlineData("*")]
    [InlineData(@"C:\*")]
    [InlineData(@"C:\Users")]
    [InlineData(@"C:\Users\*")]
    [InlineData("%USERPROFILE%")]
    [InlineData(@"%TEMP%\")]
    [InlineData(@"%USERPROFILE%\AppData")]
    [InlineData(@"C:\Users\alice\AppData\")]
    [InlineData(@"c:\USERS\alice\appdata\LOCAL\temp\*.*")]
    [InlineData(@"\\?\C:\Users\alice\Downloads")]
    [InlineData(@"\\localhost\C$\Users\alice\AppData\Roaming")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume3\ProgramData")]
    [InlineData(@"C:\Users\Public\")]
    [InlineData(@"C:\Users\alice\APPDAT~1")]
    [InlineData(@"C:\Windows\System32\..\..\Users\alice")]
    [InlineData(@"""C:/Windows/Temp/""")]
    public void BroadPathExclusion_IsMalicious(string path)
    {
        var f = Single(DefenderRules.Evaluate(Healthy(paths: [path])));

        Assert.Equal(Verdict.Malicious, f.Verdict);
        Assert.Contains(f.RuleId, new[] { DefenderRuleIds.PathExcludesEverything, DefenderRuleIds.PathBroadUserFolder });
        Assert.Equal(DefenderExclusionKind.Path, f.ExclusionList);
        Assert.Equal(path, f.ExclusionItem);
    }

    [Theory]
    [InlineData(@"C:\Users\alice\source\repos\sap-AV", DefenderRuleIds.PathInUserFolder)]
    [InlineData(@"C:\Users\alice\AppDataBackup", DefenderRuleIds.PathInUserFolder)]
    [InlineData(@"%LOCALAPPDATA%\Microsoft\VisualStudio", DefenderRuleIds.PathInUserFolder)]
    [InlineData(@"C:\Windows\Temp\build", DefenderRuleIds.PathInUserFolder)]
    [InlineData(@"C:\Windows\", DefenderRuleIds.PathSystemFolder)]
    public void NarrowUserFolderOrSystemFolderExclusion_IsSuspiciousNotMalicious(string path, string rule)
    {
        var f = Single(DefenderRules.Evaluate(Healthy(paths: [path])));

        Assert.Equal(Verdict.Suspicious, f.Verdict);
        Assert.Equal(rule, f.RuleId);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA")]
    [InlineData(@"%ProgramData%\Microsoft\Windows\Hyper-V")]
    [InlineData(@"C:\Users\Public\Documents\Hyper-V\Virtual Hard Disks")]
    [InlineData(@"C:\ClusterStorage")]
    [InlineData(@"\\buildserver\share\out")]
    [InlineData(@"D:\Dev")]
    public void DocumentedDefaultsAndProgramFolders_GiveNoFinding(string path)
    {
        var a = DefenderRules.Evaluate(Healthy(paths: [path]));

        Assert.Empty(a.Findings);
        Assert.Equal(DefenderOutcome.Clean, a.Outcome);
    }

    [Fact]
    public void UnknownEnvironmentVariable_IsUnverified_NotAnAlarmOrClean()
    {
        var a = DefenderRules.Evaluate(Healthy(paths: [@"%MYTOOLS%\bin"]));

        Assert.Empty(a.Findings);
        Assert.Equal(DefenderOutcome.Unverified, a.Outcome);
    }

    [Theory]
    [InlineData("exe", DefenderRuleIds.ExtensionRisky)]
    [InlineData(".DLL", DefenderRuleIds.ExtensionRisky)]
    [InlineData("*.ps1", DefenderRuleIds.ExtensionRisky)]
    [InlineData("hta", DefenderRuleIds.ExtensionRisky)]
    [InlineData("e?e", DefenderRuleIds.ExtensionRisky)]
    [InlineData("*", DefenderRuleIds.ExtensionExcludesEverything)]
    [InlineData(".*", DefenderRuleIds.ExtensionExcludesEverything)]
    public void RiskyExtensionExclusion_IsMalicious(string extension, string rule)
    {
        var f = Single(DefenderRules.Evaluate(Healthy(extensions: [extension])));

        Assert.Equal(Verdict.Malicious, f.Verdict);
        Assert.Equal(rule, f.RuleId);
    }

    [Fact]
    public void DataExtensionExclusions_GiveNoFinding()
    {
        var a = DefenderRules.Evaluate(Healthy(extensions: [".mdf", ".ldf", "vhdx", "*.log"]));

        Assert.Empty(a.Findings);
    }

    [Theory]
    [InlineData("powershell.exe", DefenderRuleIds.ProcessInterpreter, Verdict.Malicious)]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE", DefenderRuleIds.ProcessInterpreter, Verdict.Malicious)]
    [InlineData("mshta", DefenderRuleIds.ProcessInterpreter, Verdict.Malicious)]
    [InlineData("regsvr32.exe", DefenderRuleIds.ProcessInterpreter, Verdict.Malicious)]
    [InlineData("*.exe", DefenderRuleIds.ProcessExcludesEverything, Verdict.Malicious)]
    [InlineData(@"C:\Users\*\AppData\Local\Temp\*.exe", DefenderRuleIds.ProcessBroadFolder, Verdict.Malicious)]
    [InlineData(@"C:\Users\alice\AppData\Roaming\Tool\agent.exe", DefenderRuleIds.ProcessInUserFolder, Verdict.Suspicious)]
    public void ProcessExclusion_InterpretersAndUserFolders_AreFlagged(string process, string rule, Verdict verdict)
    {
        var f = Single(DefenderRules.Evaluate(Healthy(processes: [process])));

        Assert.Equal(rule, f.RuleId);
        Assert.Equal(verdict, f.Verdict);
        Assert.Equal(DefenderExclusionKind.Process, f.ExclusionList);
    }

    [Fact]
    public void ProgramProcessExclusions_GiveNoFinding()
    {
        var a = DefenderRules.Evaluate(Healthy(processes:
            ["sqlservr.exe", "vmwp.exe", @"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe"]));

        Assert.Empty(a.Findings);
    }

    [Fact]
    public void Finding_IsDefenderTamperingT1562_SanitizedForDisplay_AndKeepsRawItemForRemoval()
    {
        string raw = "C:\\Users\\bob\\AppData\u202E\\fake";
        string rawBroad = "C:\\Users\\bob\\AppData";
        var a = DefenderRules.Evaluate(Healthy(paths: [rawBroad + "\nInjected log line", raw]));

        Assert.NotEmpty(a.Findings);
        foreach (var f in a.Findings)
        {
            Assert.Equal(MitreTechniqueIds.DisableOrModifyTools, f.TechniqueId);
            Assert.Equal(ThreatCategory.DefenderTampering, f.Category);
            Assert.DoesNotContain('\n', f.Reason);
            Assert.DoesNotContain('\u202E', f.Reason);
            Assert.Contains("You decide", f.Reason);
            var d = f.ToDetection();
            Assert.Equal(f.Verdict, d.Verdict);
            Assert.Equal(ThreatCategory.DefenderTampering, d.Category);
        }

        Assert.Contains(a.Findings, f => f.ExclusionItem == raw);
    }

    [Fact]
    public void RealTimeOff_NoOtherAntivirus_IsMalicious()
    {
        var s = Healthy() with { Protection = Healthy().Protection with { RealTimeProtectionEnabled = false } };

        var f = Single(DefenderRules.Evaluate(s));

        Assert.Equal(DefenderRuleIds.RealTimeProtectionOff, f.RuleId);
        Assert.Equal(Verdict.Malicious, f.Verdict);
        Assert.Equal(DefenderFindingKind.ProtectionDisabled, f.Kind);
    }

    [Fact]
    public void ProtectionOff_ThirdPartyConfirmed_IsExpected_ButUnknownThirdParty_IsUnverified()
    {
        var off = Healthy() with
        {
            Protection = Healthy().Protection with { RealTimeProtectionEnabled = false, AntivirusEnabled = false, BehaviorMonitorEnabled = false },
        };

        var confirmed = DefenderRules.Evaluate(off with { RegisteredAntivirus = [DefenderOnly, OtherAv] });
        var unknown = DefenderRules.Evaluate(off with { RegisteredAntivirus = null });

        Assert.Empty(confirmed.Findings);
        Assert.Equal(DefenderOutcome.Clean, confirmed.Outcome);
        Assert.Empty(unknown.Findings);
        Assert.Equal(DefenderOutcome.Unverified, unknown.Outcome);
    }

    [Fact]
    public void BehaviourIoavAndTamperProtectionOff_AreSuspicious()
    {
        var s = Healthy() with
        {
            Protection = Healthy().Protection with { BehaviorMonitorEnabled = false, IoavProtectionEnabled = false, TamperProtected = false },
        };

        var a = DefenderRules.Evaluate(s);

        Assert.Equal(3, a.Findings.Count);
        Assert.All(a.Findings, f => Assert.Equal(Verdict.Suspicious, f.Verdict));
        Assert.Equal(
            new[] { DefenderRuleIds.BehaviorMonitoringOff, DefenderRuleIds.IoavProtectionOff, DefenderRuleIds.TamperProtectionOff }.Order(),
            a.Findings.Select(f => f.RuleId).Order());
    }

    [Fact]
    public void PreferenceSetOff_WhileTamperProtectionKeepsItOn_IsSuspicious()
    {
        var s = Healthy() with { Preferences = Healthy().Preferences with { RealtimeMonitoringDisabled = true } };

        var f = Single(DefenderRules.Evaluate(s));

        Assert.Equal(DefenderRuleIds.RealTimeProtectionOff, f.RuleId);
        Assert.Equal(Verdict.Suspicious, f.Verdict);
    }

    [Fact]
    public void PassiveMode_WithoutOtherAntivirus_IsSuspicious_WithOne_IsExpected()
    {
        var passive = Healthy() with
        {
            Protection = Healthy().Protection with { RunningMode = DefenderRunningMode.Passive, RealTimeProtectionEnabled = false },
            DefenderIsActiveAntivirus = false,
        };

        var alone = DefenderRules.Evaluate(passive);
        var handedOver = DefenderRules.Evaluate(passive with { RegisteredAntivirus = [DefenderOnly, OtherAv] });

        Assert.Equal(DefenderRuleIds.PassiveWithoutOtherAntivirus, Single(alone).RuleId);
        Assert.Equal(Verdict.Suspicious, Single(alone).Verdict);
        Assert.Empty(handedOver.Findings);
        Assert.Equal(DefenderOutcome.Clean, handedOver.Outcome);
    }

    [Theory]
    [InlineData(true, DefenderOutcome.Malicious)]
    [InlineData(false, DefenderOutcome.NotApplicable)]
    [InlineData(null, DefenderOutcome.Unverified)]
    public void NotInstalled_DependsOnTheSku(bool? defenderExpected, DefenderOutcome expected)
    {
        var a = DefenderRules.Evaluate(Unread(DefenderReadState.NotInstalled, defenderExpected, av: null));

        Assert.Equal(expected, a.Outcome);
        if (expected == DefenderOutcome.Malicious)
        {
            Assert.Equal(DefenderRuleIds.DefenderMissing, Single(a).RuleId);
        }
    }

    [Fact]
    public void ServiceNotRunning_OnClient_DependsOnConfirmedThirdParty()
    {
        var thirdParty = DefenderRules.Evaluate(Unread(DefenderReadState.ServiceNotRunning, true, [DefenderOnly with { Enabled = false }, OtherAv]));
        var none = DefenderRules.Evaluate(Unread(DefenderReadState.ServiceNotRunning, true, [DefenderOnly with { Enabled = false }]));
        var unknown = DefenderRules.Evaluate(Unread(DefenderReadState.ServiceNotRunning, true, null));
        var server = DefenderRules.Evaluate(Unread(DefenderReadState.ServiceNotRunning, false, null));

        Assert.Empty(thirdParty.Findings);
        Assert.Equal(DefenderOutcome.Clean, thirdParty.Outcome);
        Assert.Equal(Verdict.Malicious, Single(none).Verdict);
        Assert.Equal(DefenderRuleIds.DefenderServiceStopped, Single(unknown).RuleId);
        Assert.Equal(Verdict.Suspicious, Single(unknown).Verdict);
        Assert.Empty(server.Findings);
        Assert.Equal(DefenderOutcome.Unverified, server.Outcome);
    }

    [Theory]
    [InlineData(DefenderReadState.WmiUnavailable)]
    [InlineData(DefenderReadState.AccessDenied)]
    [InlineData(DefenderReadState.TimedOut)]
    public void UnreadableDefender_GivesNoFindingButNeverClean(DefenderReadState state)
    {
        var a = DefenderRules.Evaluate(Unread(state, true, [DefenderOnly]));

        Assert.Empty(a.Findings);
        Assert.Equal(DefenderOutcome.Unverified, a.Outcome);
    }

    [Fact]
    public void MissingProtectionValues_AreUnverified_NotAnAlarm()
    {
        var s = Healthy() with { Protection = new DefenderProtectionState { RunningMode = DefenderRunningMode.Unknown } };

        var a = DefenderRules.Evaluate(s);

        Assert.Empty(a.Findings);
        Assert.Equal(DefenderOutcome.Unverified, a.Outcome);
    }

    [Fact]
    public void HiddenLists_AreUnverified_AndHiddenFromSystem_IsATamperSign()
    {
        var hidden = Healthy() with { Exclusions = Healthy().Exclusions with { Paths = DefenderExclusionList.Hidden } };

        var asUser = DefenderRules.Evaluate(hidden);
        var asSystem = DefenderRules.Evaluate(hidden with { ExclusionsHiddenFromSystem = true });

        Assert.Empty(asUser.Findings);
        Assert.Equal(DefenderOutcome.Unverified, asUser.Outcome);
        var f = Single(asSystem);
        Assert.Equal(DefenderRuleIds.ExclusionsHiddenFromSystem, f.RuleId);
        Assert.Equal(DefenderFindingKind.TamperSign, f.Kind);
    }

    [Fact]
    public void TruncatedList_IsSuspicious_UncheckedMiddleIsUnverified_AndKeptEntriesAreStillJudged()
    {
        var padding = Enumerable.Range(0, 3000).Select(i => $@"C:\Program Files\Vendor\Item{i}");
        var s = Healthy(paths: [.. padding, @"C:\Users\mallory\AppData"]);

        var a = DefenderRules.Evaluate(s);

        Assert.Contains(a.Findings, f => f.RuleId == DefenderRuleIds.ExclusionListTruncated && f.Verdict == Verdict.Suspicious && f.Reason.Contains("3001"));
        Assert.Contains(a.Findings, f => f.RuleId == DefenderRuleIds.PathBroadUserFolder); // the last entry is in the kept tail
        Assert.Contains(a.Unverified, u => u.Contains("weren't checked"));
        Assert.Equal(DefenderOutcome.Malicious, a.Outcome);
    }

    [Fact]
    public void RegistryFallbackSource_IsNamedInTheReason()
    {
        var s = Healthy() with
        {
            Exclusions = Healthy().Exclusions with { Extensions = DefenderExclusionList.Known(["exe"], DefenderExclusionSource.Registry) },
        };

        var f = Single(DefenderRules.Evaluate(s));

        Assert.Equal(DefenderExclusionSource.Registry, f.ExclusionSource);
        Assert.Contains("registry", f.Reason);
    }

    [Fact]
    public void ManyFlaggedEntries_AreCappedWithOneSummary()
    {
        var paths = Enumerable.Range(0, DefenderRules.MaxExclusionFindingsPerList + 10).Select(i => $@"C:\Users\u{i}\AppData");

        var a = DefenderRules.Evaluate(Healthy(paths: paths));

        Assert.Equal(DefenderRules.MaxExclusionFindingsPerList + 1, a.Findings.Count);
        var summary = Assert.Single(a.Findings, f => f.RuleId == DefenderRuleIds.MoreFlaggedExclusions);
        Assert.Equal(Verdict.Malicious, summary.Verdict);
        Assert.Contains("10 more", summary.Reason);
        Assert.Null(summary.ExclusionItem);
    }
}
