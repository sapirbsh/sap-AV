using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Signatures;
using static SapAV.Core.Tests.Persistence.Judging;

namespace SapAV.Core.Tests.Persistence;

/// <summary>C3 rules, each positive and negative, on synthetic entries (no files, no registry).</summary>
public class PersistenceJudgeTests
{
    private const string Vendor = @"C:\Program Files\Contoso\app.exe";
    private const string Cmd = @"C:\Windows\System32\cmd.exe";

    // --- target scan carry-over -------------------------------------------------------------------------------------

    [Fact]
    public void MaliciousTarget_IsCarriedOver_WithItsTechnique_AndTheEntryKindAsSecondary()
    {
        var j = Run(Entry(Vendor), Report(Vendor, Verdict.Malicious, VendorSigned()));

        Assert.Equal((Verdict.Malicious, PersistencePriority.High), (j.Verdict, j.Priority));
        Assert.Equal(MitreTechniqueIds.MaliciousFile, j.TechniqueId);
        Assert.Contains(MitreTechniqueIds.RegistryRunKeysStartupFolder, j.SecondaryTechniqueIds);
        var carried = Assert.Single(j.Detections);
        Assert.Equal(DetectionSource.Yara, carried.Source);
        Assert.StartsWith("Autostart target: YARA rule", carried.Reason, StringComparison.Ordinal);
        Assert.Contains(MitreTechniqueIds.RegistryRunKeysStartupFolder, carried.SecondaryTechniqueIds);
    }

    [Fact]
    public void SuspiciousTargetOrHost_IsCarriedOver_CleanTargetIsNot()
    {
        var host = @"C:\Windows\System32\rundll32.exe";
        var dll = @"C:\Program Files\Contoso\x.dll";
        var entry = Entry(dll, host: host, flags: ResolutionFlag.InterpreterHost);

        Assert.Equal(Verdict.Suspicious, Run(Entry(Vendor), Report(Vendor, Verdict.Suspicious, VendorSigned())).Verdict);
        var fromHost = Run(entry, Report(dll, signature: VendorSigned()), Report(host, Verdict.Suspicious, MicrosoftSigned()));
        Assert.StartsWith("Autostart host: ", Assert.Single(fromHost.Detections).Reason, StringComparison.Ordinal);

        var clean = Run(Entry(Vendor), Report(Vendor, signature: VendorSigned()));
        Assert.Equal(Verdict.Clean, clean.Verdict);
        Assert.Empty(clean.Detections);
        Assert.Equal(MitreTechniqueIds.RegistryRunKeysStartupFolder, clean.TechniqueId);
    }

    [Fact]
    public void MicrosoftSignedSystem32Target_InAStandardLocation_IsClean_WithNoNoise()
    {
        var host = @"C:\Windows\System32\rundll32.exe";
        var shell32 = @"C:\Windows\System32\shell32.dll";
        var entry = Entry(shell32, host: host, flags: ResolutionFlag.InterpreterHost);

        var j = Run(entry, Report(shell32, signature: MicrosoftSigned()), Report(host, signature: MicrosoftSigned()));

        Assert.Equal((Verdict.Clean, 0, PersistencePriority.Low), (j.Verdict, j.Score, j.Priority));
        Assert.Empty(j.Signals); // the weak "runs through rundll32" signal is dropped for a Microsoft system target

        var unsignedDll = Run(Entry(@"C:\Program Files\Contoso\x.dll", host: host, flags: ResolutionFlag.InterpreterHost),
            Report(@"C:\Program Files\Contoso\x.dll"), Report(host, signature: MicrosoftSigned()));
        Assert.True(unsignedDll.Has(PersistenceRuleIds.InterpreterHost)); // kept for anything else
    }

    [Fact]
    public void MicrosoftSignature_DoesNotWhitelistAUserWritableWindowsFolder()
    {
        var copied = @"C:\Windows\Temp\svchost.exe"; // a signed binary copied to a writable folder (side-loading)
        var j = Run(Entry(copied), Report(copied, signature: MicrosoftSigned()), acl: new FakeAcl().WithFolder(@"C:\Windows\Temp"));

        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (j.Verdict, j.Priority));
        Assert.True(j.Has(PersistenceRuleIds.TargetRiskyFolder));
        Assert.True(j.Has(PersistenceRuleIds.TargetFolderUserWritable));
    }

    // --- target location (ACL, weighted by scope) ----------------------------------------------------------------------

    [Fact]
    public void MachineWideEntry_TargetModifiableByUsers_IsSuspicious_DecidedByTheAcl_NotTheName()
    {
        var acl = new FakeAcl();
        acl.Modifiable.Add(Vendor);

        var weak = Run(Entry(Vendor), Report(Vendor, signature: VendorSigned()), acl: acl);
        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (weak.Verdict, weak.Priority));
        Assert.True(weak.Has(PersistenceRuleIds.TargetUserModifiable));

        var protectedAcl = Run(Entry(Vendor), Report(Vendor, signature: VendorSigned()), acl: new FakeAcl());
        Assert.Equal(Verdict.Clean, protectedAcl.Verdict);
        Assert.Empty(protectedAcl.Signals);
    }

    [Fact]
    public void Service_InAFolderUsersCanWrite_AndUnsigned_IsSuspicious_WithServicePermissionsWeakness()
    {
        var target = @"C:\ProgramData\Contoso\svc.exe";
        var entry = Entry(target, PersistenceKind.Service, valueName: "ImagePath");
        var acl = new FakeAcl().WithFolder(@"C:\ProgramData\Contoso");

        var j = Run(entry, Report(target), acl: acl);

        Assert.Equal(Verdict.Suspicious, j.Verdict);
        Assert.Equal(60, j.Score); // folder 40 + unsigned 20
        Assert.Equal(MitreTechniqueIds.WindowsService, j.TechniqueId);
        Assert.Contains(MitreTechniqueIds.ServicesFilePermissionsWeakness, j.SecondaryTechniqueIds);

        Assert.Equal(Verdict.Clean, Run(entry, Report(target, signature: VendorSigned()), acl: acl).Verdict); // signed: 40 only
    }

    [Fact]
    public void PerUserEntry_InItsOwnAppData_IsClean_ButFromTemp_IsSuspicious()
    {
        var appData = @"C:\Users\alice\AppData\Roaming\Chat\chat.exe";
        var temp = @"C:\Users\alice\AppData\Local\Temp\x7f.exe";
        var acl = new FakeAcl().WithFolder(@"C:\Users\alice");

        var normal = Run(Entry(appData, sid: Sid), Report(appData), acl: acl);
        Assert.Equal(Verdict.Clean, normal.Verdict); // user-writable 10 + unsigned 20

        var risky = Run(Entry(temp, sid: Sid), Report(temp, signature: VendorSigned()), acl: acl);
        Assert.Equal((Verdict.Suspicious, PersistencePriority.Normal), (risky.Verdict, risky.Priority));
        Assert.True(risky.Has(PersistenceRuleIds.TargetRiskyFolder));
    }

    [Theory]
    [InlineData(@"C:\Users\alice\Downloads\setup.exe", TargetLocation.Downloads)]
    [InlineData(@"C:\Users\Public\Libraries\x.exe", TargetLocation.Public)]
    [InlineData(@"C:\$Recycle.Bin\S-1-5-21-1\$R1.exe", TargetLocation.RecycleBin)]
    [InlineData(@"C:\Windows\System32\cmd.exe", TargetLocation.Windows)]
    [InlineData(@"C:\Windows\Temp\x.exe", TargetLocation.Temp)]
    [InlineData(@"C:\ProgramData\Vendor\x.exe", TargetLocation.ProgramData)]
    [InlineData(@"\\?\C:\Program Files\App\x.exe.", TargetLocation.ProgramFiles)]
    public void TargetLocations_AreClassifiedByPathSegments(string path, TargetLocation expected) =>
        Assert.Equal(expected, TargetLocations.Classify(path, SystemRoot));

    // --- signature -------------------------------------------------------------------------------------------------

    [Fact]
    public void UnsignedOrBrokenSignature_IsAWeakSignalOnly()
    {
        var unsigned = Run(Entry(Vendor), Report(Vendor));
        Assert.Equal(Verdict.Clean, unsigned.Verdict);
        Assert.Equal(20, Assert.Single(unsigned.Signals, s => s.Rule == PersistenceRuleIds.TargetUnsigned).Score);

        var tampered = SignatureCheckResult.Invalid(SignatureFailureReason.HashMismatch, SignatureKind.Embedded, unchecked((int)0x80096010));
        Assert.True(Run(Entry(Vendor), Report(Vendor, signature: tampered)).Has(PersistenceRuleIds.TargetBrokenSignature));

        var script = @"C:\Program Files\Contoso\start.cmd";
        Assert.Empty(Run(Entry(script), Report(script)).Signals); // scripts aren't expected to be signed
    }

    // --- IFEO ------------------------------------------------------------------------------------------------------

    [Fact]
    public void IfeoDebugger_OnAnyImage_IsSuspicious()
    {
        var j = Run(Entry(Vendor, PersistenceKind.IfeoDebugger, valueName: "Debugger"), Report(Vendor, signature: VendorSigned()));

        Assert.Equal((Verdict.Suspicious, PersistencePriority.Normal), (j.Verdict, j.Priority));
        Assert.Equal(MitreTechniqueIds.ImageFileExecutionOptionsInjection, j.TechniqueId);
        Assert.Contains("notepad.exe", Assert.Single(j.Signals).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void IfeoDebugger_OnSethc_PointingAtMicrosoftCmd_IsStillSuspicious_HighPriority_AccessibilityFeatures()
    {
        // The classic sticky-keys backdoor runs a Microsoft-signed System32 binary: the signature must not clean it.
        var entry = Entry(Cmd, PersistenceKind.IfeoDebugger, location: Ifeo + @"\sethc.exe", valueName: "Debugger");

        var j = Run(entry, Report(Cmd, signature: MicrosoftSigned()));

        Assert.Equal((Verdict.Suspicious, PersistencePriority.High, 90), (j.Verdict, j.Priority, j.Score));
        Assert.Contains(MitreTechniqueIds.AccessibilityFeatures, j.SecondaryTechniqueIds);
    }

    [Theory]
    [InlineData(@"\taskmgr.exe", 80)]
    [InlineData(@"\MsMpEng.exe", 80)]
    [InlineData(@"\regedit.exe\Filter1", 80)] // a filtered IFEO subkey belongs to its image
    [InlineData(@"\game.exe", 60)]
    public void IfeoDebugger_OnASecurityTool_ScoresHigher(string subkey, int score)
    {
        var j = Run(Entry(Vendor, PersistenceKind.IfeoDebugger, location: Ifeo + subkey, valueName: "Debugger"), Report(Vendor, signature: VendorSigned()));
        Assert.Equal(score, j.Score);
    }

    [Fact]
    public void SilentProcessExitMonitor_IsSuspicious_AndADisabledOneIsLowerPriority()
    {
        const string location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe";
        var on = Run(Entry(Vendor, PersistenceKind.IfeoSilentProcessExit, location: location, valueName: "MonitorProcess"), Report(Vendor, signature: VendorSigned()));
        var off = Run(Entry(Vendor, PersistenceKind.IfeoSilentProcessExit, location: location, valueName: "MonitorProcess", enabled: false),
            Report(Vendor, signature: VendorSigned()));

        Assert.Equal((Verdict.Suspicious, PersistencePriority.Normal), (on.Verdict, on.Priority));
        Assert.Equal((Verdict.Suspicious, PersistencePriority.Low), (off.Verdict, off.Priority)); // still judged
    }

    // --- Winlogon --------------------------------------------------------------------------------------------------

    [Fact]
    public void Winlogon_DefaultShellAndUserinit_AreClean_AnythingElseIsSuspicious()
    {
        var explorer = @"C:\Windows\explorer.exe";
        var userinit = @"C:\Windows\System32\userinit.exe";
        Assert.Equal(Verdict.Clean, Run(Entry(explorer, PersistenceKind.WinlogonShell, valueName: "Shell"), Report(explorer, signature: MicrosoftSigned())).Verdict);
        Assert.Equal(Verdict.Clean, Run(Entry(userinit, PersistenceKind.WinlogonUserinit, valueName: "Userinit"), Report(userinit, signature: MicrosoftSigned())).Verdict);

        var shell = Run(Entry(Vendor, PersistenceKind.WinlogonShell, valueName: "Shell"), Report(Vendor, signature: VendorSigned()));
        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (shell.Verdict, shell.Priority));
        Assert.Equal(MitreTechniqueIds.WinlogonHelperDll, shell.TechniqueId);

        // Userinit "C:\Windows\system32\userinit.exe,C:\x\extra.exe": the second program is its own entry, Userinit[1].
        var extra = Run(Entry(userinit, PersistenceKind.WinlogonUserinit, valueName: "Userinit[1]"), Report(userinit, signature: MicrosoftSigned()));
        Assert.Equal(Verdict.Suspicious, extra.Verdict);
        Assert.Contains("also runs", Assert.Single(extra.Signals).Reason, StringComparison.Ordinal);
    }

    // --- missing target ------------------------------------------------------------------------------------------------

    [Fact]
    public void MissingTarget_IsInformational_UnlessUsersCanCreateIt()
    {
        var gone = @"C:\Program Files\Removed\old.exe";
        var leftover = Run(Entry(gone, flags: ResolutionFlag.TargetNotFound));
        Assert.Equal((Verdict.Clean, 20), (leftover.Verdict, leftover.Score));
        Assert.True(leftover.Has(PersistenceRuleIds.MissingTarget));

        var dangling = @"C:\Vendor\agent.exe";
        var service = Run(Entry(dangling, PersistenceKind.Service, valueName: "ImagePath"), NotFound(dangling), acl: new FakeAcl().WithFolder(@"C:\"));
        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (service.Verdict, service.Priority));
        Assert.True(service.Has(PersistenceRuleIds.MissingTargetHijackable));
        Assert.Contains(MitreTechniqueIds.ServicesFilePermissionsWeakness, service.SecondaryTechniqueIds);
        Assert.False(service.Has(PersistenceRuleIds.TargetUserModifiable)); // the location rule leaves missing targets alone
    }

    // --- unquoted path -----------------------------------------------------------------------------------------------

    [Fact]
    public void UnquotedCandidates_AreThePrefixesCreateProcessTriesFirst()
    {
        Assert.Equal([@"C:\Program.exe", @"C:\Program Files\My.exe"], PersistenceRules.UnquotedCandidates(@"C:\Program Files\My App\app.exe"));
        Assert.Equal([@"C:\Tools\v1.2"], PersistenceRules.UnquotedCandidates(@"C:\Tools\v1.2 beta\t.exe"));
        Assert.Empty(PersistenceRules.UnquotedCandidates(@"C:\Tools\t.exe"));
    }

    [Fact]
    public void UnquotedPath_WithAUserCreatableShorterPath_IsSuspicious_T1574_009()
    {
        var target = @"C:\Apps\My Tool\tool.exe";
        var entry = Entry(target, PersistenceKind.Service, valueName: "ImagePath", flags: ResolutionFlag.UnquotedPathWithSpaces);

        var hijackable = Run(entry, Report(target, signature: VendorSigned()), acl: new FakeAcl().WithFolder(@"C:\Apps"));
        var signal = Assert.Single(hijackable.Signals, s => s.Rule == PersistenceRuleIds.UnquotedPathHijackable);
        Assert.Equal(MitreTechniqueIds.PathInterceptionByUnquotedPath, signal.TechniqueId);
        Assert.Contains(@"C:\Apps\My.exe", signal.Reason, StringComparison.Ordinal);
        Assert.Equal(Verdict.Suspicious, hijackable.Verdict);

        var safe = Run(entry, Report(target, signature: VendorSigned()));
        Assert.Equal(Verdict.Clean, safe.Verdict);
        Assert.True(safe.Has(PersistenceRuleIds.UnquotedPath));
    }

    // --- hosts, inline, remote, COM ------------------------------------------------------------------------------------

    [Fact]
    public void ScriptHost_RunningAScriptFromTemp_IsSuspicious_WithThePowerShellTechnique()
    {
        var ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var script = @"C:\Users\alice\AppData\Local\Temp\a.ps1";
        var j = Run(Entry(script, sid: Sid, host: ps, flags: ResolutionFlag.InterpreterHost), Report(script), Report(ps, signature: MicrosoftSigned()),
            new FakeAcl().WithFolder(@"C:\Users\alice"));

        Assert.Equal(Verdict.Suspicious, j.Verdict);
        Assert.Contains(MitreTechniqueIds.PowerShell, j.SecondaryTechniqueIds);
    }

    [Fact]
    public void InlineScript_ThroughMshta_IsSuspicious_InlinePowerShellAloneIsNot()
    {
        var mshta = @"C:\Windows\System32\mshta.exe";
        var j = Run(Entry(null, host: mshta, flags: [ResolutionFlag.InterpreterHost, ResolutionFlag.InlineCommand]), host: Report(mshta, signature: MicrosoftSigned()));
        Assert.Equal((Verdict.Suspicious, PersistencePriority.High), (j.Verdict, j.Priority));
        Assert.Contains(MitreTechniqueIds.Mshta, j.SecondaryTechniqueIds);

        var ps = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var inline = Run(Entry(null, host: ps, flags: [ResolutionFlag.InterpreterHost, ResolutionFlag.InlineCommand]), host: Report(ps, signature: MicrosoftSigned()));
        Assert.Equal(Verdict.Clean, inline.Verdict); // 50: E4 decodes and judges encoded commands
        Assert.True(inline.Has(PersistenceRuleIds.InlineCommand));
    }

    [Fact]
    public void RemotePayload_ThroughRegsvr32_IsSuspicious_T1218_010()
    {
        var regsvr32 = @"C:\Windows\System32\regsvr32.exe";
        var dll = @"C:\Windows\System32\scrobj.dll";
        var j = Run(Entry(dll, host: regsvr32, flags: [ResolutionFlag.InterpreterHost, ResolutionFlag.RemotePayload]),
            Report(dll, signature: MicrosoftSigned()), Report(regsvr32, signature: MicrosoftSigned()));

        Assert.Equal(Verdict.Suspicious, j.Verdict); // not dropped: only weak signals go for Microsoft system targets
        Assert.Contains(MitreTechniqueIds.Regsvr32, j.SecondaryTechniqueIds);
    }

    [Fact]
    public void UserComOverride_IsSuspicious_T1546_015()
    {
        var dll = @"C:\Users\alice\AppData\Roaming\x.dll";
        var entry = new PersistenceEntry(PersistenceKind.ScheduledTask, Sid, @"\Microsoft\Windows\Test", "ComHandler[0]", "{0000}",
            ResolvedCommand.Resolved(dll, flags: [ResolutionFlag.UserComOverride, ResolutionFlag.UserEnvironment]), true, comClassId: Guid.NewGuid());

        var j = Run(entry, Report(dll, signature: VendorSigned()));

        Assert.Equal((Verdict.Suspicious, MitreTechniqueIds.ScheduledTask), (j.Verdict, j.TechniqueId));
        Assert.Contains(MitreTechniqueIds.ComponentObjectModelHijacking, j.SecondaryTechniqueIds);
        Assert.Equal(Verdict.Clean, Run(Entry(dll, PersistenceKind.ScheduledTask, sid: Sid, location: @"\T"), Report(dll, signature: VendorSigned())).Verdict);
    }

    // --- priority, MITRE, extensibility -----------------------------------------------------------------------------------

    [Fact]
    public void DisabledEntries_AreJudged_ButOneStepLowerInPriority()
    {
        var on = Run(Entry(Vendor), Report(Vendor, Verdict.Malicious));
        var off = Run(Entry(Vendor, enabled: false), Report(Vendor, Verdict.Malicious));

        Assert.Equal((Verdict.Malicious, PersistencePriority.High), (on.Verdict, on.Priority));
        Assert.Equal((Verdict.Malicious, PersistencePriority.Normal), (off.Verdict, off.Priority));
    }

    [Theory]
    [InlineData(PersistenceKind.RunKey, "T1547.001")]
    [InlineData(PersistenceKind.RunOnceKey, "T1547.001")]
    [InlineData(PersistenceKind.StartupFolder, "T1547.001")]
    [InlineData(PersistenceKind.WinlogonShell, "T1547.004")]
    [InlineData(PersistenceKind.IfeoDebugger, "T1546.012")]
    [InlineData(PersistenceKind.Service, "T1543.003")]
    [InlineData(PersistenceKind.ScheduledTask, "T1053.005")]
    public void RuleBasedFindings_HaveTheEntryKindAsPrimaryTechnique_AndOnlyCatalogTechniques(PersistenceKind kind, string technique)
    {
        var temp = @"C:\Windows\Temp\x.exe";
        var entry = Entry(temp, kind, location: kind == PersistenceKind.IfeoDebugger ? Ifeo + @"\x.exe" : null,
            valueName: kind == PersistenceKind.WinlogonShell ? "Shell" : "App");

        var j = Run(entry, Report(temp), acl: new FakeAcl().WithFolder(@"C:\Windows\Temp"));

        Assert.Equal(Verdict.Suspicious, j.Verdict);
        Assert.Equal(technique, j.TechniqueId);
        Assert.All(j.SecondaryTechniqueIds.Prepend(j.TechniqueId), id => Assert.True(MitreCatalog.IsKnown(id), id));
    }

    private sealed class AlwaysRule : IPersistenceRule
    {
        public void Evaluate(PersistenceRuleContext context) => context.Add("e4-test", 70, "added by an extension rule", MitreTechniqueIds.PowerShell);
    }

    private sealed class ThrowingRule : IPersistenceRule
    {
        public void Evaluate(PersistenceRuleContext context) => throw new InvalidOperationException("boom");
    }

    [Fact]
    public void ExtraRules_PlugIn_AndAFailingRuleDoesNotHideTheOthers()
    {
        var judge = Judge.WithRules(new ThrowingRule(), new AlwaysRule());

        var j = judge.Judge(Entry(Vendor), Report(Vendor, signature: VendorSigned()), null, new FakeAcl());

        Assert.Equal(Verdict.Suspicious, j.Verdict);
        Assert.True(j.Has("e4-test"));
        Assert.True(j.Has(PersistenceRuleIds.RuleFailed));
        Assert.Equal(PersistenceRules.Default.Count + 2, judge.Rules.Count);
    }
}
