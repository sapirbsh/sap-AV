using Microsoft.Win32;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>Run / RunOnce, Winlogon and IFEO collection (ROADMAP C2) against a throwaway HKCU key.</summary>
public sealed class RegistryCollectorTests : IDisposable
{
    private const string Sid = RegistryTestRoot.UserSid;
    private readonly RegistryTestRoot _root = new();
    private readonly SetProbe _probe = new(@"C:\Windows\explorer.exe", @"C:\Windows\System32\userinit.exe");

    public void Dispose() => _root.Dispose();

    [Fact]
    public void MachineRunKeys_IncludingWow64_AreCollected_AndTaskManagerDisabledIsReported()
    {
        using (var run = _root.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
        {
            run.SetValue("Vendor", @"""C:\Program Files\Vendor\tray.exe"" /background");
            run.SetValue("Off", @"C:\Tools\off.exe");
            run.SetValue("", @"C:\ignored-default.exe");
            run.SetValue("Number", 5, RegistryValueKind.DWord);
        }

        _root.Machine(@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce").SetValue("Setup32", @"C:\Setup\once.exe");
        _root.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            .SetValue("Off", new byte[] { 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, RegistryValueKind.Binary);

        var result = _root.Collect(_probe, new RegistryAutorunSource());

        var vendor = result.Single("Vendor");
        Assert.Equal(PersistenceKind.RunKey, vendor.Kind);
        Assert.True(vendor.IsMachineScope);
        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", vendor.Location);
        Assert.Equal(@"C:\Program Files\Vendor\tray.exe", vendor.Resolution.TargetPath);
        Assert.True(vendor.Enabled);
        Assert.False(result.Single("Off").Enabled);
        Assert.Equal(PersistenceKind.RunOnceKey, result.Single("Setup32").Kind);
        Assert.Equal("T1547.001", result.Single("Setup32").TechniqueId);
        Assert.DoesNotContain(result.Entries, e => e.ValueName is "" or "Number");
    }

    [Fact]
    public void LoadedUserHive_IsCollectedWithTheUsersEnvironment()
    {
        _root.AddUser(Sid, @"C:\Users\alice", loaded: true);
        _root.Users($@"{Sid}\Software\Microsoft\Windows\CurrentVersion\Run").SetValue("Updater", @"%APPDATA%\upd\upd.exe -q", RegistryValueKind.ExpandString);

        var entry = _root.Collect(_probe, new RegistryAutorunSource()).Single("Updater");

        Assert.Equal(Sid, entry.UserSid);
        Assert.Equal($@"HKU\{Sid}\Software\Microsoft\Windows\CurrentVersion\Run", entry.Location);
        Assert.Equal(@"C:\Users\alice\AppData\Roaming\upd\upd.exe", entry.Resolution.TargetPath);
        Assert.Contains(ResolutionFlag.UserEnvironment, entry.Resolution.Flags);
        Assert.Equal(@"%APPDATA%\upd\upd.exe -q", entry.CommandLine); // stored as written, not expanded
    }

    [Fact]
    public void UnloadedProfile_IsSkippedAndReportedAsNotCollected()
    {
        _root.AddUser(Sid, @"C:\Users\bob", loaded: false);

        var result = _root.Collect(_probe, new RegistryAutorunSource());

        var issue = Assert.Single(result.Issues, i => i.Reason == PersistenceIssueReason.HiveNotLoaded);
        Assert.Equal(Sid, issue.UserSid);
        Assert.DoesNotContain(result.Entries, e => e.UserSid == Sid);
    }

    [Fact]
    public void Winlogon_ShellAndUserinit_OneEntryPerProgram()
    {
        using (var winlogon = _root.Machine(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
        {
            winlogon.SetValue("Shell", "explorer.exe");
            winlogon.SetValue("Userinit", @"C:\Windows\system32\userinit.exe, C:\ProgramData\evil.exe,");
        }

        var result = _root.Collect(_probe, new RegistryAutorunSource());

        var shell = result.Single("Shell");
        Assert.Equal(PersistenceKind.WinlogonShell, shell.Kind);
        Assert.Equal(@"C:\Windows\explorer.exe", shell.Resolution.TargetPath);
        Assert.Equal(@"C:\Windows\system32\userinit.exe", result.Single("Userinit").Resolution.TargetPath);
        Assert.Equal(@"C:\ProgramData\evil.exe", result.Single("Userinit[1]").Resolution.TargetPath);
        Assert.Equal("T1547.004", result.Single("Userinit[1]").TechniqueId);
    }

    [Fact]
    public void Ifeo_DebuggerFilteredDebuggerAndSilentProcessExit()
    {
        const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        _root.Machine($@"{ifeo}\sethc.exe").SetValue("Debugger", @"C:\Windows\System32\cmd.exe");
        _root.Machine($@"{ifeo}\mitigated.exe").SetValue("MitigationOptions", new byte[8], RegistryValueKind.Binary);
        _root.Machine($@"{ifeo}\app.exe").SetValue("UseFilter", 1, RegistryValueKind.DWord);
        _root.Machine($@"{ifeo}\app.exe\filter1").SetValue("Debugger", @"C:\Users\Public\dbg.exe");
        _root.Machine($@"{ifeo}\notepad.exe").SetValue("GlobalFlag", "0x00000200");
        const string exits = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
        using (var notepad = _root.Machine($@"{exits}\notepad.exe"))
        {
            notepad.SetValue("MonitorProcess", @"C:\Users\Public\mon.exe");
            notepad.SetValue("ReportingMode", 1, RegistryValueKind.DWord);
        }

        _root.Machine($@"{exits}\calc.exe").SetValue("MonitorProcess", @"C:\Users\Public\mon2.exe"); // no GlobalFlag: dormant

        var result = _root.Collect(_probe, new RegistryAutorunSource());

        var debuggers = result.Entries.Where(e => e.Kind == PersistenceKind.IfeoDebugger).ToList();
        Assert.Equal(2, debuggers.Count);
        Assert.Contains(debuggers, d => d.Location.EndsWith(@"\sethc.exe", StringComparison.Ordinal) && d.Resolution.TargetPath == @"C:\Windows\System32\cmd.exe");
        Assert.Contains(debuggers, d => d.Location.EndsWith(@"\app.exe\filter1", StringComparison.Ordinal));
        var monitors = result.Entries.Where(e => e.Kind == PersistenceKind.IfeoSilentProcessExit).ToDictionary(e => e.Resolution.TargetPath!);
        Assert.True(monitors[@"C:\Users\Public\mon.exe"].Enabled);
        Assert.False(monitors[@"C:\Users\Public\mon2.exe"].Enabled);
        Assert.All(result.Entries, e => Assert.Equal("T1546.012", e.TechniqueId));
    }

    [Fact]
    public void AFailingSource_TheBudgetAndTheEntryCap_BecomeIssues_NotExceptions()
    {
        _root.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run").SetValue("A", @"C:\a.exe");
        _root.Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce").SetValue("B", @"C:\b.exe");

        var failing = new PersistenceCollector(_root.View, _probe, [new ThrowingSource(), new RegistryAutorunSource()]).Collect();
        var capped = new PersistenceCollector(_root.View, _probe, [new RegistryAutorunSource()], new PersistenceLimits { MaxEntries = 1 }).Collect();
        var outOfTime = new PersistenceCollector(_root.View, _probe, [new RegistryAutorunSource()], new PersistenceLimits { TimeBudget = TimeSpan.Zero }).Collect();

        Assert.Contains(failing.Issues, i => i.Reason == PersistenceIssueReason.Error && i.Location == "thrower");
        Assert.Equal(2, failing.Entries.Count);
        Assert.Single(capped.Entries);
        Assert.Contains(capped.Issues, i => i.Reason == PersistenceIssueReason.LimitReached);
        Assert.Contains(outOfTime.Issues, i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded);
        Assert.Throws<OperationCanceledException>(() =>
            new PersistenceCollector(_root.View, _probe, [new RegistryAutorunSource()]).Collect(new CancellationToken(canceled: true)));
    }

    [Fact]
    public void Environments_AreBuiltFromTheRegistry_UserPathAppended()
    {
        _root.AddUser(Sid, @"%SystemDrive%\Users\carol", loaded: true);
        _root.Users($@"{Sid}\Environment").SetValue("Path", @"C:\Users\carol\bin");

        var machine = RegistryEnvironment.Machine(_root.View);
        var users = RegistryEnvironment.Profiles(_root.View, machine, (_, _, _, _, _) => { }, 16);

        Assert.Equal(@"C:\Windows\system32;C:\Windows;C:\Tools", machine.Get("Path"));
        Assert.Null(machine.Get("APPDATA"));
        var carol = Assert.Single(users);
        Assert.Equal(@"C:\Users\carol", carol.ProfilePath);
        Assert.True(carol.HiveLoaded);
        Assert.EndsWith(@";C:\Users\carol\bin", carol.Environment.Get("Path"));
        Assert.Contains(@"C:\Users\carol\bin", carol.Environment.SearchDirectories);
    }

    private sealed class ThrowingSource : IPersistenceSource
    {
        public string Name => "thrower";

        public void Collect(PersistenceContext context) => throw new InvalidOperationException("boom");
    }
}
