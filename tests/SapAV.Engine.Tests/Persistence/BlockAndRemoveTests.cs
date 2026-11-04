using Microsoft.Win32;
using SapAV.Core.Alerts;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Engine.Alerts;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Remediation;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// D5 Block &amp; remove with backup and restore, per persistence type, against throwaway HKCU test keys, temp folders and fake
/// SCM / Task Scheduler (nothing real is changed), plus authorization, the TOCTOU guard, no-clobber restore and tampering.
/// </summary>
public sealed class BlockAndRemoveTests : IDisposable
{
    private const string Alice = RemediationHarness.Alice;
    private const string Bob = RemediationHarness.Bob;
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string IfeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe";

    private readonly RemediationHarness _h = new();

    public void Dispose() => _h.Dispose();

    private RawRegistryValue? Raw(RegistryRoot root, string path, string name)
    {
        var editor = new NoFollowRegistryEditor(_h.Registry.MachineKey, _h.Registry.UsersKey);
        return editor.Read(root, path, name, out var value) == RegistryEditStatus.Ok ? value : null;
    }

    [Fact]
    public void UserRunValue_RemoveThenRestore_RoundTripsTheExactValue_WithEventLogRecords()
    {
        using (var run = _h.UserRunKey(Alice))
        {
            run.SetValue("Updater", @"%APPDATA%\upd\upd.exe -q", RegistryValueKind.ExpandString);
            run.SetValue("Other", @"C:\Tools\keep.exe");
        }

        string path = $@"{Alice}\{RemediationHarness.UserRun}";
        var before = Raw(RegistryRoot.Users, path, "Updater")!;
        var alice = _h.User(Alice);

        var blocked = _h.Block(alice, _h.IdOf("Updater"));

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.Null(Raw(RegistryRoot.Users, path, "Updater"));
        Assert.NotNull(Raw(RegistryRoot.Users, path, "Other")); // only that value
        var record = blocked.Record!;
        Assert.Equal((PersistenceBackupAction.ValueDeleted, Alice, Alice), (record.Action, record.UserSid, record.BlockedBy));
        var blockedAlert = Assert.Single(_h.Alerts.Snapshot(), a => a.Type == AlertType.PersistenceBlocked);
        Assert.Equal((3002, "T1547.001", AlertAction.Blocked), (AlertEventCatalog.For(blockedAlert.Type).EventId, blockedAlert.TechniqueId, blockedAlert.Action));

        var restored = _h.Restore(alice, record.Id);

        Assert.Equal(RemediationStatus.Restored, restored.Status);
        var after = Raw(RegistryRoot.Users, path, "Updater")!;
        Assert.Equal(RawRegistryValue.RegSz + 1, after.Type); // REG_EXPAND_SZ kept, nothing expanded
        Assert.True(before.SameAs(after));
        Assert.Equal(PersistenceBackupState.Restored, Assert.Single(_h.Remediator.List(alice)).State);
        var restoredAlert = Assert.Single(_h.Alerts.Snapshot(), a => a.Type == AlertType.PersistenceRestored);
        Assert.Equal((3003, AlertAction.Restored), (AlertEventCatalog.For(restoredAlert.Type).EventId, restoredAlert.Action));
    }

    [Fact]
    public void MachineWideEntries_AreAdministratorOnly()
    {
        _h.Registry.Machine(RemediationHarness.MachineRun).SetValue("Vendor", @"C:\Program Files\Vendor\tray.exe");
        _h.AddService("EvilSvc", @"C:\evil\svc.exe");
        string taskPath = _h.AddTask("MachineTask", @"C:\evil\task.exe", principal: "S-1-5-18");
        var alice = _h.User(Alice);

        Assert.Equal(RemediationStatus.AccessDenied, _h.Block(alice, _h.IdOf("Vendor")).Status);
        Assert.Equal(RemediationStatus.AccessDenied, _h.Block(alice, PersistenceEntryId.Compute(_h.Entry(e => e.Kind == PersistenceKind.Service && e.Location.EndsWith("EvilSvc")))).Status);
        Assert.Equal(RemediationStatus.AccessDenied, _h.Block(alice, PersistenceEntryId.Compute(_h.Entry(e => e.Location == taskPath))).Status);
        Assert.NotNull(_h.Registry.Machine(RemediationHarness.MachineRun).GetValue("Vendor"));
        Assert.Equal(2, _h.Services.Services["EvilSvc"].StartType);
        Assert.True(_h.TaskScheduler.Tasks[taskPath].Enabled);

        Assert.Equal(RemediationStatus.Blocked, _h.Block(_h.Admin(), _h.IdOf("Vendor")).Status);
    }

    [Fact]
    public void AnotherUsersEntriesAndBackups_AreOutOfReachOfAStandardUser()
    {
        using (var run = _h.UserRunKey(Bob))
        {
            run.SetValue("BobsTool", @"C:\Tools\bob.exe");
        }

        string bobsId = _h.IdOf("BobsTool");
        var alice = _h.User(Alice);

        Assert.Equal(RemediationStatus.EntryChanged, _h.Block(alice, bobsId).Status); // Alice's scope is all that is collected for her
        Assert.NotNull(_h.UserRunKey(Bob).GetValue("BobsTool"));

        var byAdmin = _h.Block(_h.Admin(), bobsId);
        Assert.Equal(RemediationStatus.Blocked, byAdmin.Status);
        Assert.Empty(_h.Remediator.List(alice));
        Assert.Equal(RemediationStatus.NotFound, _h.Restore(alice, byAdmin.Record!.Id).Status);
        Assert.Equal(RemediationStatus.NotFound, _h.Remediator.Purge(alice, byAdmin.Record.Id).Status);
        Assert.Null(_h.UserRunKey(Bob).GetValue("BobsTool"));
        Assert.Single(_h.Remediator.List(_h.User(Bob)));
    }

    [Fact]
    public void EntryChangedAfterItsIdWasGivenOut_IsRefused_AndLeftAlone()
    {
        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Tools\upd.exe");
        string id = _h.IdOf("Updater");
        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Users\alice\AppData\Local\Temp\other.exe"); // swapped after the alert

        var result = _h.Block(_h.User(Alice), id);

        Assert.Equal(RemediationStatus.EntryChanged, result.Status);
        Assert.Equal(@"C:\Users\alice\AppData\Local\Temp\other.exe", _h.UserRunKey(Alice).GetValue("Updater"));
        Assert.Empty(_h.Store.List());
        Assert.Equal(RemediationStatus.NotFound, _h.Block(_h.User(Alice), "pe1-RunKey-u-XYZ").Status); // not even an ID
    }

    [Fact]
    public void Restore_RefusesToClobberWhatIsThereNow()
    {
        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Tools\upd.exe");
        var alice = _h.User(Alice);
        var record = _h.Block(alice, _h.IdOf("Updater")).Record!;
        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Tools\new.exe");

        var result = _h.Restore(alice, record.Id);

        Assert.Equal(RemediationStatus.LocationChanged, result.Status);
        Assert.Equal(@"C:\Tools\new.exe", _h.UserRunKey(Alice).GetValue("Updater"));
        Assert.Equal(PersistenceBackupState.Active, Assert.Single(_h.Remediator.List(alice)).State); // still restorable later
        Assert.DoesNotContain(_h.Alerts.Snapshot(), a => a.Type == AlertType.PersistenceRestored);
    }

    [Fact]
    public void WinlogonUserinit_IsSetBackToTheWindowsDefault_NeverDeleted_AndRestoredExactly()
    {
        using (var winlogon = _h.Registry.Machine(WinlogonKey))
        {
            winlogon.SetValue("Shell", "explorer.exe");
            winlogon.SetValue("Userinit", @"C:\Windows\system32\userinit.exe, C:\ProgramData\evil.exe,");
        }

        var admin = _h.Admin();
        var blocked = _h.Block(admin, _h.IdOf("Userinit[1]"));

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.Equal(PersistenceBackupAction.ValueReset, blocked.Record!.Action);
        Assert.Equal(@"C:\Windows\system32\userinit.exe,", _h.Registry.Machine(WinlogonKey).GetValue("Userinit"));
        Assert.Equal(RemediationStatus.NothingToDo, _h.Block(admin, _h.IdOf("Shell")).Status); // already the default
        Assert.Equal("explorer.exe", _h.Registry.Machine(WinlogonKey).GetValue("Shell"));

        Assert.Equal(RemediationStatus.Restored, _h.Restore(admin, blocked.Record.Id).Status);
        Assert.Equal(@"C:\Windows\system32\userinit.exe, C:\ProgramData\evil.exe,", _h.Registry.Machine(WinlogonKey).GetValue("Userinit"));
    }

    [Fact]
    public void IfeoDebugger_OnlyTheDebuggerValueIsRemoved()
    {
        using (var ifeo = _h.Registry.Machine(IfeoKey))
        {
            ifeo.SetValue("Debugger", @"C:\evil\dbg.exe");
            ifeo.SetValue("GlobalFlag", 0, RegistryValueKind.DWord);
        }

        var admin = _h.Admin();
        var blocked = _h.Block(admin, _h.IdOf("Debugger"));

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        using (var ifeo = _h.Registry.Machine(IfeoKey))
        {
            Assert.Null(ifeo.GetValue("Debugger"));
            Assert.Equal(0, ifeo.GetValue("GlobalFlag"));
        }

        Assert.Equal(RemediationStatus.Restored, _h.Restore(admin, blocked.Record!.Id).Status);
        Assert.Equal(@"C:\evil\dbg.exe", _h.Registry.Machine(IfeoKey).GetValue("Debugger"));
    }

    [Fact]
    public void Service_IsDisabledAndStopped_NotDeleted_AndRestoreRefusesAChangedStartType()
    {
        _h.AddService("EvilSvc", @"C:\evil\svc.exe", start: 2, running: true);
        var admin = _h.Admin();

        var blocked = _h.Block(admin, PersistenceEntryId.Compute(_h.Entry(e => e.Kind == PersistenceKind.Service && e.Location.EndsWith(@"\EvilSvc"))));

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.Equal(new ServiceState(4, false), _h.Services.Services["EvilSvc"]); // still there: disabled and stopped
        Assert.Equal(["EvilSvc"], _h.Services.Stopped);
        Assert.Equal((2, true), (blocked.Record!.OldStartType, blocked.Record.WasRunning));
        Assert.NotNull(_h.Registry.Machine(@"SYSTEM\CurrentControlSet\Services\EvilSvc").GetValue("ImagePath"));

        _h.Services.Services["EvilSvc"] = new ServiceState(3, false); // someone changed it since
        Assert.Equal(RemediationStatus.LocationChanged, _h.Restore(admin, blocked.Record.Id).Status);
        Assert.Equal(3, _h.Services.Services["EvilSvc"].StartType);

        _h.Services.Services["EvilSvc"] = new ServiceState(4, false);
        Assert.Equal(RemediationStatus.Restored, _h.Restore(admin, blocked.Record.Id).Status);
        Assert.Equal(2, _h.Services.Services["EvilSvc"].StartType);
    }

    [Fact]
    public void Engines_OwnService_IsNeverDisabled()
    {
        _h.AddService(EngineHost.ServiceName, @"C:\Program Files\sap-AV\SapAV.Engine.exe");

        var result = _h.Block(_h.Admin(), PersistenceEntryId.Compute(_h.Entry(e => e.Kind == PersistenceKind.Service)));

        Assert.Equal(RemediationStatus.NotSupported, result.Status);
        Assert.Equal(2, _h.Services.Services[EngineHost.ServiceName].StartType);
    }

    [Fact]
    public void UsersOwnTask_IsDisabledThroughTheScheduler_FileUntouched_AndReenabledOnlyIfUnchanged()
    {
        string taskPath = _h.AddTask("AliceTask", @"C:\Users\alice\AppData\Local\Temp\t.exe", principal: Alice);
        byte[] file = File.ReadAllBytes(Path.Combine(_h.Tasks, "AliceTask"));
        var alice = _h.User(Alice);

        var blocked = _h.Block(alice, PersistenceEntryId.Compute(_h.Entry(e => e.Location == taskPath)));

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.False(_h.TaskScheduler.Tasks[taskPath].Enabled);
        Assert.Equal(file, File.ReadAllBytes(Path.Combine(_h.Tasks, "AliceTask"))); // the definition file is never edited
        Assert.Contains("<Exec>", blocked.Record!.TaskXml);

        var disabled = _h.TaskScheduler.Tasks[taskPath];
        _h.TaskScheduler.Tasks[taskPath] = disabled with { Xml = disabled.Xml + "<!-- changed -->" };
        Assert.Equal(RemediationStatus.LocationChanged, _h.Restore(alice, blocked.Record.Id).Status);
        Assert.False(_h.TaskScheduler.Tasks[taskPath].Enabled);

        _h.TaskScheduler.Tasks[taskPath] = disabled;
        Assert.Equal(RemediationStatus.Restored, _h.Restore(alice, blocked.Record.Id).Status);
        Assert.True(_h.TaskScheduler.Tasks[taskPath].Enabled);
    }

    [Fact]
    public void Task_WhoseRegisteredPrincipalIsSomeoneElse_IsRefusedToAStandardUser()
    {
        string taskPath = _h.AddTask("Claimed", @"C:\Tools\t.exe", principal: Alice); // the file claims Alice...
        _h.TaskScheduler.Tasks[taskPath] = _h.TaskScheduler.Tasks[taskPath] with { PrincipalUserId = Bob }; // ...the Task Scheduler says Bob

        var result = _h.Block(_h.User(Alice), PersistenceEntryId.Compute(_h.Entry(e => e.Location == taskPath)));

        Assert.Equal(RemediationStatus.AccessDenied, result.Status);
        Assert.True(_h.TaskScheduler.Tasks[taskPath].Enabled);
        Assert.Empty(_h.Store.List());
    }

    [Fact]
    public void StartupItem_IsMovedIntoQuarantine_AndRestoredOnlyWhenItsNameIsFree()
    {
        string item = Path.Combine(_h.AliceStartup, "evil.cmd");
        byte[] content = "@echo synthetic startup item"u8.ToArray();
        File.WriteAllBytes(item, content);
        var alice = _h.User(Alice);

        var blocked = _h.Block(alice, _h.IdOf("evil.cmd"));

        Assert.Equal(RemediationStatus.Blocked, blocked.Status);
        Assert.False(File.Exists(item));
        Assert.NotNull(_h.Quarantine.Manager.Get(blocked.Record!.QuarantineItemId!));

        File.WriteAllText(item, "a new file with that name");
        Assert.Equal(RemediationStatus.LocationChanged, _h.Restore(alice, blocked.Record.Id).Status);
        Assert.Equal("a new file with that name", File.ReadAllText(item));

        File.Delete(item);
        Assert.Equal(RemediationStatus.Restored, _h.Restore(alice, blocked.Record.Id).Status);
        Assert.Equal(content, File.ReadAllBytes(item));
    }

    [Fact]
    public void TamperedBackup_IsNeverActedOn()
    {
        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Tools\upd.exe");
        var alice = _h.User(Alice);
        var record = _h.Block(alice, _h.IdOf("Updater")).Record!;
        string file = Path.Combine(_h.Store.Folder, record.Id + FilePersistenceBackupStore.Extension);
        string text = File.ReadAllText(file);
        File.WriteAllText(file, text.Replace(@"upd.exe", @"pwn.exe", StringComparison.Ordinal)); // a forged value to "restore"

        Assert.Equal(RemediationStatus.NotFound, _h.Restore(alice, record.Id).Status);
        Assert.Equal(RemediationStatus.InvalidBackup, _h.Restore(_h.Admin(), record.Id).Status);
        Assert.Null(_h.UserRunKey(Alice).GetValue("Updater"));
        Assert.Empty(_h.Remediator.List(alice));
        Assert.Equal(BackupLoadStatus.Invalid, _h.Store.TryLoad(record.Id, out _));
    }

    [Fact]
    public void ARegistryLinkOnTheWay_IsRefused_NotFollowed()
    {
        string target = $@"{Alice}\Software\LinkTarget";
        _h.Registry.Users(target).SetValue("Planted", @"C:\Tools\planted.exe");
        using var link = RegistryLink.Create(_h.Registry.UsersKey, $@"{Alice}\Software\Microsoft\Windows\CurrentVersion\Run", _h.Registry.UsersKey, target);

        var entry = _h.Entry("Planted"); // the read-only collector follows the link (as any reader)
        var result = _h.Block(_h.User(Alice), PersistenceEntryId.Compute(entry));

        Assert.Equal(RemediationStatus.Redirected, result.Status);
        Assert.NotNull(_h.Registry.Users(target).GetValue("Planted"));
        Assert.Empty(_h.Store.List());
    }

    [Fact]
    public void AValueInTheUsersHive_TheyCantChangeThemselves_IsRefused()
    {
        string policies = $@"{Alice}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
        _h.Registry.Users(policies).SetValue("CorpAgent", @"C:\Program Files\Corp\agent.exe");
        using (var key = _h.Registry.Users(policies))
        {
            var security = key.GetAccessControl();
            using var me = System.Security.Principal.WindowsIdentity.GetCurrent();
            security.AddAccessRule(new System.Security.AccessControl.RegistryAccessRule(me.User!, System.Security.AccessControl.RegistryRights.SetValue,
                System.Security.AccessControl.AccessControlType.Deny));
            key.SetAccessControl(security); // like an administrator-set policy key: the user may read it, not change it
        }

        var result = _h.Block(_h.User(Alice), _h.IdOf("CorpAgent"));

        Assert.Equal(RemediationStatus.AccessDenied, result.Status);
        using (var readOnly = _h.Registry.UsersKey.OpenSubKey(policies))
        {
            Assert.NotNull(readOnly!.GetValue("CorpAgent"));
        }

        Assert.Empty(_h.Store.List());
    }

    [Fact]
    public void PerUserBackupQuota_StopsAStandardUser_AndOnlyRestoredHistoryIsTrimmed()
    {
        var record = new PersistenceBackupRecord
        {
            Id = string.Empty, Kind = PersistenceKind.Service, UserSid = Alice, Location = "x", CommandLine = "x", EntryKey = "x",
            Action = PersistenceBackupAction.ServiceDisabled, BlockedBy = Alice, BlockedAtUtc = DateTimeOffset.UnixEpoch, ServiceName = "s", OldStartType = 2,
        };
        var active = Enumerable.Range(0, PersistenceRemediator.MaxActivePerUser).Select(_ => record with { Id = FilePersistenceBackupStore.NewId() }).ToArray();
        foreach (var r in active)
        {
            _h.Store.Save(r);
        }

        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Tools\upd.exe");
        Assert.Equal(RemediationStatus.QuotaExceeded, _h.Block(_h.User(Alice), _h.IdOf("Updater")).Status);
        Assert.NotNull(_h.UserRunKey(Alice).GetValue("Updater"));

        foreach (var r in active)
        {
            _h.Store.Save(r with { State = PersistenceBackupState.Restored }); // history only now...
        }

        for (int i = active.Length; i < PersistenceRemediator.MaxRecordsPerUser; i++)
        {
            _h.Store.Save(record with { Id = FilePersistenceBackupStore.NewId(), State = PersistenceBackupState.Restored, BlockedAtUtc = DateTimeOffset.UnixEpoch.AddDays(1) });
        }

        Assert.Equal(RemediationStatus.Blocked, _h.Block(_h.User(Alice), _h.IdOf("Updater")).Status); // ...so the oldest one makes room
        Assert.Equal(PersistenceRemediator.MaxRecordsPerUser, _h.Store.List().Count);
        Assert.Single(_h.Store.List(), r => r.Record!.State == PersistenceBackupState.Active);
    }
}
