using System.Security;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.EventLogging;

public sealed class EventLogSourceInstallerTests
{
    private const string MessageFile = @"C:\Program Files\sap-AV\System.Diagnostics.EventLog.Messages.dll";

    private readonly FakeWindowsEventLog _eventLog = new();
    private readonly FakeMessageFileCheck _protectedLocation = new();

    private EventLogSourceInstaller Installer(IMessageFileLocationCheck? check = null) =>
        new(_eventLog, check ?? _protectedLocation, messageFile: MessageFile);

    [Fact]
    public void Install_FreshMachine_CreatesTheRestrictedLogBeforeTheSource_ThenClearsItOnce()
    {
        var outcome = Installer().Install();

        Assert.Equal(EventLogSourceInstallResult.Created, outcome.Result);
        Assert.Equal(["WriteLogSettings sap-AV", "WriteSource sap-AV@sap-AV", "ClearLog sap-AV"], _eventLog.Changes);
        Assert.Equal(EventLogSettings.Default, _eventLog.Logs["sap-AV"].Settings);
        Assert.Equal(MessageFile, _eventLog.ReadMessageFile("sap-AV", "sap-AV"));
        Assert.Equal([MessageFile], _protectedLocation.Checked);
    }

    [Fact]
    public void Install_Rerun_IsAlreadyRegistered_ReappliesTheSettings_WithoutClearing()
    {
        Installer().Install();
        _eventLog.Logs["sap-AV"].Settings = EventLogSettings.Default with { CustomSd = "O:BAG:SYD:(A;;0x3;;;IU)" }; // tampered
        _eventLog.Changes.Clear();

        var outcome = Installer().Install();

        Assert.Equal(EventLogSourceInstallResult.AlreadyRegistered, outcome.Result);
        Assert.Equal(["WriteLogSettings sap-AV", "WriteSource sap-AV@sap-AV"], _eventLog.Changes);
        Assert.Equal(EventLogSettings.Default, _eventLog.Logs["sap-AV"].Settings);
    }

    [Fact]
    public void Install_SourceInTheApplicationLog_IsMovedToTheDedicatedLog_DeletingTheOldOneFirst()
    {
        _eventLog.Register("sap-AV", "Application"); // B1's layout

        var outcome = Installer().Install();

        Assert.Equal(EventLogSourceInstallResult.Migrated, outcome.Result);
        Assert.Equal("DeleteSource sap-AV@Application", _eventLog.Changes[0]);
        Assert.Equal(["sap-AV"], _eventLog.FindLogsForSource("sap-AV"));
        Assert.Contains("ClearLog sap-AV", _eventLog.Changes);
        Assert.Equal(EventLogSourceInstallResult.AlreadyRegistered, Installer().Install().Result);
    }

    [Fact]
    public void Install_SourceInBothApplicationAndTheDedicatedLog_EndsUpOnlyInTheDedicatedLog()
    {
        _eventLog.Register("sap-AV", "Application");
        _eventLog.Register("sap-AV", "sap-AV");

        Assert.Equal(EventLogSourceInstallResult.Migrated, Installer().Install().Result);
        Assert.Equal(["sap-AV"], _eventLog.FindLogsForSource("sap-AV"));
        Assert.DoesNotContain("ClearLog sap-AV", _eventLog.Changes); // the log existed: its events are kept
    }

    [Theory]
    [InlineData("System")]
    [InlineData("Application", "System")]
    public void Install_SourceInAnotherLog_IsRefused_NothingChanges(params string[] logs)
    {
        foreach (var log in logs)
        {
            _eventLog.Register("sap-AV", log);
        }

        var outcome = Installer().Install();

        Assert.Equal(new EventLogInstallOutcome(EventLogSourceInstallResult.RegisteredInOtherLog, "System"), outcome);
        Assert.Empty(_eventLog.Changes);
        Assert.Equal(logs.Order(), _eventLog.FindLogsForSource("sap-AV"));
    }

    [Fact]
    public void Install_MessageFileNotAdminOnly_IsRefusedBeforeAnyChange_EvenTheMigration()
    {
        _eventLog.Register("sap-AV", "Application");
        var userWritable = new FakeMessageFileCheck("the message file's folder 'C:\\Users\\bob\\engine' can be changed by bob");

        var outcome = Installer(userWritable).Install();

        Assert.Equal(EventLogSourceInstallResult.MessageFileNotProtected, outcome.Result);
        Assert.Contains("bob", outcome.Detail);
        Assert.Empty(_eventLog.Changes);
        Assert.Equal(["Application"], _eventLog.FindLogsForSource("sap-AV"));
    }

    [Fact]
    public void Install_CustomSdReadBackDiffers_IsAnError()
    {
        _eventLog.ReadBack = written => written with { CustomSd = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;IU)" };

        Assert.Throws<InvalidOperationException>(() => Installer().Install());
    }

    [Fact]
    public void Uninstall_RemovesTheDedicatedLogAndALeftoverApplicationSource_ThenIsANoOp()
    {
        Installer().Install();
        _eventLog.Register("sap-AV", "Application");
        _eventLog.Changes.Clear();

        Assert.Equal(EventLogSourceUninstallResult.Removed, Installer().Uninstall().Result);
        Assert.Equal(["DeleteSource sap-AV@Application", "DeleteLog sap-AV"], _eventLog.Changes);
        Assert.Empty(_eventLog.FindLogsForSource("sap-AV"));
        Assert.False(_eventLog.LogExists("sap-AV"));

        Assert.Equal(EventLogSourceUninstallResult.NotRegistered, Installer().Uninstall().Result);
        Assert.Equal(2, _eventLog.Changes.Count);
    }

    [Fact]
    public void Uninstall_SourceInAnotherLog_IsRefused_NothingChanges()
    {
        _eventLog.Register("sap-AV", "System");

        Assert.Equal(new EventLogUninstallOutcome(EventLogSourceUninstallResult.RegisteredInOtherLog, "System"), Installer().Uninstall());
        Assert.Empty(_eventLog.Changes);
    }

    [Theory]
    [InlineData("Application")]
    [InlineData("security")]
    public void Installer_BuiltInLogName_IsRejected(string logName)
    {
        Assert.Throws<ArgumentException>(() => new EventLogSourceInstaller(_eventLog, _protectedLocation, logName: logName));
    }

    [Fact]
    public void DefaultMessageFile_IsThePassThroughDllNextToSystemDiagnosticsEventLog()
    {
        var path = EventLogSourceInstaller.DefaultMessageFile();

        Assert.Equal("System.Diagnostics.EventLog.Messages.dll", Path.GetFileName(path));
        Assert.True(File.Exists(path), path);
    }

    [Theory]
    [InlineData("")]
    [InlineData("--environment Development")]
    public void Commands_OtherArguments_StartTheEngineNormally(string commandLine)
    {
        var args = commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Null(EngineCommands.TryRun(args, _eventLog, TextWriter.Null, TextWriter.Null, _protectedLocation));
    }

    [Theory]
    [InlineData("--install-eventlog-source extra")]
    [InlineData("--INSTALL-EVENTLOG-SOURCE")]
    [InlineData("--environment Development --uninstall-eventlog-source")]
    public void Commands_KnownCommandWithExtrasOrOtherCase_IsAUsageError_NeverStartsTheEngine(string commandLine)
    {
        var error = new StringWriter();

        var exit = EngineCommands.TryRun(commandLine.Split(' '), _eventLog, TextWriter.Null, error, _protectedLocation);

        Assert.Equal(EngineCommands.ExitFailed, exit);
        Assert.Contains("Usage", error.ToString());
        Assert.Empty(_eventLog.Changes);
    }

    [Fact]
    public void Commands_MapOutcomesToExitCodes()
    {
        var error = new StringWriter();
        string[] install = [EngineCommands.InstallEventLogSource];
        string[] uninstall = [EngineCommands.UninstallEventLogSource];

        Assert.Equal(EngineCommands.ExitSuccess, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error, _protectedLocation));
        Assert.Equal(EngineCommands.ExitSuccess, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error, _protectedLocation));
        Assert.Equal(EngineCommands.ExitSuccess, EngineCommands.TryRun(uninstall, _eventLog, TextWriter.Null, error, _protectedLocation));

        Assert.Equal(EngineCommands.ExitUnprotectedMessageFile,
            EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error, new FakeMessageFileCheck("user-writable")));
        Assert.Contains("user-writable", error.ToString());

        _eventLog.Register("sap-AV", "System");
        Assert.Equal(EngineCommands.ExitConflict, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error, _protectedLocation));

        _eventLog.Unregister("sap-AV");
        _eventLog.Failure = new SecurityException("Requested registry access is not allowed.");
        Assert.Equal(EngineCommands.ExitNotElevated, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error, _protectedLocation));
        Assert.Contains("elevated", error.ToString());
    }
}
