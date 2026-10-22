using System.Security;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.EventLogging;

public sealed class EventLogSourceInstallerTests
{
    private readonly FakeWindowsEventLog _eventLog = new();

    [Fact]
    public void Install_IsIdempotent_CreatesOnlyWhenMissing()
    {
        var installer = new EventLogSourceInstaller(_eventLog);

        Assert.Equal(EventLogSourceInstallResult.Created, installer.Install(out var first));
        Assert.Equal(EventLogSourceInstallResult.AlreadyRegistered, installer.Install(out var second));

        Assert.Equal(1, _eventLog.CreateCalls);
        Assert.Equal(("Application", "Application"), (first, second));
        Assert.Equal("Application", _eventLog.Sources["sap-AV"]);
    }

    [Fact]
    public void InstallAndUninstall_RefuseASourceBoundToAnotherLog()
    {
        _eventLog.Sources["sap-AV"] = "System";
        var installer = new EventLogSourceInstaller(_eventLog);

        Assert.Equal(EventLogSourceInstallResult.RegisteredInOtherLog, installer.Install(out var log));
        Assert.Equal(EventLogSourceUninstallResult.RegisteredInOtherLog, installer.Uninstall(out _));

        Assert.Equal("System", log);
        Assert.Equal((0, 0), (_eventLog.CreateCalls, _eventLog.DeleteCalls));
        Assert.Equal("System", _eventLog.Sources["sap-AV"]);
    }

    [Fact]
    public void Uninstall_RemovesOurSource_ThenIsANoOp()
    {
        _eventLog.Sources["sap-AV"] = "application"; // registry names are case-insensitive
        var installer = new EventLogSourceInstaller(_eventLog);

        Assert.Equal(EventLogSourceUninstallResult.Removed, installer.Uninstall(out _));
        Assert.Equal(EventLogSourceUninstallResult.NotRegistered, installer.Uninstall(out _));
        Assert.Equal(1, _eventLog.DeleteCalls);
    }

    [Fact]
    public void Install_ConcurrentInstallerWinsTheRace_IsAlreadyRegistered_NotAnError()
    {
        _eventLog.BeforeCreate = source => _eventLog.Sources[source] = "Application";
        var installer = new EventLogSourceInstaller(_eventLog);

        Assert.Equal(EventLogSourceInstallResult.AlreadyRegistered, installer.Install(out var log));
        Assert.Equal("Application", log);

        _eventLog.Sources.Clear();
        _eventLog.BeforeCreate = source => _eventLog.Sources[source] = "System";
        Assert.Equal(EventLogSourceInstallResult.RegisteredInOtherLog, installer.Install(out log));
        Assert.Equal("System", log);
    }

    [Theory]
    [InlineData("")]
    [InlineData("--environment Development")]
    public void Commands_OtherArguments_StartTheEngineNormally(string commandLine)
    {
        var args = commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.Null(EngineCommands.TryRun(args, _eventLog, TextWriter.Null, TextWriter.Null));
    }

    [Theory]
    [InlineData("--install-eventlog-source extra")]
    [InlineData("--INSTALL-EVENTLOG-SOURCE")]
    [InlineData("--environment Development --uninstall-eventlog-source")]
    public void Commands_KnownCommandWithExtrasOrOtherCase_IsAUsageError_NeverStartsTheEngine(string commandLine)
    {
        var error = new StringWriter();

        var exit = EngineCommands.TryRun(commandLine.Split(' '), _eventLog, TextWriter.Null, error);

        Assert.Equal(EngineCommands.ExitFailed, exit);
        Assert.Contains("Usage", error.ToString());
        Assert.Equal((0, 0), (_eventLog.CreateCalls, _eventLog.DeleteCalls));
    }

    [Fact]
    public void Commands_MapOutcomesToExitCodes()
    {
        var error = new StringWriter();
        string[] install = [EngineCommands.InstallEventLogSource];

        Assert.Equal(EngineCommands.ExitSuccess, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error));
        Assert.Equal(EngineCommands.ExitSuccess, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error));

        _eventLog.Sources["sap-AV"] = "System";
        Assert.Equal(EngineCommands.ExitConflict, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error));

        _eventLog.Sources.Clear();
        _eventLog.Failure = new SecurityException("Requested registry access is not allowed.");
        Assert.Equal(EngineCommands.ExitNotElevated, EngineCommands.TryRun(install, _eventLog, TextWriter.Null, error));
        Assert.Contains("elevated", error.ToString());
    }
}
