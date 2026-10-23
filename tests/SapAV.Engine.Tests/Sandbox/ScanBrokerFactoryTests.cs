using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>Review L1: the in-process mode is a console/debug tool only and is refused when running as a service.</summary>
public sealed class ScanBrokerFactoryTests : IDisposable
{
    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"))).FullName;

    public void Dispose() => TempDir.DeleteTree(_dir);

    [Fact]
    public async Task InProcess_AsAService_IsRefused_AndFilesAreNotScanned()
    {
        var broker = ScanBrokerFactory.Create(new SandboxOptions { Mode = SandboxMode.InProcess }, new FakeRulesSource(),
            NullLogger.Instance, TimeProvider.System, online: null, runningAsService: true);
        var path = Path.Combine(_dir, "f.txt");
        File.WriteAllText(path, "content");

        var report = await broker.ScanAsync(new ScanItem(path, ScanTrigger.RealTime));

        Assert.IsType<UnavailableScanBroker>(broker);
        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Null(report.Result.Verdict);
        Assert.NotNull(report.Identity);
        Assert.Contains("refused", broker.Status.LastError, StringComparison.Ordinal);
    }

    [Fact]
    public void InProcess_InAConsoleRun_IsAllowed_AndAppContainerIsTheDefault()
    {
        var inProcess = ScanBrokerFactory.Create(new SandboxOptions { Mode = SandboxMode.InProcess }, new FakeRulesSource(),
            NullLogger.Instance, TimeProvider.System, online: null, runningAsService: false);
        using var sandboxed = (SandboxedScanBroker)ScanBrokerFactory.Create(new SandboxOptions(), new FakeRulesSource(),
            NullLogger.Instance, TimeProvider.System, online: null, runningAsService: true);

        Assert.IsType<InProcessScanBroker>(inProcess);
        Assert.Equal(SandboxMode.AppContainer, sandboxed.Status.Mode);
        ((IDisposable)inProcess).Dispose();
    }
}
