using Microsoft.Win32;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>Service collection from the registry (ROADMAP C2) against a throwaway HKCU key.</summary>
public sealed class ServiceCollectorTests : IDisposable
{
    private readonly RegistryTestRoot _root = new();
    private readonly SetProbe _probe = new();

    public void Dispose() => _root.Dispose();

    private void Service(string name, int type, int start, string? imagePath, string? serviceDll = null)
    {
        using var key = _root.Machine($@"{ServiceSource.ServicesKey}\{name}");
        key.SetValue("Type", type, RegistryValueKind.DWord);
        key.SetValue("Start", start, RegistryValueKind.DWord);
        if (imagePath is not null)
        {
            key.SetValue("ImagePath", imagePath, RegistryValueKind.ExpandString);
        }

        if (serviceDll is not null)
        {
            _root.Machine($@"{ServiceSource.ServicesKey}\{name}\Parameters").SetValue("ServiceDll", serviceDll, RegistryValueKind.ExpandString);
        }
    }

    [Fact]
    public void OwnProcessService_ImagePath_WithUnquotedSpacesFlagged()
    {
        _probe.Add(@"C:\Program Files\Acme Agent\agent.exe");
        Service("AcmeAgent", 0x10, 2, @"C:\Program Files\Acme Agent\agent.exe -service");

        var entry = _root.Collect(_probe, new ServiceSource()).Single("ImagePath");

        Assert.Equal(PersistenceKind.Service, entry.Kind);
        Assert.Equal(@"HKLM\SYSTEM\CurrentControlSet\Services\AcmeAgent", entry.Location);
        Assert.Equal(@"C:\Program Files\Acme Agent\agent.exe", entry.Resolution.TargetPath);
        Assert.Contains(ResolutionFlag.UnquotedPathWithSpaces, entry.Resolution.Flags);
        Assert.Equal(ServiceStartType.Automatic, entry.ServiceStart);
        Assert.Equal("T1543.003", entry.TechniqueId);
    }

    [Fact]
    public void SvchostService_ReportsTheServiceDll_WithSvchostAsHost()
    {
        Service("Netsvc", 0x20, 2, @"%SystemRoot%\system32\svchost.exe -k netsvcs -p", @"%SystemRoot%\System32\netsvc.dll");

        var result = _root.Collect(_probe, new ServiceSource());

        var entry = Assert.Single(result.Entries);
        Assert.Equal("ServiceDll", entry.ValueName);
        Assert.Equal(@"HKLM\SYSTEM\CurrentControlSet\Services\Netsvc\Parameters", entry.Location);
        Assert.Equal(@"C:\Windows\System32\netsvc.dll", entry.Resolution.TargetPath);
        Assert.Equal(@"C:\Windows\system32\svchost.exe", entry.Resolution.HostPath);
        Assert.Contains(ResolutionFlag.InterpreterHost, entry.Resolution.Flags);
    }

    [Fact]
    public void ServiceDll_WithAForeignHost_ReportsBoth()
    {
        Service("Odd", 0x20, 3, @"C:\ProgramData\svchost.exe -k odd", @"C:\ProgramData\odd.dll");

        var result = _root.Collect(_probe, new ServiceSource());

        Assert.Equal(@"C:\ProgramData\svchost.exe", result.Single("ImagePath").Resolution.TargetPath);
        Assert.Equal(@"C:\ProgramData\odd.dll", result.Single("ServiceDll").Resolution.TargetPath);
    }

    [Fact]
    public void DisabledServices_AreReported_NotSkipped()
    {
        Service("Dormant", 0x10, 4, @"""C:\Tools\dormant.exe""");

        var entry = _root.Collect(_probe, new ServiceSource()).Single("ImagePath");

        Assert.False(entry.Enabled);
        Assert.Equal(ServiceStartType.Disabled, entry.ServiceStart);
    }

    [Fact]
    public void Drivers_FollowTheKernelPathRules_AndNonServiceKeysAreSkipped()
    {
        Service("rooted", 1, 3, @"\SystemRoot\System32\drivers\rooted.sys");
        Service("relative", 1, 0, @"System32\drivers\relative.sys");
        Service("ntpath", 2, 3, @"\??\C:\Drivers\ntpath.sys");
        Service("implicit", 1, 3, null);
        _root.Machine($@"{ServiceSource.ServicesKey}\EventLog\Config").SetValue("Something", "x");

        var targets = _root.Collect(_probe, new ServiceSource()).Entries.ToDictionary(
            e => e.Location[(e.Location.LastIndexOf('\\') + 1)..], e => e.Resolution.TargetPath);

        Assert.Equal(@"C:\Windows\System32\drivers\rooted.sys", targets["rooted"]);
        Assert.Equal(@"C:\Windows\System32\drivers\relative.sys", targets["relative"]);
        Assert.Equal(@"C:\Drivers\ntpath.sys", targets["ntpath"]);
        Assert.Equal(@"C:\Windows\System32\drivers\implicit.sys", targets["implicit"]);
        Assert.Equal(4, targets.Count);
    }
}
