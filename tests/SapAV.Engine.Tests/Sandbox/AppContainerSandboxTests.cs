using System.Net;
using System.Net.Sockets;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Sandbox.Native;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>One throwaway AppContainer profile (and folder grant) for the whole class; removed afterwards.</summary>
public sealed class AppContainerFixture : IDisposable
{
    private readonly Lazy<TestAppContainer> _container = new(() => new TestAppContainer("Sandbox"));

    internal TestAppContainer Container => _container.Value;

    public void Dispose()
    {
        if (_container.IsValueCreated)
        {
            _container.Value.Dispose();
        }
    }
}

/// <summary>
/// B5 sandbox boundaries, checked against the real worker in a real AppContainer: token, Job limits, mitigations, no
/// network, no access to user files by path, and read-only brokered handles. Every worker is killed in cleanup.
/// </summary>
public sealed class AppContainerSandboxTests(AppContainerFixture fixture) : IClassFixture<AppContainerFixture>, IDisposable
{
    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"))).FullName;

    public void Dispose() => TempDir.DeleteTree(_dir);

    private async Task<WorkerProcess> StartAsync()
    {
        var worker = fixture.Container.Start();
        try
        {
            var loaded = await WorkerTestClient.LoadRulesAsync(worker, "rule M { strings: $a = \"sapav-b5\" condition: $a }");
            Assert.Equal(WorkerResponseKind.RulesLoaded, loaded.Kind);
            return worker;
        }
        catch
        {
            worker.Dispose();
            throw;
        }
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task WorkerToken_IsTheAppContainer_WithNoCapabilities_AtLowIntegrity()
    {
        using var worker = await StartAsync();
        var token = worker.QueryToken();

        Assert.True(token.IsAppContainer);
        Assert.Equal(fixture.Container.Sid.Value, token.AppContainerSid);
        Assert.Equal(0, token.CapabilityCount); // no internetClient, no privateNetworkClientServer, nothing
        Assert.True(token.IntegrityRid <= SandboxTokenInfo.LowIntegrityRid, $"integrity 0x{token.IntegrityRid:X}");
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task ProcessAndThreadDacl_GrantNoContainerUserOrWorldSid_AndTheUserCantOpenTheWorker()
    {
        using var worker = await StartAsync();
        using var self = System.Security.Principal.WindowsIdentity.GetCurrent();
        var forbidden = new[] { fixture.Container.Sid.Value, "S-1-15-2-1", "S-1-15-2-2", self.User!.Value, "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4" };

        foreach (var (what, handle) in new (string, System.Runtime.InteropServices.SafeHandle)[] { ("process", worker.Process), ("thread", worker.InitialThread!) })
        {
            var sd = WorkerObjectSecurity.Read(handle);
            Assert.True((sd.ControlFlags & System.Security.AccessControl.ControlFlags.DiscretionaryAclProtected) != 0, $"{what} DACL inherits");
            var sids = sd.DiscretionaryAcl!.Cast<System.Security.AccessControl.KnownAce>().Select(a => a.SecurityIdentifier.Value).ToArray();
            Assert.Contains("S-1-5-18", sids);
            Assert.All(sids, sid =>
            {
                Assert.DoesNotContain(sid, forbidden);
                Assert.False(sid.StartsWith("S-1-15-", StringComparison.Ordinal), $"{what} DACL grants package SID {sid}");
                Assert.False(sid.StartsWith("S-1-5-5-", StringComparison.Ordinal), $"{what} DACL grants logon SID {sid}");
            });
        }

        if (!new System.Security.Principal.WindowsPrincipal(self).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        {
            // Same account as the broker here, yet it can't open the worker by PID (to read memory or steal handles).
            using var byPid = System.Diagnostics.Process.GetProcessById(worker.ProcessId);
            Assert.Throws<System.ComponentModel.Win32Exception>(() => byPid.Handle);
        }
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task JobLimits_AndMitigations_AreApplied_AndTheWorkerCantStartAChild()
    {
        using var worker = await StartAsync();

        var (flags, processLimit, memory) = worker.QueryJobLimits();
        Assert.Equal(SandboxNative.JobObjectLimitKillOnJobClose, flags & SandboxNative.JobObjectLimitKillOnJobClose);
        Assert.Equal(SandboxNative.JobObjectLimitDieOnUnhandledException, flags & SandboxNative.JobObjectLimitDieOnUnhandledException);
        Assert.Equal(1u, processLimit);
        Assert.Equal(1024UL * 1024 * 1024, memory);
        Assert.NotEqual(0u, worker.QueryMitigationFlags(SandboxNative.ProcessStrictHandleCheckPolicy) & 1);
        Assert.NotEqual(0u, worker.QueryMitigationFlags(SandboxNative.ProcessExtensionPointDisablePolicy) & 1);
        Assert.NotEqual(0u, worker.QueryMitigationFlags(SandboxNative.ProcessChildProcessPolicy) & 1);

        var spawn = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.SpawnProcess);
        Assert.False(spawn.Probe!.Succeeded, spawn.Probe.Detail);
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task NoNetwork_LoopbackConnectFails()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var worker = await StartAsync();

        var probe = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.ConnectTcp, port: port);

        Assert.False(probe.Probe!.Succeeded, probe.Probe.Detail);
        Assert.False(listener.Pending());
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task UserFiles_CantBeOpenedOrCreatedByPath()
    {
        var file = Path.Combine(_dir, "secret.txt");
        File.WriteAllText(file, "user data");
        using var worker = await StartAsync();

        var open = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.OpenPath, path: file);
        var create = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.CreateFileIn, path: _dir);

        Assert.False(open.Probe!.Succeeded, open.Probe.Detail);
        Assert.Contains("denied", open.Probe.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.False(create.Probe!.Succeeded, create.Probe.Detail);
        Assert.Single(Directory.GetFiles(_dir));
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task BrokeredHandle_IsReadOnly_EvenWhenTheEnginesHandleCanWriteAndDelete()
    {
        var file = Path.Combine(_dir, "target.bin");
        File.WriteAllText(file, "original");
        using var worker = await StartAsync();

        // The engine's own handle has write + delete; the copy in the worker must have neither.
        var full = File.OpenHandle(file, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, FileOptions.None);
        IntPtr remote = worker.DuplicateInto(full, WorkerProcess.ReadOnlyFileAccess);
        try
        {
            var write = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.WriteHandle, handle: remote);
            var delete = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.DeleteViaHandle, handle: remote);

            Assert.False(write.Probe!.Succeeded, write.Probe.Detail);
            Assert.Equal(5, write.Probe.Win32Error); // ERROR_ACCESS_DENIED
            Assert.False(delete.Probe!.Succeeded, delete.Probe.Detail);
            Assert.Equal(5, delete.Probe.Win32Error);
        }
        finally
        {
            worker.CloseInWorker(remote);
            full.Dispose();
        }

        Assert.Equal("original", File.ReadAllText(file));
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task WithoutTestHooks_FaultsAndProbesAreRefused()
    {
        using var worker = fixture.Container.Start(testHooks: false);
        Assert.Equal(WorkerResponseKind.RulesLoaded, (await WorkerTestClient.LoadRulesAsync(worker)).Kind);
        var file = Path.Combine(_dir, "f.bin");
        File.WriteAllText(file, "x");

        var probe = await WorkerTestClient.ProbeAsync(worker, WorkerProbeKind.OpenPath, path: file);
        var crash = await WorkerTestClient.ScanAsync(worker, file, WorkerTestFault.Crash);

        Assert.Equal(WorkerResponseKind.Failed, probe.Kind);
        Assert.Equal(WorkerResponseKind.Failed, crash.Kind);
        Assert.False(worker.HasExited);
    }

    [Fact]
    public void WorkerEnvironment_IsMinimal_NothingInheritedFromTheEngine()
    {
        Environment.SetEnvironmentVariable("DOTNET_SAPAV_INHERITANCE_MARKER", "planted");
        try
        {
            var block = WorkerProcess.BuildEnvironment(testHooks: false);
            Assert.DoesNotContain("DOTNET_SAPAV_INHERITANCE_MARKER", block, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(WorkerProcess.TestHooksVariable, block, StringComparison.Ordinal);
            Assert.Contains("DOTNET_EnableDiagnostics=0", block, StringComparison.Ordinal);
            Assert.Contains(WorkerProcess.TestHooksVariable + "=1", WorkerProcess.BuildEnvironment(testHooks: true), StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("DOTNET_SAPAV_INHERITANCE_MARKER", null);
        }
    }
}
