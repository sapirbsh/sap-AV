using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.BrowserHijack;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.BrowserHijack;

/// <summary>
/// E6 / B5: the hosts file is parsed only in the scan worker. These go through the real broker and the real worker exe
/// (test-only unsandboxed isolation: same pipes, Job Object and protocol), on temp hosts files the engine opens with the hardened open.
/// </summary>
public sealed partial class HostsParsingInWorkerTests : IDisposable
{
    private readonly RegistryTestRoot _root = new();
    private readonly TempDir _dir = new();
    private readonly List<SandboxedScanBroker> _brokers = [];

    public void Dispose()
    {
        foreach (var broker in _brokers)
        {
            broker.Dispose();
        }

        _root.Dispose();
        _dir.Dispose();
    }

    private SandboxedScanBroker Broker(Func<string, WorkerTestFault>? faults = null, string? workerPath = null)
    {
        var broker = new SandboxedScanBroker(new SandboxOptions
        {
            WorkerPath = workerPath ?? TestAppContainer.WorkerExe,
            WorkerCount = 1,
            EnableWorkerTestHooks = true,
            Isolation = WorkerIsolation.UnsandboxedForTests,
            RequestTimeout = TimeSpan.FromSeconds(30),
            ParseTimeout = TimeSpan.FromSeconds(30),
            RestartBackoffInitial = TimeSpan.FromMilliseconds(1),
            RestartBackoffMax = TimeSpan.FromMilliseconds(10),
        }, new FakeRulesSource(), NullLogger.Instance) { ParseFaultInjector = faults };
        _brokers.Add(broker);
        return broker;
    }

    /// <summary>The collector with the real hardened opener pointed at <paramref name="hostsPath"/> instead of the system hosts file.</summary>
    private RegistryBrowserHijackSource Source(IPersistenceFileParser parser, string hostsPath) =>
        new(_root.View, new RedirectedOpener(hostsPath), parser, BrowserHijackCollectorTests.SystemDirectory, () => false, null,
            TimeProvider.System, NullLogger.Instance);

    private string WriteHosts(string text)
    {
        var path = Path.Combine(_dir.Path, "hosts");
        File.WriteAllBytes(path, Encoding.UTF8.GetBytes(text));
        return path;
    }

    [Fact]
    public async Task RoundTrip_ThroughTheWorker_OverOneMegabyte_KeepsSecurityDomainsFromTheMiddle()
    {
        var path = Path.Combine(_dir.Path, "hosts");
        var pad = Encoding.ASCII.GetBytes("0.0.0.0 pad.example\n");
        using (var file = File.Create(path))
        {
            file.Write(Encoding.ASCII.GetBytes("# synthetic\n::1 localhost\n"));
            for (int i = 0; i < 30_000; i++)
            {
                file.Write(pad);
            }

            file.Write(Encoding.ASCII.GetBytes("10.6.6.6 www.virustotal.com virustotal.com\n"));
            while (file.Length <= HostsFileSnapshot.MaxBytes)
            {
                file.Write(pad);
            }
        }

        var broker = Broker();
        var hosts = (await Source(broker, path).GetSnapshotAsync()).Hosts;

        Assert.Equal(HijackReadState.Available, hosts.Read);
        Assert.True(hosts.ContentTruncated);
        var content = hosts.Content!;
        Assert.True(content.InputTruncated && content.EntriesTruncated);
        Assert.Equal(HostsAddressFamily.IPv6, content.Entries[0].Family);
        Assert.True(content.Entries[0].IsBlocking);
        var kept = Assert.Single(content.Entries, e => e.Names.Contains("www.virustotal.com"));
        Assert.False(kept.IsBlocking); // recomputed engine-side from the address
        Assert.Equal(BrowserHijackCollectorTests.OwnerOf(path), hosts.OwnerSid); // metadata from the engine's own handle
        Assert.True(broker.Status.WorkersRunning >= 1); // it really went through a worker
    }

    [Fact]
    public async Task AWorkerThatCantStart_IsParserUnavailable_NeverParsedInProcess()
    {
        var broker = Broker(workerPath: Path.Combine(_dir.Path, "no-such-worker.exe"));

        var hosts = (await Source(broker, WriteHosts("127.0.0.1 localhost\n")).GetSnapshotAsync()).Hosts;

        Assert.Equal(HijackReadState.ParserUnavailable, hosts.Read);
        Assert.Null(hosts.Content);
        Assert.NotNull(hosts.Length);
    }

    [Theory]
    [InlineData(nameof(WorkerTestFault.MalformedResponse))]
    [InlineData(nameof(WorkerTestFault.WrongSchemaResponse))]
    public async Task ABrokenWorkerAnswer_IsRejected_AndTheHostsPartIsUnknown(string fault)
    {
        var broker = Broker(_ => Enum.Parse<WorkerTestFault>(fault));

        var hosts = (await Source(broker, WriteHosts("127.0.0.1 localhost\n")).GetSnapshotAsync()).Hosts;

        Assert.Equal(HijackReadState.Failed, hosts.Read);
        Assert.Null(hosts.Content);
        Assert.Equal(1, broker.Status.WorkerRestarts); // a worker that broke the protocol is replaced
    }

    [Fact]
    public async Task AHostsFile_IsAlwaysAloneInItsRequest()
    {
        // Review L3: a hosts file has its own answer cap, so the broker refuses to batch it with anything.
        var path = WriteHosts("127.0.0.1 a\n");
        using var first = File.OpenHandle(path);
        using var second = File.OpenHandle(path);
        var broker = Broker();

        await Assert.ThrowsAsync<ArgumentException>(() => broker.ParseBatchAsync(
            [new PersistenceParseInput(first, WorkerParseKind.HostsFile, "a"), new PersistenceParseInput(second, WorkerParseKind.ScheduledTask, "b")],
            null, CancellationToken.None));
    }

    [RequiresFact(Requires.RealHostsFile)]
    public async Task RealMachine_HostsAndCurrentUserProxy_AreReadable_ReadOnly()
    {
        // The real registry and hosts file, read-only; parsing still goes through the worker.
        var source = new RegistryBrowserHijackSource(Broker(), TimeProvider.System, NullLogger<RegistryBrowserHijackSource>.Instance);

        var snapshot = await source.GetSnapshotAsync();

        Assert.Equal(Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts"), snapshot.Hosts.Path, ignoreCase: true);
        Assert.Equal(HijackReadState.Available, snapshot.Hosts.Read);
        Assert.NotNull(snapshot.Hosts.Content);
        var me = snapshot.Users.Single(u => u.Sid == WindowsIdentity.GetCurrent().User!.Value);
        Assert.Equal(HijackReadState.Available, me.Settings.Read);
    }

    [Fact]
    public void BrowserHijackSources_NeverWrite()
    {
        // Guard (E6): the collector only reads the registry and the hosts file. Comment lines are ignored.
        Assert.Matches(WriteApi(), "key.SetValue(\"ProxyServer\", x);");
        Assert.Matches(WriteApi(), "Registry.LocalMachine.OpenSubKey(p, writable: true)");
        var root = FindRepoRoot();
        var files = new[] { Path.Combine(root, "src", "SapAV.Engine", "BrowserHijack"), Path.Combine(root, "src", "SapAV.Core", "BrowserHijack") }
            .SelectMany(d => Directory.EnumerateFiles(d, "*.cs")).ToArray();
        Assert.True(files.Length >= 5, $"only {files.Length} files found");

        var hits = files.SelectMany(f => File.ReadAllLines(f).Select((line, i) => (f, i, line: line.TrimStart())))
            .Where(x => !x.line.StartsWith("//", StringComparison.Ordinal) && WriteApi().IsMatch(x.line))
            .Select(x => $"{Path.GetFileName(x.f)}:{x.i + 1}: {x.line}")
            .ToArray();

        Assert.Empty(hits);
    }

    [GeneratedRegex(@"\.SetValue\s*\(|\bCreateSubKey\b|\bDeleteValue\b|\bDeleteSubKey|writable:\s*true|\bGenericWrite\b|\bFileWrite|File\.(Write|Append|Create|Delete|Move|Copy|Replace|Open\()|RandomAccess\.Write|\bSetAccessControl\b|\bRegLoadKey\b")]
    private static partial Regex WriteApi();

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SapAV.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("SapAV.sln not found above the test output folder.");
    }

    private sealed class RedirectedOpener(string path) : IHostsFileOpener
    {
        public HostsFileOpen Open(string ignored) => new SafeHostsFileOpener().Open(path);
    }
}
