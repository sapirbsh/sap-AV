using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.BrowserHijack;
using SapAV.Engine.Persistence;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.BrowserHijack;

/// <summary>
/// E6: the read-only browser-hijack collector over a throwaway test registry root (never the real HKLM / HKU), a fake hosts
/// opener and an in-test stand-in for the worker; the real hardened opener over temp files. The real worker path is in
/// <see cref="HostsParsingInWorkerTests"/>.
/// </summary>
public sealed class BrowserHijackCollectorTests : IDisposable
{
    private const string SidA = "S-1-5-21-1000-2000-3000-1001";
    private const string SidB = "S-1-5-21-1000-2000-3000-1002";
    private const string SidUnloaded = "S-1-5-21-1000-2000-3000-1003";
    internal const string SystemDirectory = @"C:\Windows\System32";

    private readonly RegistryTestRoot _root = new();
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        _root.Dispose();
        _dir.Dispose();
    }

    private RegistryBrowserHijackSource Source(IHostsFileOpener? hosts = null, IRegistryView? registry = null, IPersistenceFileParser? parser = null) =>
        new(registry ?? _root.View, hosts ?? new FakeHostsOpener(() => HostsFileOpen.Failed(HijackReadState.NotFound, null)),
            parser ?? InTestHostsParser.Instance, SystemDirectory, () => false, null, TimeProvider.System, NullLogger.Instance);

    private RegistryKey UserSettings(string sid) => _root.Users($@"{sid}\{RegistryBrowserHijackSource.InternetSettingsPath}");

    /// <summary>An opener that opens a temp file with this content, as the real one would open the hosts file.</summary>
    private FakeHostsOpener HostsWith(string content, string owner = "S-1-5-18")
    {
        var path = Path.Combine(_dir.Path, Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(path, Encoding.UTF8.GetBytes(content));
        return new FakeHostsOpener(() =>
        {
            var handle = File.OpenHandle(path);
            return HostsFileOpen.Opened(handle, RandomAccess.GetLength(handle), DateTimeOffset.UnixEpoch, owner);
        });
    }

    /// <summary>A synthetic connection-settings blob: version, counter, flags, then length-prefixed ANSI strings.</summary>
    private static byte[] Blob(uint version, uint flags, params string[] strings)
    {
        var bytes = new List<byte>();
        bytes.AddRange(BitConverter.GetBytes(version));
        bytes.AddRange(BitConverter.GetBytes(1u));
        bytes.AddRange(BitConverter.GetBytes(flags));
        foreach (var s in strings)
        {
            bytes.AddRange(BitConverter.GetBytes((uint)s.Length));
            bytes.AddRange(Encoding.Latin1.GetBytes(s));
        }

        return bytes.ToArray();
    }

    [Fact]
    public async Task PerUserProxies_AcrossLoadedAndUnloadedProfiles()
    {
        _root.AddUser(SidA, @"C:\Users\a", loaded: true);
        _root.AddUser(SidB, @"C:\Users\b", loaded: true);
        _root.AddUser(SidUnloaded, @"C:\Users\c", loaded: false);
        using (var a = UserSettings(SidA))
        {
            a.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            a.SetValue("ProxyServer", "127.0.0.1:8877");
            a.SetValue("ProxyOverride", "<local>");
        }

        using (var b = UserSettings(SidB))
        {
            b.SetValue("AutoConfigURL", "file://C:/Users/b/AppData/Local/Temp/p.pac");
            b.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        }

        var snapshot = await Source().GetSnapshotAsync();

        Assert.Equal(HijackReadState.Available, snapshot.UsersRead);
        Assert.False(snapshot.UsersTruncated);
        var a1 = snapshot.Users.Single(u => u.Sid == SidA);
        Assert.Equal("127.0.0.1:8877", a1.Settings.ProxyServer);
        Assert.Equal("<local>", a1.Settings.ProxyOverride);
        Assert.True(a1.Settings.ConfiguresProxy);
        Assert.False(a1.Policy.KeyExists);
        var b1 = snapshot.Users.Single(u => u.Sid == SidB);
        Assert.Equal("file://C:/Users/b/AppData/Local/Temp/p.pac", b1.Settings.AutoConfigUrl);
        Assert.True(b1.Settings.ConfiguresProxy);

        var unloaded = snapshot.Users.Single(u => u.Sid == SidUnloaded);
        Assert.False(unloaded.HiveLoaded);
        Assert.Equal(HijackReadState.NotLoaded, unloaded.Settings.Read);
        Assert.Null(unloaded.Settings.ConfiguresProxy); // unknown, never "no proxy"
    }

    [Fact]
    public async Task AHiveThatGoesAwayDuringCollection_IsNotLoaded_NeverNoProxy()
    {
        // Review M3: listed as loaded, then logged off before its keys are read.
        _root.AddUser(SidA, @"C:\Users\a", loaded: true);

        var snapshot = await Source(registry: new VanishingHive(_root.View, SidA)).GetSnapshotAsync();

        var a = snapshot.Users.Single(u => u.Sid == SidA);
        Assert.False(a.HiveLoaded);
        Assert.Equal(HijackReadState.NotLoaded, a.Settings.Read);
        Assert.Null(a.Settings.ConfiguresProxy);
    }

    [Fact]
    public async Task AnOversizedValue_IsNotRead_AndIsUnknown()
    {
        _root.AddUser(SidA, @"C:\Users\a", loaded: true);
        using (var a = UserSettings(SidA))
        {
            a.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            a.SetValue("ProxyServer", new string('x', ProxySettings.MaxStoredBytes)); // UTF-16: twice the byte cap
        }

        using (var connections = _root.Machine($@"{RegistryBrowserHijackSource.InternetSettingsPath}\Connections"))
        {
            connections.SetValue("WinHttpSettings", new byte[ProxySettings.MaxStoredBytes + 1], RegistryValueKind.Binary);
        }

        var snapshot = await Source().GetSnapshotAsync();

        var settings = snapshot.Users.Single(u => u.Sid == SidA).Settings;
        Assert.Null(settings.ProxyServer);
        Assert.Contains("ProxyServer", settings.UnreadableValues);
        Assert.True(settings.Truncated);
        Assert.Null(settings.ConfiguresProxy);
        Assert.True(snapshot.WinHttp.TooLarge);
        Assert.Null(snapshot.WinHttp.ConfiguresProxy);
    }

    [Fact]
    public async Task ServiceAccounts_AreReadWhenLoaded_AndUnknownWhenNot()
    {
        using (var system = _root.Users($@"S-1-5-18\{RegistryBrowserHijackSource.InternetSettingsPath}\Connections"))
        {
            system.SetValue("DefaultConnectionSettings", Blob(0x46, 0x3, "10.6.6.6:80", "", ""), RegistryValueKind.Binary);
        }

        var snapshot = await Source().GetSnapshotAsync();

        var system18 = snapshot.Users.Single(u => u.Sid == "S-1-5-18");
        Assert.True(system18.IsServiceAccount);
        Assert.True(system18.Settings.DefaultConnection!.ProxyEnabled);
        Assert.Equal("10.6.6.6:80", system18.Settings.DefaultConnection.ProxyServer);
        Assert.True(system18.Settings.ConfiguresProxy); // the blob enables it even with no ProxyEnable value
        Assert.Equal(HijackReadState.NotLoaded, snapshot.Users.Single(u => u.Sid == "S-1-5-19").Settings.Read);
    }

    [Fact]
    public async Task MachineAndPolicySettings_AndUnreadableValueTypes()
    {
        using (var machine = _root.Machine(RegistryBrowserHijackSource.InternetSettingsPath))
        {
            machine.SetValue("ProxyServer", new byte[] { 1, 2, 3 }, RegistryValueKind.Binary); // wrong type
            machine.SetValue("ProxyEnable", "garbage");
        }

        using (var policy = _root.Machine(RegistryBrowserHijackSource.PolicyInternetSettingsPath))
        {
            policy.SetValue("ProxySettingsPerUser", 0, RegistryValueKind.DWord);
            policy.SetValue("AutoConfigURL", "http://pac.evil.example/x.pac" + new string('a', 5000));
        }

        var snapshot = await Source().GetSnapshotAsync();

        Assert.Equal(new[] { "ProxyEnable", "ProxyServer" }, snapshot.MachineSettings.UnreadableValues.Order());
        Assert.Null(snapshot.MachineSettings.ConfiguresProxy); // a value exists but can't be read: unknown
        Assert.True(snapshot.ProxyIsMachineWide);
        Assert.True(snapshot.MachinePolicy.Truncated);
        Assert.Equal(ProxySettings.MaxValueLength, snapshot.MachinePolicy.AutoConfigUrl!.Length);
    }

    [Fact]
    public async Task WinHttp_NotSet_IsDirect_Set_IsParsed_WrongType_IsUnknown()
    {
        Assert.False((await Source().GetSnapshotAsync()).WinHttp.ConfiguresProxy);

        using var connections = _root.Machine($@"{RegistryBrowserHijackSource.InternetSettingsPath}\Connections");
        connections.SetValue("WinHttpSettings", Blob(0x28, 3, "10.6.6.6:3128", "<local>"), RegistryValueKind.Binary);
        var parsed = (await Source().GetSnapshotAsync()).WinHttp;
        Assert.True(parsed.ConfiguresProxy);
        Assert.Equal("10.6.6.6:3128", parsed.Settings!.ProxyServer);

        connections.SetValue("WinHttpSettings", "not binary");
        var wrong = (await Source().GetSnapshotAsync()).WinHttp;
        Assert.True(wrong.UnexpectedType);
        Assert.Null(wrong.ConfiguresProxy);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData(@"%SystemRoot%\System32\drivers\etc", false)]
    [InlineData(@"C:\Windows\System32\drivers\etc\", false)]
    [InlineData(@"C:\ProgramData\x\etc", true)]
    [InlineData(@"%SystemRoot%\Temp", true)]
    public async Task DataBasePath_RedirectIsReported(string? value, bool redirected)
    {
        if (value is not null)
        {
            using var key = _root.Machine(RegistryBrowserHijackSource.TcpipParametersPath);
            key.SetValue("DataBasePath", value, RegistryValueKind.ExpandString);
        }

        var hosts = (await Source().GetSnapshotAsync()).Hosts;

        Assert.Equal(HijackReadState.Available, hosts.DataBasePathRead);
        Assert.Equal(value, hosts.DataBasePath);
        Assert.Equal(redirected, hosts.DataBasePathRedirected);
        Assert.Equal(@"C:\Windows\System32\drivers\etc\hosts", hosts.Path); // never taken from DataBasePath
    }

    [Fact]
    public async Task Hosts_HandleGoesToTheParser_WithTheDefaultFilter_AndMetadataStaysEngineSide()
    {
        var opener = HostsWith("127.0.0.1 localhost\n10.6.6.6 www.eset.com\n", owner: "S-1-5-21-1-2-3-1001");
        var parser = new RecordingParser(InTestHostsParser.Instance);

        var hosts = (await Source(opener, parser: parser).GetSnapshotAsync()).Hosts;

        Assert.Equal(@"C:\Windows\System32\drivers\etc\hosts", opener.LastPath);
        var input = Assert.Single(parser.Inputs);
        Assert.Equal(WorkerParseKind.HostsFile, input.Kind);
        Assert.Same(HostsNameFilter.DefaultSecurityDomains, input.KeepNames);
        Assert.Equal(HijackReadState.Available, hosts.Read);
        Assert.Equal(2, hosts.Content!.TotalEntries);
        Assert.False(hosts.Content.Entries[1].IsBlocking);
        Assert.False(hosts.OwnerIsTrusted); // a user owns the hosts file: a signal
        Assert.Equal(DateTimeOffset.UnixEpoch, hosts.LastWriteTime);
        Assert.True(opener.LastOpen!.Handle!.IsClosed); // the collector closes the handle after the parse
    }

    [Fact]
    public async Task Hosts_WithoutAWorker_IsParserUnavailable_NeverParsedHere()
    {
        var hosts = (await Source(HostsWith("127.0.0.1 localhost\n"), parser: UnavailablePersistenceParser.NoSandbox).GetSnapshotAsync()).Hosts;

        Assert.Equal(HijackReadState.ParserUnavailable, hosts.Read);
        Assert.Null(hosts.Content);
        Assert.NotNull(hosts.Length); // metadata is still known
        Assert.Equal("S-1-5-18", hosts.OwnerSid);
    }

    [Theory]
    [InlineData(HijackReadState.AccessDenied)]
    [InlineData(HijackReadState.Redirected)]
    [InlineData(HijackReadState.Locked)]
    public async Task Hosts_UnreadStates_LeaveContentUnknown(HijackReadState state)
    {
        var parser = new RecordingParser(InTestHostsParser.Instance);
        var hosts = (await Source(new FakeHostsOpener(() => HostsFileOpen.Failed(state, "x")), parser: parser).GetSnapshotAsync()).Hosts;

        Assert.Equal(state, hosts.Read);
        Assert.Null(hosts.Content);
        Assert.Null(hosts.OwnerIsTrusted);
        Assert.Empty(parser.Inputs);
    }

    [Fact]
    public async Task RegistryAccessDenied_AndAThrowingOpener_AreUnknownStates()
    {
        var snapshot = await Source(new FakeHostsOpener(() => throw new InvalidOperationException("bug")), new DenyingRegistryView()).GetSnapshotAsync();

        Assert.Equal(HijackReadState.AccessDenied, snapshot.MachineSettings.Read);
        Assert.Equal(HijackReadState.AccessDenied, snapshot.MachinePolicy.Read);
        Assert.Null(snapshot.ProxyIsMachineWide);
        Assert.Equal(HijackReadState.AccessDenied, snapshot.WinHttp.Read);
        Assert.Null(snapshot.WinHttp.ConfiguresProxy);
        Assert.Equal(HijackReadState.AccessDenied, snapshot.UsersRead);
        Assert.Equal(HijackReadState.AccessDenied, snapshot.Hosts.DataBasePathRead);
        Assert.Null(snapshot.Hosts.DataBasePathRedirected);
        Assert.Equal(HijackReadState.Failed, snapshot.Hosts.Read);
    }

    [Fact]
    public async Task Collection_WritesNothing()
    {
        _root.AddUser(SidA, @"C:\Users\a", loaded: true);
        static int Count(RegistryKey key) => key.SubKeyCount + key.ValueCount + key.GetSubKeyNames().Sum(n => { using var s = key.OpenSubKey(n)!; return Count(s); });
        int before = Count(_root.MachineKey) + Count(_root.UsersKey);

        await Source().GetSnapshotAsync();

        Assert.Equal(before, Count(_root.MachineKey) + Count(_root.UsersKey));
    }

    [Fact]
    public void RealOpener_ReadsMetadataFromTheHandle_AndMissingIsNotFound()
    {
        var path = Path.Combine(_dir.Path, "hosts");
        File.WriteAllBytes(path, Encoding.ASCII.GetBytes("127.0.0.1 a.example\n0.0.0.0 b.example\n"));
        var opener = new SafeHostsFileOpener();

        using (var opened = opener.Open(path))
        {
            Assert.Equal(HijackReadState.Available, opened.State);
            Assert.False(opened.Handle!.IsInvalid);
            Assert.Equal(new FileInfo(path).Length, opened.Length);
            Assert.Equal(OwnerOf(path), opened.OwnerSid); // elevated runs (CI): new files are owned by Administrators
            Assert.NotNull(opened.LastWriteTime);
            Assert.Equal(1u, opened.NumberOfLinks);
            Assert.True(opened.WritableByNonAdmins); // a user owns this temp file
        }

        using var missing = opener.Open(Path.Combine(_dir.Path, "missing"));
        Assert.Equal(HijackReadState.NotFound, missing.State);
        Assert.Null(missing.Handle);
    }

    [Fact]
    public void RealOpener_ALockedFile_IsRetried_ThenLockedWithAReason()
    {
        var path = Path.Combine(_dir.Path, "hosts");
        File.WriteAllText(path, "127.0.0.1 a\n");
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
        var clock = System.Diagnostics.Stopwatch.StartNew();

        using var opened = new SafeHostsFileOpener(lockedAttempts: 3, lockedDelay: TimeSpan.FromMilliseconds(50)).Open(path);

        Assert.Equal(HijackReadState.Locked, opened.State);
        Assert.Contains("oplock or lease", opened.Detail);
        Assert.True(clock.Elapsed >= TimeSpan.FromMilliseconds(90), $"retried for only {clock.Elapsed}");
    }

    [Fact]
    public void AnInvalidNameFilter_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => new RegistryBrowserHijackSource(_root.View, new FakeHostsOpener(() => throw new InvalidOperationException()),
            InTestHostsParser.Instance, SystemDirectory, () => false, ["bad name"], TimeProvider.System, NullLogger.Instance));
    }

    [Fact]
    public void DependencyInjection_ResolvesTheRegistrySource()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        Assert.IsType<RegistryBrowserHijackSource>(host.Services.GetRequiredService<IBrowserHijackSource>());
    }

    internal sealed class FakeHostsOpener(Func<HostsFileOpen> open) : IHostsFileOpener
    {
        public string? LastPath { get; private set; }

        public HostsFileOpen? LastOpen { get; private set; }

        public HostsFileOpen Open(string path)
        {
            LastPath = path;
            return LastOpen = open();
        }
    }

    /// <summary>
    /// A stand-in for the sandboxed worker in tests that aren't about the sandbox: reads the handle and runs the worker entry point
    /// plus the engine's validation in the test process (the engine assembly itself never calls the parser; see the IL guard).
    /// </summary>
    internal sealed class InTestHostsParser : IPersistenceFileParser
    {
        public static InTestHostsParser Instance { get; } = new();

        public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<PersistenceParseResult>> ParseBatchAsync(IReadOnlyList<PersistenceParseInput> files, Func<bool>? canContinue, CancellationToken cancellationToken)
        {
            var results = files.Select(f =>
            {
                long length = RandomAccess.GetLength(f.File);
                var content = new byte[Math.Min(length, HostsFileSnapshot.MaxBytes)];
                int read = RandomAccess.Read(f.File, content, 0);
                var wire = WireParsedFileCodec.ParseHostsInWorker(content[..read], length > content.Length, f.KeepNames);
                var parsed = WireParsedFileCodec.FromWire(wire, f.Kind);
                return parsed.Error is { } error
                    ? PersistenceParseResult.Malformed(error)
                    : new PersistenceParseResult(PersistenceParseStatus.Parsed, null, null, null) { Hosts = parsed.Hosts };
            }).ToArray();
            return Task.FromResult<IReadOnlyList<PersistenceParseResult>>(results);
        }
    }

    private sealed class RecordingParser(IPersistenceFileParser inner) : IPersistenceFileParser
    {
        public List<PersistenceParseInput> Inputs { get; } = [];

        public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyList<PersistenceParseResult>> ParseBatchAsync(IReadOnlyList<PersistenceParseInput> files, Func<bool>? canContinue, CancellationToken cancellationToken)
        {
            Inputs.AddRange(files);
            return inner.ParseBatchAsync(files, canContinue, cancellationToken);
        }
    }

    /// <summary>The real test view, except that one user's hive is gone when opened directly (a logoff after the listing).</summary>
    private sealed class VanishingHive(IRegistryView inner, string sid) : IRegistryView
    {
        public IRegistryKeyReader? Open(RegistryRoot root, string path) =>
            root == RegistryRoot.Users && path.Equals(sid, StringComparison.OrdinalIgnoreCase) ? null : inner.Open(root, path);
    }

    /// <summary>The file's owner SID (elevated runs, such as CI, create files owned by Administrators, not the user).</summary>
    internal static string OwnerOf(string path) =>
        new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier))!.Value;

    private sealed class DenyingRegistryView : IRegistryView
    {
        public IRegistryKeyReader? Open(RegistryRoot root, string path) => throw new UnauthorizedAccessException();
    }
}
