using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using SapAV.Core.BrowserHijack;
using SapAV.Engine.BrowserHijack;
using SapAV.Engine.Persistence;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.BrowserHijack;

/// <summary>
/// E6: the read-only browser-hijack collector over a throwaway test registry root (never the real HKLM / HKU) and a fake hosts
/// reader; the real hardened hosts reader over temp files; one skippable read-only test of the real machine.
/// </summary>
public sealed class BrowserHijackCollectorTests : IDisposable
{
    private const string SidA = "S-1-5-21-1000-2000-3000-1001";
    private const string SidB = "S-1-5-21-1000-2000-3000-1002";
    private const string SidUnloaded = "S-1-5-21-1000-2000-3000-1003";
    private const string SystemDirectory = @"C:\Windows\System32";

    private readonly RegistryTestRoot _root = new();

    public void Dispose() => _root.Dispose();

    private RegistryBrowserHijackSource Source(IHostsFileReader? hosts = null, IRegistryView? registry = null, Func<string, bool>? keep = null) =>
        new(registry ?? _root.View, hosts ?? new FakeHostsReader(HostsFileRead.Failed(HijackReadState.NotFound, null)), SystemDirectory,
            () => false, keep, TimeProvider.System, NullLogger.Instance);

    private RegistryKey UserSettings(string sid) => _root.Users($@"{sid}\{RegistryBrowserHijackSource.InternetSettingsPath}");

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
    public async Task Hosts_ContentAndMetadata_FromTheReader()
    {
        var reader = new FakeHostsReader(new HostsFileRead(HijackReadState.Available, null,
            Encoding.UTF8.GetBytes("127.0.0.1 localhost\n10.6.6.6 www.eset.com\n"), false, 42, DateTimeOffset.UnixEpoch, "S-1-5-21-1-2-3-1001"));

        var hosts = (await Source(reader).GetSnapshotAsync()).Hosts;

        Assert.Equal(@"C:\Windows\System32\drivers\etc\hosts", reader.LastPath);
        Assert.Equal(HostsFileSnapshot.MaxBytes, reader.LastMax);
        Assert.Equal(2, hosts.Content!.TotalEntries);
        Assert.Equal(42, hosts.Length);
        Assert.False(hosts.OwnerIsTrusted); // a user owns the hosts file: a signal
        Assert.False(hosts.ContentTruncated);
    }

    [Theory]
    [InlineData(HijackReadState.AccessDenied)]
    [InlineData(HijackReadState.Redirected)]
    [InlineData(HijackReadState.Locked)]
    public async Task Hosts_UnreadStates_LeaveContentUnknown(HijackReadState state)
    {
        var hosts = (await Source(new FakeHostsReader(HostsFileRead.Failed(state, "x"))).GetSnapshotAsync()).Hosts;

        Assert.Equal(state, hosts.Read);
        Assert.Null(hosts.Content);
        Assert.Null(hosts.OwnerIsTrusted);
    }

    [Fact]
    public async Task RegistryAccessDenied_AndAThrowingReader_AreUnknownStates()
    {
        var snapshot = await Source(new ThrowingHostsReader(), new DenyingRegistryView()).GetSnapshotAsync();

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
    public void RealReader_ReadsCappedWithTruncatedFlag_AndMissingIsNotFound()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "hosts");
        File.WriteAllBytes(path, Encoding.ASCII.GetBytes("127.0.0.1 a.example\n0.0.0.0 b.example\n"));
        var reader = new SafeHostsFileReader();

        var full = reader.Read(path, HostsFileSnapshot.MaxBytes);
        Assert.Equal(HijackReadState.Available, full.State);
        Assert.False(full.Truncated);
        Assert.Equal(new FileInfo(path).Length, full.Content.Length);
        Assert.Equal(WindowsIdentity.GetCurrent().User!.Value, full.OwnerSid);
        Assert.NotNull(full.LastWriteTime);

        var capped = reader.Read(path, 10);
        Assert.True(capped.Truncated);
        Assert.Equal(10, capped.Content.Length);

        Assert.Equal(HijackReadState.NotFound, reader.Read(Path.Combine(dir.Path, "missing"), 100).State);
    }

    [Fact]
    public void RealReader_OverOneMegabyte_IsTruncatedAndStillParses()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "hosts");
        var line = Encoding.ASCII.GetBytes("0.0.0.0 pad.example\n");
        using (var file = File.Create(path))
        {
            for (int written = 0; written <= HostsFileSnapshot.MaxBytes; written += line.Length)
            {
                file.Write(line);
            }
        }

        var source = new RegistryBrowserHijackSource(_root.View, new PathRedirectReader(path), SystemDirectory, () => false, null,
            TimeProvider.System, NullLogger.Instance);
        var hosts = source.ReadHosts();

        Assert.Equal(HijackReadState.Available, hosts.Read);
        Assert.True(hosts.ContentTruncated);
        Assert.True(hosts.Content!.EntriesTruncated);
        Assert.Equal(HostsFileSnapshot.MaxBytes / line.Length, hosts.Content.TotalEntries);
    }

    [Fact]
    public void DependencyInjection_ResolvesTheRegistrySource()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        Assert.IsType<RegistryBrowserHijackSource>(host.Services.GetRequiredService<IBrowserHijackSource>());
    }

    [RequiresFact(Requires.RealHostsFile)]
    public async Task RealMachine_HostsAndCurrentUserProxy_AreReadable_ReadOnly()
    {
        var source = new RegistryBrowserHijackSource(TimeProvider.System, NullLogger<RegistryBrowserHijackSource>.Instance);

        var snapshot = await source.GetSnapshotAsync();

        Assert.Equal(Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts"), snapshot.Hosts.Path, ignoreCase: true);
        Assert.Equal(HijackReadState.Available, snapshot.Hosts.Read);
        Assert.NotNull(snapshot.Hosts.Content);
        var me = snapshot.Users.Single(u => u.Sid == WindowsIdentity.GetCurrent().User!.Value);
        Assert.True(me.HiveLoaded);
        Assert.Equal(HijackReadState.Available, me.Settings.Read);
        Assert.NotNull(me.Settings.ConfiguresProxy);
    }

    private sealed class FakeHostsReader(HostsFileRead result) : IHostsFileReader
    {
        public string? LastPath { get; private set; }

        public int LastMax { get; private set; }

        public HostsFileRead Read(string path, int maxBytes)
        {
            LastPath = path;
            LastMax = maxBytes;
            return result;
        }
    }

    private sealed class ThrowingHostsReader : IHostsFileReader
    {
        public HostsFileRead Read(string path, int maxBytes) => throw new InvalidOperationException("bug");
    }

    /// <summary>The real reader, pointed at a temp file instead of the system hosts file.</summary>
    private sealed class PathRedirectReader(string path) : IHostsFileReader
    {
        public HostsFileRead Read(string ignored, int maxBytes) => new SafeHostsFileReader().Read(path, maxBytes);
    }

    private sealed class DenyingRegistryView : IRegistryView
    {
        public IRegistryKeyReader? Open(RegistryRoot root, string path) => throw new UnauthorizedAccessException();
    }
}
