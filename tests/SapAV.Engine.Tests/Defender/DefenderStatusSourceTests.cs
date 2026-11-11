using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SapAV.Core.Defender;
using SapAV.Engine.Defender;
using SapAV.Engine.Tests.TestSupport;
using static SapAV.Engine.Tests.Defender.DefenderWmiData;

namespace SapAV.Engine.Tests.Defender;

/// <summary>E5: the WMI-backed source (timeouts, failures, what it queries), the real reader's hang guard, and DI wiring.</summary>
public sealed class DefenderStatusSourceTests
{
    private static WmiDefenderStatusSource Source(IWmiReader reader, TimeSpan? timeout = null, IDefenderEnvironment? environment = null) =>
        new(reader, environment ?? new FakeDefenderEnvironment(DefenderEnvironmentInfo.Unknown), TimeProvider.System,
            Options.Create(new DefenderStatusOptions { QueryTimeout = timeout ?? TimeSpan.FromSeconds(5) }),
            NullLogger<WmiDefenderStatusSource>.Instance);

    [Fact]
    public async Task Source_ReadsOnlyTheThreeClasses_WithTheConfiguredTimeout()
    {
        var reader = new FakeWmiReader()
            .Returns(DefenderStatusMapper.ComputerStatusClass, One(HealthyStatus()))
            .Returns(DefenderStatusMapper.PreferenceClass, One(Preference(paths: [@"C:\x"])));

        var snapshot = await Source(reader, TimeSpan.FromSeconds(3)).GetSnapshotAsync();

        Assert.Equal(DefenderReadState.Available, snapshot.Availability);
        Assert.Null(snapshot.RegisteredAntivirus); // Security Center missing in the fake, like on Windows Server
        Assert.Equal(
            [@"root\Microsoft\Windows\Defender:MSFT_MpComputerStatus", @"root\Microsoft\Windows\Defender:MSFT_MpPreference", @"root\SecurityCenter2:AntiVirusProduct"],
            reader.Queries.Select(q => $"{q.NamespacePath}:{q.ClassName}").Order());
        Assert.All(reader.Queries, q => Assert.Equal(TimeSpan.FromSeconds(3), q.Timeout));
    }

    [Fact]
    public async Task HungReader_GivesATimedOutSnapshot_WithinTheTimeoutPlusGrace()
    {
        // A reader that ignores its timeout entirely: the source still returns.
        var never = new TaskCompletionSource<WmiReadResult>();
        var reader = new FakeWmiReader()
            .Handles(DefenderStatusMapper.ComputerStatusClass, (_, _) => never.Task)
            .Returns(DefenderStatusMapper.PreferenceClass, One(Preference()));

        var watch = Stopwatch.StartNew();
        var snapshot = await Source(reader, TimeSpan.FromMilliseconds(200)).GetSnapshotAsync();

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"took {watch.Elapsed}");
        Assert.Equal(DefenderReadState.TimedOut, snapshot.Availability);
        Assert.Equal(DefenderReadState.Available, snapshot.PreferenceRead);
        Assert.Null(snapshot.Protection.RealTimeProtectionEnabled);
    }

    [Fact]
    public async Task ThrowingReader_IsAFailedRead_ButCallerCancellationStillThrows()
    {
        var reader = new FakeWmiReader()
            .Handles(DefenderStatusMapper.ComputerStatusClass, (_, _) => throw new InvalidOperationException("boom"))
            .Handles(DefenderStatusMapper.PreferenceClass, (_, ct) => Task.Delay(Timeout.Infinite, ct).ContinueWith(_ => One(Preference()), ct));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Source(reader).GetSnapshotAsync(cts.Token));

        reader.Returns(DefenderStatusMapper.PreferenceClass, One(Preference()));
        var snapshot = await Source(reader).GetSnapshotAsync();
        Assert.Equal(DefenderReadState.Failed, snapshot.ComputerStatusRead);
        Assert.Contains("InvalidOperationException", snapshot.Detail);
    }

    [Fact]
    public async Task RealReader_AbandonsHungCalls_AndStopsStartingNewOnesUntilTheyFinish()
    {
        using var release = new ManualResetEventSlim();
        int calls = 0;
        var reader = new ManagementWmiReader(_ =>
        {
            Interlocked.Increment(ref calls);
            release.Wait(TimeSpan.FromSeconds(30));
            return WmiReadResult.Ok([]);
        });
        var query = new WmiClassQuery(DefenderStatusMapper.DefenderNamespace, DefenderStatusMapper.ComputerStatusClass, ["AMRunningMode"], TimeSpan.FromMilliseconds(100));

        for (int i = 0; i < ManagementWmiReader.MaxAbandonedCalls; i++)
        {
            Assert.Equal(WmiReadStatus.TimedOut, (await reader.ReadAsync(query, default)).Status);
        }

        var refused = await reader.ReadAsync(query, default);
        Assert.Equal(WmiReadStatus.TimedOut, refused.Status);
        Assert.Contains("still hung", refused.Detail);
        Assert.Equal(ManagementWmiReader.MaxAbandonedCalls, Volatile.Read(ref calls)); // no new thread for the refused call

        release.Set();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (reader.AbandonedCalls > 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        Assert.Equal(WmiReadStatus.Ok, (await reader.ReadAsync(query, default)).Status);
    }

    [Theory]
    [InlineData(unchecked((int)0x8004100E), WmiReadStatus.NotFound)]          // invalid namespace: Defender not installed
    [InlineData(unchecked((int)0x80041003), WmiReadStatus.AccessDenied)]
    [InlineData(unchecked((int)0x800106BA), WmiReadStatus.ServiceNotRunning)] // Defender's service stopped
    [InlineData(unchecked((int)0x800706BA), WmiReadStatus.Unavailable)]       // WMI's RPC server unavailable
    [InlineData(unchecked((int)0x80041002), WmiReadStatus.Failed)]            // generic not found is not "not installed"
    [InlineData(unchecked((int)0x80004005), WmiReadStatus.Failed)]
    public void Hresults_AreClassified(int hresult, WmiReadStatus expected) =>
        Assert.Equal(expected, ManagementWmiReader.Classify(hresult));

    [Theory]
    [InlineData(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference WHERE 1=1")]
    [InlineData(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference;")]
    [InlineData(@"\\otherhost\root\cimv2", "Win32_Process")]
    [InlineData(@"root\..\cimv2", "Win32_Process")]
    public void Query_RejectsAnythingButALocalNamespaceAndAPlainClassName(string ns, string className) =>
        Assert.ThrowsAny<ArgumentException>(() => new WmiClassQuery(ns, className, ["Name"], TimeSpan.FromSeconds(1)));

    [Fact]
    public async Task ConcurrentCallers_ShareOneCollection()
    {
        var gate = new TaskCompletionSource();
        int statusReads = 0;
        var reader = new FakeWmiReader()
            .Handles(DefenderStatusMapper.ComputerStatusClass, async (_, _) =>
            {
                Interlocked.Increment(ref statusReads);
                await gate.Task;
                return One(HealthyStatus());
            })
            .Returns(DefenderStatusMapper.PreferenceClass, One(Preference()));
        var environment = new FakeDefenderEnvironment(DefenderEnvironmentInfo.Unknown);
        var source = Source(reader, environment: environment);

        var callers = Enumerable.Range(0, 8).Select(_ => source.GetSnapshotAsync()).ToArray();
        gate.SetResult();
        var snapshots = await Task.WhenAll(callers);

        Assert.Equal(1, statusReads);
        Assert.Equal(1, environment.Calls);
        Assert.All(snapshots, s => Assert.Same(snapshots[0], s));
        await source.GetSnapshotAsync(); // a finished collection isn't reused
        Assert.Equal(2, statusReads);
    }

    [Theory]
    [InlineData("not a timespan", 10_000)]
    [InlineData("00:00:03", 3_000)]
    public void QueryTimeout_MalformedConfig_KeepsTheDefault(string value, int expectedMs)
    {
        var section = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Defender:QueryTimeout"] = value }).Build().GetSection("Defender");
        var options = new DefenderStatusOptions();

        DefenderStatusOptions.Bind(section, options);

        Assert.Equal(TimeSpan.FromMilliseconds(expectedMs), options.QueryTimeout);
    }

    [Fact]
    public void Environment_ReadsSku_AndMergesExclusionKeys_ButAPartialListIsUnreadable()
    {
        const string local = WindowsDefenderEnvironment.LocalExclusionsKey;
        const string policy = WindowsDefenderEnvironment.PolicyExclusionsKey;
        var registry = new FakeRegistryView()
            .Key(WindowsDefenderEnvironment.ProductOptionsKey, ("ProductType", "WinNT"))
            .Key(local + @"\Paths", (@"C:\Dev", 0), (@"D:\", 0))
            .Key(policy + @"\Paths", (@"c:\dev", "0"), (@"C:\Games", "0"))
            .Denied(local + @"\Processes")
            .Key(policy + @"\Processes", ("evil.exe", "0"));

        var info = new WindowsDefenderEnvironment(registry, () => true).Read();

        Assert.True(info.IsClientSku);
        Assert.True(info.RunningAsSystem);
        Assert.Equal([@"C:\Dev", @"D:\", @"C:\Games"], info.RegistryExclusions.Paths);
        Assert.Null(info.RegistryExclusions.Processes); // the local key was denied: unknown, never just the policy half
        Assert.Empty(info.RegistryExclusions.Extensions!); // no keys at all: no exclusions
    }

    [Fact]
    public void BuiltHost_ExposesTheWmiDefenderStatusSource()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        Assert.IsType<WmiDefenderStatusSource>(host.Services.GetRequiredService<IDefenderStatusSource>());
        Assert.IsType<ManagementWmiReader>(host.Services.GetRequiredService<IWmiReader>());
    }

    /// <summary>
    /// Read-only, against the real Defender on this PC. Never writes: it only takes a snapshot. Skips when WMI or Defender's
    /// WMI provider doesn't answer (or with SAPAV_TEST_SIMULATE_CLEAN_MACHINE=1).
    /// </summary>
    [RequiresFact(Requires.DefenderWmi)]
    public async Task RealDefender_SnapshotIsReadable_WithoutChangingAnything()
    {
        var source = Source(new ManagementWmiReader(), TimeSpan.FromSeconds(30), new WindowsDefenderEnvironment());

        var snapshot = await source.GetSnapshotAsync();

        Assert.Equal(DefenderReadState.Available, snapshot.ComputerStatusRead);
        Assert.NotNull(snapshot.Protection.AntimalwareServiceEnabled);
        if (snapshot.PreferenceRead == DefenderReadState.Available)
        {
            // Visible as an administrator / SYSTEM; hidden behind the "N/A" placeholder otherwise. Never Unknown when read.
            Assert.NotEqual(DefenderExclusionListState.Unknown, snapshot.Exclusions.Paths.State);
        }
    }
}
