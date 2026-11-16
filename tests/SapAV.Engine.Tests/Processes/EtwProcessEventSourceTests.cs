using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Processes;
using SapAV.Engine.Processes;

namespace SapAV.Engine.Tests.Processes;

/// <summary>E8: the engine source's lifecycle against a fake ETW session (no real session is created here).</summary>
public sealed class EtwProcessEventSourceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 16, 10, 0, 0, TimeSpan.Zero);

    private static EtwProcessEventSource Source(FakeSessionFactory factory, IRunningProcessSnapshot? snapshot = null, IProcessInfoReader? info = null) =>
        new(new ProcessEventSourceOptions(), NullLogger.Instance, TimeProvider.System, factory, snapshot ?? new FixedSnapshot([]),
            info ?? new FixedInfo(), p => p);

    [Fact]
    public async Task NotElevated_ReportsAccessDenied_WithoutTouchingEtw()
    {
        var factory = new FakeSessionFactory { Elevated = false };
        using var source = Source(factory);

        var status = await source.StartAsync();

        Assert.Equal(ProcessEventSourceHealth.AccessDenied, status.Health);
        Assert.Equal(0, factory.Creates);
        Assert.Empty(factory.Stopped);
    }

    [Fact]
    public async Task CreateFailures_MapToAccessDeniedOrUnavailable_AndNeverThrow()
    {
        using var denied = Source(new FakeSessionFactory { CreateError = new UnauthorizedAccessException() });
        Assert.Equal(ProcessEventSourceHealth.AccessDenied, (await denied.StartAsync()).Health);

        using var noResources = Source(new FakeSessionFactory { CreateError = new COMException("no", unchecked((int)0x800705AA)) });
        var status = await noResources.StartAsync();
        Assert.Equal(ProcessEventSourceHealth.Unavailable, status.Health);
        Assert.Contains("0x800705AA", status.Detail);
    }

    [Fact]
    public async Task Start_StopsALeftoverSession_PublishesPreExisting_ThenLiveEvents()
    {
        var factory = new FakeSessionFactory();
        var old = new ProcessDetails(T0.AddHours(-1), @"C:\Windows\explorer.exe", "explorer.exe", 1, "S-1-5-21-1-2-3-1001", ProcessIntegrityLevel.Medium);
        using var source = Source(factory, new FixedSnapshot([new RunningProcessEntry(50, 4, "explorer.exe")]), new FixedInfo { [50] = old });
        using var sub = source.Subscribe();

        var status = await source.StartAsync();

        Assert.Equal(ProcessEventSourceHealth.Running, status.Health);
        Assert.Equal([ProcessEventSourceOptions.DefaultSessionName], factory.Stopped); // the leftover-session cleanup ran first
        Assert.Equal(ProcessEventSourceOptions.DefaultSessionName, status.SessionName);
        var existing = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(existing.IsPreExisting);
        Assert.Equal("explorer.exe", existing.CommandLine);

        factory.Last!.Feed(new KernelProcessRecord(ProcessEventKind.Started, 60, 50, T0, 1, @"C:\Windows\System32\cmd.exe", T0));
        var started = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(60, started.ProcessId);
        Assert.Equal(50, source.FindParent(started)?.ProcessId);
    }

    [Fact]
    public async Task StopAndDispose_StopTheSession_JoinTheThread_AndAreIdempotent()
    {
        var factory = new FakeSessionFactory();
        var source = Source(factory);
        var sub = source.Subscribe();
        await source.StartAsync();
        var session = factory.Last!;

        await source.StopAsync();
        Assert.True(session.StopCalled);
        Assert.True(session.RunReturned.Wait(TimeSpan.FromSeconds(10)));
        Assert.Equal(ProcessEventSourceHealth.Stopped, source.Status.Health);
        await source.StopAsync();

        // It can start again with a fresh session, and Dispose stops that one too and completes every reader.
        await source.StartAsync();
        var second = factory.Last!;
        Assert.NotSame(session, second);
        source.Dispose();
        source.Dispose();
        Assert.True(second.StopCalled);
        await sub.Reader.Completion.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => source.StartAsync());
    }

    [Fact]
    public async Task SessionEndingOnItsOwn_IsUnavailable_AndLostEventsAreReported()
    {
        var factory = new FakeSessionFactory();
        using var source = Source(factory);
        await source.StartAsync();
        var session = factory.Last!;

        session.Lost = 12;
        Assert.Equal(ProcessEventSourceHealth.LostEvents, source.Status.Health);
        Assert.Equal(12, source.Status.LostEvents);

        session.EndFromOutside(); // e.g. "logman stop" by an administrator
        Assert.True(session.RunReturned.Wait(TimeSpan.FromSeconds(10)));
        await WaitFor(() => source.Status.Health == ProcessEventSourceHealth.Unavailable);
        Assert.True(session.StopCalled);

        Assert.Equal(ProcessEventSourceHealth.Running, (await source.StartAsync()).Health); // a restart gets a new session
    }

    [Fact]
    public async Task HostedService_StartsOnlyAsServiceOrSystem_OrWhenAskedInConsole()
    {
        using var source = new FakeProcessEventSource();
        var console = new ProcessEventSourceService(source, new ProcessEventSourceOptions(), NullLogger<ProcessEventSourceService>.Instance, () => false);
        await console.StartAsync(CancellationToken.None);
        await console.StopAsync(CancellationToken.None);
        Assert.Equal(0, source.StartCalls);
        Assert.Equal(0, source.StopCalls);

        var disabled = new ProcessEventSourceService(source, new ProcessEventSourceOptions { Enabled = false }, NullLogger<ProcessEventSourceService>.Instance, () => true);
        await disabled.StartAsync(CancellationToken.None);
        Assert.Equal(0, source.StartCalls);

        var service = new ProcessEventSourceService(source, new ProcessEventSourceOptions(), NullLogger<ProcessEventSourceService>.Instance, () => true);
        await service.StartAsync(CancellationToken.None);
        await service.StopAsync(CancellationToken.None);
        Assert.Equal(1, source.StartCalls);
        Assert.Equal(1, source.StopCalls);
    }

    [Fact]
    public void BuiltHost_RegistersTheEtwSource_WithoutStartingIt()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        var source = Assert.IsType<EtwProcessEventSource>(host.Services.GetRequiredService<IProcessEventSource>());
        Assert.Equal(ProcessEventSourceHealth.Stopped, source.Status.Health);
        Assert.Contains(host.Services.GetServices<IHostedService>(), s => s is ProcessEventSourceService);
    }

    [Theory]
    [InlineData("sap-AV-Engine-KernelProcess", true)]
    [InlineData("sap-AV-Test-KernelProcess-p12-ab", true)]
    [InlineData("NT Kernel Logger", false)]
    [InlineData("sap-AV-x\n", false)]
    [InlineData("EventLog-System", false)]
    public void SessionName_MustBeASapAvName_ElseTheDefaultIsUsed(string name, bool valid)
    {
        var options = new ProcessEventSourceOptions { SessionName = name };
        Assert.Equal(valid, ProcessEventSourceOptions.IsValidSessionName(name));
        Assert.Equal(valid ? name : ProcessEventSourceOptions.DefaultSessionName, options.EffectiveSessionName);
    }

    [Fact]
    public void OrphanedSessions_AreThoseWhoseOwnerPidIsGone_OnlyUnderTheSapAvPrefix()
    {
        const string Prefix = "sap-AV-Test-KernelProcess-";
        string[] active = ["sap-AV-Test-KernelProcess-p100-aa", "sap-AV-Test-KernelProcess-p200-bb", "sap-AV-Engine-KernelProcess",
            "Other-p100-cc", "sap-AV-Test-KernelProcess-pX-dd"];

        var orphaned = EtwSessionNames.FindOrphaned(active, Prefix, pid => pid == 200);

        Assert.Equal(["sap-AV-Test-KernelProcess-p100-aa"], orphaned);
        Assert.Throws<ArgumentException>(() => EtwSessionNames.FindOrphaned(active, "EventLog-", _ => false));
    }

    private static async Task WaitFor(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "condition not reached in time");
            await Task.Delay(20);
        }
    }

    internal sealed class FixedSnapshot(IReadOnlyList<RunningProcessEntry> entries) : IRunningProcessSnapshot
    {
        public IReadOnlyList<RunningProcessEntry> Take() => entries;
    }

    internal sealed class FixedInfo : Dictionary<int, ProcessDetails>, IProcessInfoReader
    {
        public ProcessDetails? TryRead(int processId) => TryGetValue(processId, out var d) ? d : null;
    }

    internal sealed class FakeSessionFactory : IKernelProcessSessionFactory
    {
        public bool? Elevated { get; set; } = true;

        public Exception? CreateError { get; set; }

        public int Creates { get; private set; }

        public List<string> Stopped { get; } = [];

        public FakeSession? Last { get; private set; }

        public bool? IsElevated() => Elevated;

        public IReadOnlyList<string> GetActiveSessionNames() => [];

        public bool StopSession(string name)
        {
            Stopped.Add(name);
            return false;
        }

        public IKernelProcessSession Create(string name, int bufferSizeMB)
        {
            Creates++;
            if (CreateError is not null)
            {
                throw CreateError;
            }

            return Last = new FakeSession(name);
        }
    }

    internal sealed class FakeSession(string name) : IKernelProcessSession
    {
        private readonly BlockingCollection<KernelProcessRecord?> _queue = [];

        public string Name { get; } = name;

        public long? EventsLost => Lost;

        public long Lost { get; set; }

        public bool StopCalled { get; private set; }

        public ManualResetEventSlim RunReturned { get; } = new();

        public void Feed(KernelProcessRecord record) => _queue.Add(record);

        public void EndFromOutside() => _queue.Add(null);

        public void Run(Action<KernelProcessRecord> onRecord)
        {
            try
            {
                foreach (var record in _queue.GetConsumingEnumerable())
                {
                    if (record is null)
                    {
                        return;
                    }

                    onRecord(record);
                }
            }
            finally
            {
                RunReturned.Set();
            }
        }

        public void Stop()
        {
            StopCalled = true;
            _queue.CompleteAdding();
        }

        public void Dispose() => Stop();
    }
}
