using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Processes;
using SapAV.Engine.Processes;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Processes;

/// <summary>
/// E8: the one real ETW test. A uniquely named test session (owner PID in its name) sees a harmless child process
/// (<c>cmd.exe /c exit 0</c>) start and stop. Runs only elevated with a working ETW session; the session is always stopped.
/// </summary>
public sealed class EtwProcessEventSourceIntegrationTests
{
    [RequiresFact(Requires.RunningElevated, Requires.EtwSession)]
    public async Task RealSession_SeesAChildProcessStartAndStop()
    {
        TestRequirements.StopOrphanedTestEtwSessions();
        var options = new ProcessEventSourceOptions
        {
            StartInConsole = true,
            SessionName = EtwSessionNames.WithOwner(TestRequirements.TestEtwSessionPrefix, Environment.ProcessId, Guid.NewGuid().ToString("N")[..8]),
        };
        var factory = TraceEventKernelProcessSessionFactory.Instance;
        var source = new EtwProcessEventSource(options, NullLogger.Instance, TimeProvider.System, factory, ToolhelpProcessSnapshot.Instance,
            NativeProcessInfoReader.Instance, new DevicePathMapper().ToWin32);
        try
        {
            using var sub = source.Subscribe(capacity: ProcessEventSubscription.MaxCapacity);
            var status = await source.StartAsync();
            Assert.True(status.IsReceiving, $"{status.Health}: {status.Detail}");
            Assert.Contains(source.GetKnownProcesses(), p => p.ProcessId == Environment.ProcessId && p.IsPreExisting);

            using var child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c exit 0")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            })!;
            int childPid = child.Id;
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));

            ProcessEvent? started = null, stopped = null;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while ((started is null || stopped is null) && !timeout.IsCancellationRequested)
            {
                ProcessEvent e;
                try
                {
                    e = await sub.Reader.ReadAsync(timeout.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (e.ProcessId != childPid)
                {
                    continue;
                }

                if (e.Kind == ProcessEventKind.Started && e.ParentProcessId == Environment.ProcessId)
                {
                    started = e;
                }
                else if (e.Kind == ProcessEventKind.Stopped && started is not null && e.Key == started.Key)
                {
                    stopped = e;
                }
            }

            Assert.NotNull(started);
            Assert.Equal(Environment.ProcessId, started.ParentProcessId);
            Assert.EndsWith("cmd.exe", started.ImagePath, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(started.StartTime);
            Assert.NotNull(stopped);
            Assert.Equal(0, stopped.ExitCode);
            Assert.Null(source.FindProcess(started.Key));
        }
        finally
        {
            source.Dispose();
        }

        Assert.DoesNotContain(options.SessionName, factory.GetActiveSessionNames());
    }
}
