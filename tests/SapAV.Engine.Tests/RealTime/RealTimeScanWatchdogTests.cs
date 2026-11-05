using SapAV.Core.Scanning;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>Section D tester request: the scan-stage watchdog fires on a hung pipeline call (StuckScanTimeout is an option now).</summary>
public sealed class RealTimeScanWatchdogTests : IDisposable
{
    private readonly RealTimeHarness _rt = new();

    public void Dispose() => _rt.Dispose();

    [Fact]
    public void AScanThatHangs_IsCancelledByTheWatchdog()
    {
        _rt.Options.StuckScanTimeout = TimeSpan.FromMilliseconds(200);
        using var release = new ManualResetEventSlim();
        _rt.Broker.OnScan = (_, _, _) =>
        {
            // Hangs on the scan thread (synchronously, like a stuck open) until the watchdog has fired, or 20 s.
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
            while (_rt.Monitor.Status.Cancelled == 0 && DateTime.UtcNow < deadline)
            {
                release.Wait(TimeSpan.FromMilliseconds(50));
            }

            return Task.FromResult<FileScanReport?>(null);
        };
        _rt.Write("hang.txt");
        _rt.Start();

        _rt.Events.Added(_rt.Watched, "hang.txt");
        _rt.WaitFor("hang.txt");

        Assert.True(_rt.Monitor.Status.Cancelled >= 1);
    }
}
