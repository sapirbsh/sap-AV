using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Hashing;
using SapAV.Engine.RealTime;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.RealTime;

/// <summary>
/// Review D1 H1: holds a batch oplock on a file and never acknowledges its break (like a hostile or hung oplock holder).
/// Any other open of the file that waits for the acknowledgement would hang until this is disposed.
/// </summary>
internal sealed class BatchOplock : IDisposable
{
    private const uint FsctlRequestBatchOplock = 0x00090008;
    private readonly Microsoft.Win32.SafeHandles.SafeFileHandle _handle;

    public BatchOplock(string path)
    {
        _handle = CreateFileW(path, 0x80000000 /* GENERIC_READ */, 0x7, IntPtr.Zero, 3 /* OPEN_EXISTING */, 0x40000000 /* OVERLAPPED */, IntPtr.Zero);
        Assert.False(_handle.IsInvalid, $"open for the oplock failed ({System.Runtime.InteropServices.Marshal.GetLastPInvokeError()})");
        // Left to the process on purpose: the kernel completes this OVERLAPPED when the handle closes (32 bytes, test only).
        IntPtr overlapped = System.Runtime.InteropServices.Marshal.AllocHGlobal(64);
        System.Runtime.InteropServices.Marshal.Copy(new byte[64], 0, overlapped, 64);
        bool granted = DeviceIoControl(_handle, FsctlRequestBatchOplock, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, overlapped);
        int error = System.Runtime.InteropServices.Marshal.GetLastPInvokeError();
        Assert.True(!granted && error == 997, $"the batch oplock was not granted (Win32 error {error})"); // ERROR_IO_PENDING = held
    }

    public void Dispose() => _handle.Dispose();

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(
        string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        Microsoft.Win32.SafeHandles.SafeFileHandle device, uint code, IntPtr inBuffer, uint inSize, IntPtr outBuffer, uint outSize, out uint returned,
        IntPtr overlapped);
}

/// <summary>Real time moved by a fixed offset (the clock still runs).</summary>
internal sealed class ShiftedTime(TimeSpan offset) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + offset;
}

/// <summary>A fixed folder list.</summary>
internal sealed class FixedFolders(params WatchedFolder[] folders) : IWatchedFolderSource
{
    public List<WatchedFolder> Folders { get; } = [.. folders];

    public WatchedFolderSet Resolve() => new([.. Folders], []);
}

/// <summary>
/// A watch factory whose events the test pushes by hand (no FileSystemWatcher timing). The monitor still opens each root
/// for real (SafeTree), so every event is resolved against the real file system.
/// </summary>
internal sealed class FakeWatchFactory : IDirectoryWatchFactory
{
    private readonly ConcurrentDictionary<string, (WatchedRoot Root, IDirectoryWatchSink Sink)> _watches = new(StringComparer.OrdinalIgnoreCase);

    public int Started { get; private set; }

    public IDisposable Start(WatchedRoot root, IDirectoryWatchSink sink, int bufferBytes)
    {
        Started++;
        _watches[root.ExactPath] = (root, sink);
        return new Stop(() => _watches.TryRemove(root.ExactPath, out _));
    }

    public bool IsWatching(string folder) => _watches.ContainsKey(ExactPath.ToExtended(folder)!);

    public WatchedRoot Root(string folder) => _watches[ExactPath.ToExtended(folder)!].Root;

    public void Raise(string folder, params FileChange[] changes)
    {
        var (root, sink) = _watches[ExactPath.ToExtended(folder)!];
        sink.OnChanges(root, changes);
    }

    public void Added(string folder, params string[] names) => Raise(folder, [.. names.Select(n => new FileChange(FileChangeKind.Added, n))]);

    public void Overflow(string folder)
    {
        var (root, sink) = _watches[ExactPath.ToExtended(folder)!];
        sink.OnOverflow(root);
    }

    private sealed class Stop(Action stop) : IDisposable
    {
        public void Dispose() => stop();
    }
}

/// <summary>
/// One real-time test: a temp folder <see cref="Watched"/> (watched), a fake broker (verdict by file name), the real scan
/// pipeline, the real queue and threads, short delays. Results are collected and waited for without sleeping.
/// </summary>
internal sealed class RealTimeHarness : IDisposable
{
    private readonly TempDir _temp = new();
    private readonly List<RealTimeFileResult> _results = [];
    private RealTimeMonitor? _monitor;

    public RealTimeHarness()
    {
        Watched = Directory.CreateDirectory(Path.Combine(_temp.Path, "watched")).FullName;
        Outside = Directory.CreateDirectory(Path.Combine(_temp.Path, "outside")).FullName;
        Folders = new FixedFolders(new WatchedFolder(Watched, WatchedFolderKind.Downloads));
    }

    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public string Base => _temp.Path;

    public string Watched { get; }

    /// <summary>A folder that is not watched (link targets, "elsewhere").</summary>
    public string Outside { get; }

    public FixedFolders Folders { get; }

    public FakeScanBroker Broker { get; } = new();

    public FakeWatchFactory Events { get; } = new();

    /// <summary>Null = no verdict handler (results only).</summary>
    public IScanVerdictHandler? Handler { get; set; }

    /// <summary>Replaces <see cref="Events"/> (e.g. the real watcher).</summary>
    public IDirectoryWatchFactory? Watches { get; set; }

    public IScanBroker? RealBroker { get; set; }

    public IRemoteFileProbe? Remote { get; set; }

    public Func<string, int>? DriveType { get; set; }

    /// <summary>The monitor's clock (real time, optionally shifted so files written now count as "old" or "recent").</summary>
    public TimeProvider Time { get; set; } = TimeProvider.System;

    public ListLogger<RealTimeMonitor> Log { get; } = new();

    public RealTimeOptions Options { get; } = new()
    {
        ScanThreads = 1,
        SettleDelay = TimeSpan.FromMilliseconds(20),
        MaxSettleDelay = TimeSpan.FromMilliseconds(500),
        LockRetryInitial = TimeSpan.FromMilliseconds(10),
        LockRetryMax = TimeSpan.FromMilliseconds(50),
        MaxLockWait = TimeSpan.FromSeconds(20),
        RevalidateInterval = TimeSpan.FromHours(1),
    };

    public RealTimeMonitor Monitor => _monitor ?? throw new InvalidOperationException("Start() first.");

    public RealTimeMonitor Start()
    {
        var pipeline = new ScanFilePipeline(RealBroker ?? Broker, ExclusionSet.Always(new FolderSet([])), Handler, TimeProvider.System, NullLogger.Instance);
        _monitor = new RealTimeMonitor(Options, Folders, pipeline, ExclusionSet.Always(new FolderSet([])), Time, LockedLog,
            Watches ?? Events, Remote, driveType: DriveType);
        _monitor.FileHandled += result =>
        {
            lock (_results)
            {
                _results.Add(result);
                Monitor_Pulse();
            }
        };
        _monitor.Start();
        return _monitor;
    }

    private ILogger LockedLog => new SynchronizedLogger(Log);

    private void Monitor_Pulse() => System.Threading.Monitor.PulseAll(_results);

    public string Write(string relative, string content = "plain test content")
    {
        var path = Path.Combine(Watched, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    /// <summary>A snapshot of the log (the monitor logs from several threads).</summary>
    public (LogLevel Level, string Message)[] LogLines()
    {
        lock (Log)
        {
            return [.. Log.Lines];
        }
    }

    public RealTimeFileResult[] Results()
    {
        lock (_results)
        {
            return [.. _results];
        }
    }

    /// <summary>Waits (no sleep: woken by each result) until a result matches.</summary>
    public RealTimeFileResult WaitFor(Func<RealTimeFileResult, bool> match)
    {
        var deadline = DateTime.UtcNow + Timeout;
        lock (_results)
        {
            while (true)
            {
                if (_results.FirstOrDefault(match) is { } found)
                {
                    return found;
                }

                var left = deadline - DateTime.UtcNow;
                Assert.True(left > TimeSpan.Zero, $"No matching real-time result in time; got: {string.Join(", ", _results.Select(r => $"{Path.GetFileName(r.Path)}={r.Outcome}"))}");
                System.Threading.Monitor.Wait(_results, left);
            }
        }
    }

    public RealTimeFileResult WaitFor(string name) =>
        WaitFor(r => string.Equals(Path.GetFileName(r.Path), name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Polls a condition on the monitor's state (status counters) until it holds.</summary>
    public static void Until(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + Timeout;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting for: {what}");
            Thread.Sleep(5);
        }
    }

    public void Dispose()
    {
        _monitor?.Dispose();
        _temp.Dispose();
    }

    /// <summary>The list logger is not thread-safe; the monitor logs from several threads.</summary>
    private sealed class SynchronizedLogger(ListLogger<RealTimeMonitor> inner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (inner)
            {
                inner.Log(logLevel, eventId, state, exception, formatter);
            }
        }
    }
}
