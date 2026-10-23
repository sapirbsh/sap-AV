using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.ScanWorker;

/// <summary>
/// Fault injection and sandbox probes for the engine's tests. Off unless the engine starts the worker with
/// <c>SAPAV_SCANWORKER_TEST_HOOKS=1</c>; the engine sets that only through an internal, test-only launch option
/// (never from configuration), and it always passes a fresh, minimal environment, so nothing inherited can turn it on.
/// With the hooks off, a request asking for a fault or a probe is refused (a Failed response).
/// </summary>
internal static class TestHooks
{
    public const string Variable = "SAPAV_SCANWORKER_TEST_HOOKS";

    public static bool Enabled { get; } = Environment.GetEnvironmentVariable(Variable) == "1";

    /// <summary>Simulates a parser that crashes the process or never returns.</summary>
    public static void Inject(WorkerTestFault fault)
    {
        switch (fault)
        {
            case WorkerTestFault.Crash:
                Environment.FailFast("sap-AV scan worker: injected parser crash (test hook).");
                break;

            case WorkerTestFault.Hang:
                Thread.Sleep(Timeout.Infinite);
                break;
        }
    }
}

/// <summary>Operations the sandbox must block, each reported as succeeded / failed with the Win32 error.</summary>
internal static class SandboxProbes
{
    public static WorkerProbeResult Run(WorkerProbeRequest probe)
    {
        try
        {
            return probe.Kind switch
            {
                WorkerProbeKind.ConnectTcp => ConnectTcp(probe.Port),
                WorkerProbeKind.OpenPath => OpenPath(probe.Path),
                WorkerProbeKind.WriteHandle => WriteHandle(probe.Handle),
                WorkerProbeKind.DeleteViaHandle => DeleteViaHandle(probe.Handle),
                WorkerProbeKind.SpawnProcess => SpawnProcess(),
                WorkerProbeKind.CreateFileIn => CreateFileIn(probe.Path),
                _ => Result(false, 0, "unknown probe"),
            };
        }
        catch (Exception ex)
        {
            return Result(false, ex.HResult & 0xFFFF, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static WorkerProbeResult ConnectTcp(int port)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            var connect = socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
            if (!connect.Wait(TimeSpan.FromSeconds(5)))
            {
                return Result(false, 0, "connect timed out");
            }

            return Result(true, 0, "connected");
        }
        catch (AggregateException ex) when (ex.InnerException is SocketException se)
        {
            return Result(false, se.ErrorCode, $"SocketException {se.SocketErrorCode}");
        }
        catch (SocketException se)
        {
            return Result(false, se.ErrorCode, $"SocketException {se.SocketErrorCode}");
        }
    }

    private static WorkerProbeResult OpenPath(string? path)
    {
        using var handle = File.OpenHandle(path ?? string.Empty, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Result(true, 0, $"opened ({RandomAccess.GetLength(handle)} bytes)");
    }

    private static WorkerProbeResult CreateFileIn(string? directory)
    {
        var path = Path.Combine(directory ?? string.Empty, "sapav-probe-" + Guid.NewGuid().ToString("N") + ".txt");
        using (File.OpenHandle(path, FileMode.CreateNew, FileAccess.Write))
        {
        }

        File.Delete(path);
        return Result(true, 0, "created");
    }

    private static unsafe WorkerProbeResult WriteHandle(long handle)
    {
        using var file = new SafeFileHandle((IntPtr)handle, ownsHandle: false);
        byte b = (byte)'X';
        if (WriteFile(file, &b, 1, out _, IntPtr.Zero))
        {
            return Result(true, 0, "wrote 1 byte");
        }

        return Result(false, Marshal.GetLastPInvokeError(), "WriteFile failed");
    }

    private static unsafe WorkerProbeResult DeleteViaHandle(long handle)
    {
        using var file = new SafeFileHandle((IntPtr)handle, ownsHandle: false);
        byte deleteFile = 1; // FILE_DISPOSITION_INFO.DeleteFile
        if (SetFileInformationByHandle(file, 4 /* FileDispositionInfo */, &deleteFile, 1))
        {
            return Result(true, 0, "marked for deletion");
        }

        return Result(false, Marshal.GetLastPInvokeError(), "SetFileInformationByHandle(FileDispositionInfo) failed");
    }

    private static WorkerProbeResult SpawnProcess()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        using var process = Process.Start(new ProcessStartInfo(cmd, "/c exit 0") { UseShellExecute = false, CreateNoWindow = true });
        return Result(process is not null, 0, process is null ? "no process" : $"started pid {process.Id}");
    }

    private static WorkerProbeResult Result(bool succeeded, int error, string detail) =>
        new() { Succeeded = succeeded, Win32Error = error, Detail = detail };

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool WriteFile(SafeFileHandle file, byte* buffer, uint count, out uint written, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, void* info, uint size);
}
