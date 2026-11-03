using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.RealTime;

/// <summary>
/// Review D1 H1: a watchdog for one real-time scan thread. The thread arms it with a deadline for each stage of a file (the
/// opens, then the pipeline call); the scheduler checks it, and a thread past its deadline gets <c>CancelSynchronousIo</c>
/// (again every second until it moves on). That ends an open stuck behind an oplock break the holder never acknowledges
/// (the probe and scan opens already use FILE_COMPLETE_IF_OPLOCKED; this covers anything else synchronous, e.g. the
/// quarantine's reopen). The cancelled call fails with ERROR_OPERATION_ABORTED and the file is retried or reported.
/// Cancelling is harmless when the thread isn't in synchronous I/O (it waits for the worker on a task, not on I/O).
/// </summary>
internal sealed class ScanThreadWatch : IDisposable
{
    private const uint ThreadTerminate = 0x0001; // what CancelSynchronousIo needs

    private readonly SafeWaitHandle _thread;
    private readonly Lock _gate = new();
    private long _deadline;
    private string? _path;
    private string? _stage;

    private ScanThreadWatch(SafeWaitHandle thread) => _thread = thread;

    /// <summary>Times this watch cancelled its thread's I/O (tests).</summary>
    public int Cancellations { get; private set; }

    /// <summary>A watch for the calling thread (call it on the thread being watched).</summary>
    public static ScanThreadWatch ForCurrentThread() => new(new SafeWaitHandle(OpenThread(ThreadTerminate, false, GetCurrentThreadId()), ownsHandle: true));

    /// <summary>The thread starts <paramref name="stage"/> of <paramref name="path"/>; overdue after <paramref name="timeout"/>.</summary>
    public void Arm(string path, string stage, TimeSpan timeout)
    {
        lock (_gate)
        {
            _path = path;
            _stage = stage;
            _deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        }
    }

    /// <summary>The thread is done with the file. Taking the lock means a cancel decided for this file has already happened.</summary>
    public void Disarm()
    {
        lock (_gate)
        {
            _deadline = 0;
        }
    }

    /// <summary>Cancels the thread's synchronous I/O if it is past its deadline at <paramref name="now"/> (TickCount64 ms).</summary>
    /// <returns>What it was stuck on, or null if it isn't overdue.</returns>
    public (string Path, string Stage)? CancelIfOverdue(long now)
    {
        lock (_gate)
        {
            if (_deadline == 0 || now < _deadline)
            {
                return null;
            }

            _deadline = now + 1000;
            if (!_thread.IsInvalid)
            {
                CancelSynchronousIo(_thread); // false (ERROR_NOT_FOUND) when nothing is pending: fine
            }

            Cancellations++;
            return (_path ?? string.Empty, _stage ?? string.Empty);
        }
    }

    public void Dispose() => _thread.Dispose();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenThread(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelSynchronousIo(SafeWaitHandle thread);
}
