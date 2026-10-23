using SapAV.Engine.Scanning.Native;

namespace SapAV.Engine.Scanning;

/// <summary>
/// Dedicated threads for blocking scan work (file opens and directory listing can't be cancelled and can stall on slow
/// shares or oplocks, so they never run on the shared thread pool; review A2). Each thread puts <b>itself</b> in
/// background mode (<c>THREAD_MODE_BACKGROUND_BEGIN</c>: low CPU, I/O and memory priority) and leaves it before exiting;
/// the engine process and its other threads (pipe, alerts) keep normal priority.
/// </summary>
internal static class BackgroundThread
{
    /// <summary>Starts <paramref name="body"/> on a new background-mode thread. Exceptions from the body are the caller's to catch.</summary>
    public static Thread Start(string name, Action body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var thread = new Thread(() => Run(body))
        {
            IsBackground = true,
            Name = name,
        };
        thread.Start();
        return thread;
    }

    /// <summary>True on threads started here while background mode is on (for tests and logs).</summary>
    [ThreadStatic]
    private static bool t_inBackgroundMode;

    public static bool IsCurrentInBackgroundMode => t_inBackgroundMode;

    private static void Run(Action body)
    {
        t_inBackgroundMode = ScanNative.BeginBackgroundMode();
        try
        {
            body();
        }
        finally
        {
            if (t_inBackgroundMode)
            {
                ScanNative.EndBackgroundMode();
                t_inBackgroundMode = false;
            }
        }
    }
}
