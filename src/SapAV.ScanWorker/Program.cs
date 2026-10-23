using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using SapAV.Core.Scanning.Isolation;
using SapAV.ScanWorker;

// The sandboxed scan worker (B5). Started only by the engine's broker:
//   SapAV.ScanWorker.exe --request-pipe <handle> --response-pipe <handle>
// Both handles are anonymous pipe ends the broker let this process inherit (and nothing else). The worker reads one
// request at a time, answers it, and exits when the request pipe closes. It never opens a user file by path: every
// file arrives as a read-only handle duplicated into this process.

if (!TryParse(args, out string requestPipe, out string responsePipe))
{
    Console.Error.WriteLine("Usage: SapAV.ScanWorker --request-pipe <handle> --response-pipe <handle> (started by the sap-AV engine).");
    return 2;
}

EnterBackgroundMode();

using var input = new AnonymousPipeClientStream(PipeDirection.In, requestPipe);
using var output = new AnonymousPipeClientStream(PipeDirection.Out, responsePipe);
using var service = new WorkerService(TestHooks.Enabled);
return await new WorkerLoop(service, input, output).RunAsync().ConfigureAwait(false);

static bool TryParse(string[] args, out string request, out string response)
{
    request = response = string.Empty;
    if (args.Length != 4 || args[0] != "--request-pipe" || args[2] != "--response-pipe")
    {
        return false;
    }

    request = args[1];
    response = args[3];
    return long.TryParse(request, NumberStyles.None, CultureInfo.InvariantCulture, out _)
        && long.TryParse(response, NumberStyles.None, CultureInfo.InvariantCulture, out _);
}

// Low CPU, I/O and memory priority for the whole process (CLAUDE.md: scanning must not freeze the PC). Best effort.
static void EnterBackgroundMode()
{
    const uint ProcessModeBackgroundBegin = 0x00100000;
    _ = NativeMethods.SetPriorityClass(NativeMethods.GetCurrentProcess(), ProcessModeBackgroundBegin);
}

internal static partial class NativeMethods
{
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetPriorityClass(IntPtr process, uint priorityClass);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetCurrentProcess();
}
