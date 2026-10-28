using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>A running process and its image path (C4). <paramref name="ImagePath"/> is null when it couldn't be read.</summary>
/// <param name="Problem">Why the image path is missing (engine text: "access denied", "no image file"...), or null.</param>
internal sealed record ProcessImage(int ProcessId, string Name, string? ImagePath, string? Problem = null);

/// <summary>Lists running processes (fake it in tests). Never kills, suspends or injects into anything.</summary>
internal interface IProcessSource
{
    IReadOnlyList<ProcessImage> Snapshot(CancellationToken cancellationToken);
}

/// <summary>
/// The real process list: process IDs from the system process snapshot (<see cref="Process.GetProcesses()"/>,
/// NtQuerySystemInformation underneath), then for each one <c>OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)</c> and
/// <c>QueryFullProcessImageNameW</c> (Win32 path). That right is enough for nearly every process as SYSTEM, including
/// protected (PPL) ones; whatever still can't be opened is reported as not collected, never an error. The handle is
/// query-only: nothing is read from the process's memory, and nothing is stopped or suspended. The System and Idle
/// processes have no image file.
/// </summary>
internal sealed class WindowsProcessSource : IProcessSource
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int MaxPath = 32_767;

    public IReadOnlyList<ProcessImage> Snapshot(CancellationToken cancellationToken)
    {
        var result = new List<ProcessImage>();
        Process[] processes = Process.GetProcesses();
        try
        {
            foreach (var process in processes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int pid;
                string name;
                try
                {
                    pid = process.Id;
                    name = process.ProcessName;
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
                {
                    continue; // exited meanwhile
                }

                result.Add(pid is 0 or 4 ? new ProcessImage(pid, name, null, "no image file (system process)") : Query(pid, name));
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }

        return result;
    }

    private static ProcessImage Query(int pid, string name)
    {
        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            return new ProcessImage(pid, name, null, error == 5 ? "access denied (protected process)" : $"could not be opened (Win32 error {error})");
        }

        var buffer = new char[MaxPath];
        uint size = (uint)buffer.Length;
        if (!QueryFullProcessImageNameW(handle, 0, buffer, ref size))
        {
            return new ProcessImage(pid, name, null, $"no image path (Win32 error {Marshal.GetLastPInvokeError()})");
        }

        return new ProcessImage(pid, name, new string(buffer, 0, (int)size));
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] exeName, ref uint size);
}

/// <summary>
/// Quick Scan phase 1 (C4): the executables of running processes. Each distinct image (case-insensitive path) is queued
/// once and scanned like any file: SafeScanOpen (no link followed, writers denied; a file a writer has open is scanned
/// shared with a change-journal check, or reported Locked) and the sandboxed worker. A running image is normally readable
/// (the loader's mapping blocks writers, not readers). A Malicious image gets the normal auto-quarantine policy: the file
/// is moved, but the program keeps running from memory until it exits; stopping it is Remove threat (E11), never here.
/// </summary>
internal sealed class ProcessImageCheck(IProcessSource source, ILogger? logger = null) : IScanCheck
{
    public string Name => "Running programs";

    public double Weight => 1;

    public void Run(IScanCheckContext context)
    {
        var snapshot = source.Snapshot(context.CancellationToken);
        var summary = Summarize(snapshot);
        foreach (var path in summary.Images)
        {
            context.QueueFile(path);
        }

        context.Note($"{snapshot.Count} processes, {summary.Images.Count} distinct program files.");
        if (summary.NotCollected.Count > 0)
        {
            context.Note($"{summary.NotCollected.Count} processes were not collected (protected, system or already exited); see the engine log.");
            foreach (var p in summary.NotCollected.Take(50))
            {
                logger?.LogInformation("Quick Scan: process {Pid} ({Name}) not collected: {Problem}.", p.ProcessId, p.Name, p.Problem);
            }
        }

        context.WaitForQueuedFiles();
        if (context.QuarantinedInPhase > 0)
        {
            context.Note($"{context.QuarantinedInPhase} running program file(s) were quarantined; a program keeps running until it exits or the PC restarts.");
        }
    }

    /// <summary>The distinct local image paths (first-seen order) and the processes whose image couldn't be collected.</summary>
    internal static (IReadOnlyList<string> Images, IReadOnlyList<ProcessImage> NotCollected) Summarize(IReadOnlyList<ProcessImage> snapshot)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var images = new List<string>();
        var notCollected = new List<ProcessImage>();
        foreach (var process in snapshot)
        {
            if (process.ImagePath is null)
            {
                notCollected.Add(process);
            }
            else if (PersistenceText.NormalizeLocalPath(process.ImagePath) is not { } path)
            {
                notCollected.Add(process with { Problem = "the image isn't on a local drive path" });
            }
            else if (seen.Add(path))
            {
                images.Add(path);
            }
        }

        return (images, notCollected);
    }
}
