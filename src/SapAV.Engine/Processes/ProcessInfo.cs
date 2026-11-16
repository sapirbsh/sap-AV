using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Processes;

namespace SapAV.Engine.Processes;

/// <summary>What a query-only look at a running process returns. Every field may be null (not readable).</summary>
public sealed record ProcessDetails(
    DateTimeOffset? StartTime,
    string? ImagePath,
    string? CommandLine,
    int? SessionId,
    string? UserSid,
    ProcessIntegrityLevel IntegrityLevel);

/// <summary>Whether a process instance (PID + start time) still runs.</summary>
public enum ProcessLiveness
{
    /// <summary>No process with that PID, it has exited, or the PID now belongs to a process with another start time.</summary>
    Gone,

    /// <summary>The same process instance is still running.</summary>
    Running,

    /// <summary>It exists but couldn't be checked.</summary>
    Unknown,
}

/// <summary>Reads <see cref="ProcessDetails"/> of a live process. Never throws; null when the process can't be opened. Faked in tests.</summary>
public interface IProcessInfoReader
{
    ProcessDetails? TryRead(int processId);

    /// <summary>
    /// Whether the process with this PID and start time still runs (E8 review H1: a stop event for a running process is forged;
    /// M4: pruning stale table entries). A null <paramref name="startTime"/> matches any instance with the PID.
    /// </summary>
    ProcessLiveness CheckLiveness(int processId, DateTimeOffset? startTime);
}

/// <summary>One row of the running-process snapshot (Toolhelp): PID, parent PID and the short exe name.</summary>
public sealed record RunningProcessEntry(int ProcessId, int ParentProcessId, string ExeName);

/// <summary>Lists the running processes. Never throws (empty on failure). Faked in tests.</summary>
public interface IRunningProcessSnapshot
{
    IReadOnlyList<RunningProcessEntry> Take();
}

/// <summary>
/// The real <see cref="IProcessInfoReader"/>: <c>OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)</c>, then creation time,
/// <c>QueryFullProcessImageNameW</c>, the command line (<c>NtQueryInformationProcess</c> class 60, Windows 8.1+), the session
/// and the token's user and integrity level (<c>TOKEN_QUERY</c>). Query-only: nothing is suspended, stopped or written, and
/// the target's memory is read only by the kernel's own command-line query. The command line is the process's own,
/// attacker-chosen text: it is length-checked here and sanitized by <see cref="ProcessText"/>.
/// </summary>
public sealed class NativeProcessInfoReader : IProcessInfoReader
{
    public static NativeProcessInfoReader Instance { get; } = new();

    public ProcessDetails? TryRead(int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        using var process = ProcessNative.OpenProcess(ProcessNative.ProcessQueryLimitedInformation, false, (uint)processId);
        if (process.IsInvalid)
        {
            return null;
        }

        DateTimeOffset? start = ProcessNative.GetProcessTimes(process, out long creation, out _, out _, out _) && creation > 0
            ? DateTimeOffset.FromFileTime(creation).ToUniversalTime()
            : null;
        int? session = ProcessNative.ProcessIdToSessionId((uint)processId, out uint s) ? (int)s : null;
        var (sid, integrity) = ReadToken(process);
        return new ProcessDetails(start, ReadImagePath(process), ReadCommandLine(process), session, sid, integrity);
    }

    public ProcessLiveness CheckLiveness(int processId, DateTimeOffset? startTime)
    {
        if (processId <= 0)
        {
            return ProcessLiveness.Unknown; // Idle / System: never "gone"
        }

        using var process = ProcessNative.OpenProcess(ProcessNative.ProcessQueryLimitedInformation | ProcessNative.Synchronize, false, (uint)processId);
        if (process.IsInvalid)
        {
            // ERROR_INVALID_PARAMETER: no such PID (its process object is gone). Anything else (access denied) is not proof.
            return Marshal.GetLastPInvokeError() == ProcessNative.ErrorInvalidParameter ? ProcessLiveness.Gone : ProcessLiveness.Unknown;
        }

        if (startTime is { } expected)
        {
            if (!ProcessNative.GetProcessTimes(process, out long creation, out _, out _, out _) || creation <= 0)
            {
                return ProcessLiveness.Unknown;
            }

            if ((DateTimeOffset.FromFileTime(creation) - expected).Duration() > KernelProcessEventMapper.StartTimeTolerance)
            {
                return ProcessLiveness.Gone; // the PID was reused: the instance asked about is gone
            }
        }

        return ProcessNative.WaitForSingleObject(process, 0) switch
        {
            ProcessNative.WaitObject0 => ProcessLiveness.Gone, // exited; only open handles keep the object around
            ProcessNative.WaitTimeout => ProcessLiveness.Running,
            _ => ProcessLiveness.Unknown,
        };
    }

    private static string? ReadImagePath(SafeProcessHandle process)
    {
        var buffer = ArrayPool<char>.Shared.Rent(32768);
        try
        {
            uint size = 32768;
            return ProcessNative.QueryFullProcessImageNameW(process, 0, buffer, ref size) && size > 0 && size <= 32768
                ? new string(buffer, 0, (int)size)
                : null;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(buffer);
        }
    }

    private static unsafe string? ReadCommandLine(SafeProcessHandle process)
    {
        // Windows caps a command line at 32,767 characters; the buffer is a UNICODE_STRING header plus the text.
        const int MaxBytes = 70_000;
        int status = ProcessNative.NtQueryInformationProcess(process, ProcessNative.ProcessCommandLineInformation, null, 0, out int needed);
        if (needed <= 0 || needed > MaxBytes || status is not (ProcessNative.StatusInfoLengthMismatch or ProcessNative.StatusBufferTooSmall))
        {
            return null;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(needed);
        try
        {
            fixed (byte* p = buffer)
            {
                if (ProcessNative.NtQueryInformationProcess(process, ProcessNative.ProcessCommandLineInformation, p, needed, out _) != 0)
                {
                    return null;
                }

                return CommandLineFromBuffer(buffer.AsSpan(0, needed), (nint)p);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// The text of the UNICODE_STRING at the start of <paramref name="buffer"/> (mapped at <paramref name="baseAddress"/>), or null
    /// when its pointer or length doesn't lie inside the buffer. Never reads outside the buffer.
    /// </summary>
    internal static string? CommandLineFromBuffer(ReadOnlySpan<byte> buffer, nint baseAddress)
    {
        int headerSize = nint.Size == 8 ? 16 : 8;
        if (buffer.Length < headerSize)
        {
            return null;
        }

        int length = BitConverter.ToUInt16(buffer);
        long pointer = nint.Size == 8 ? BitConverter.ToInt64(buffer[8..]) : BitConverter.ToInt32(buffer[4..]);
        if (length == 0)
        {
            return string.Empty;
        }

        long offset = pointer - baseAddress;
        if (length % 2 != 0 || offset < headerSize || offset > buffer.Length || length > buffer.Length - offset)
        {
            return null;
        }

        return System.Text.Encoding.Unicode.GetString(buffer.Slice((int)offset, length));
    }

    private static (string? Sid, ProcessIntegrityLevel Integrity) ReadToken(SafeProcessHandle process)
    {
        if (!ProcessNative.OpenProcessToken(process, ProcessNative.TokenQuery, out var token))
        {
            return (null, ProcessIntegrityLevel.Unknown);
        }

        using (token)
        {
            string? user = ReadTokenSid(token, ProcessNative.TokenUserClass);
            string? label = ReadTokenSid(token, ProcessNative.TokenIntegrityLevelClass);
            return (ProcessText.Sid(user), IntegrityFromLabelSid(label));
        }
    }

    /// <summary>TOKEN_USER and TOKEN_MANDATORY_LABEL both start with a SID_AND_ATTRIBUTES whose first field is the SID pointer.</summary>
    private static string? ReadTokenSid(SafeAccessTokenHandle token, int infoClass)
    {
        ProcessNative.GetTokenInformation(token, infoClass, 0, 0, out int needed);
        if (needed <= 0 || needed > 4096)
        {
            return null;
        }

        nint buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!ProcessNative.GetTokenInformation(token, infoClass, buffer, needed, out _))
            {
                return null;
            }

            nint sid = Marshal.ReadIntPtr(buffer);
            return sid == 0 ? null : new SecurityIdentifier(sid).Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Maps a mandatory label SID (S-1-16-RID) to an integrity level.</summary>
    internal static ProcessIntegrityLevel IntegrityFromLabelSid(string? labelSid)
    {
        const string Prefix = "S-1-16-";
        if (labelSid is null || !labelSid.StartsWith(Prefix, StringComparison.Ordinal)
            || !uint.TryParse(labelSid.AsSpan(Prefix.Length), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out uint rid))
        {
            return ProcessIntegrityLevel.Unknown;
        }

        return rid switch
        {
            < 0x1000 => ProcessIntegrityLevel.Untrusted,
            < 0x2000 => ProcessIntegrityLevel.Low,
            < 0x2100 => ProcessIntegrityLevel.Medium,
            < 0x3000 => ProcessIntegrityLevel.MediumPlus,
            < 0x4000 => ProcessIntegrityLevel.High,
            < 0x5000 => ProcessIntegrityLevel.System,
            _ => ProcessIntegrityLevel.Protected,
        };
    }
}

/// <summary>The real <see cref="IRunningProcessSnapshot"/>: one Toolhelp process snapshot (no process is opened here).</summary>
public sealed class ToolhelpProcessSnapshot : IRunningProcessSnapshot
{
    public static ToolhelpProcessSnapshot Instance { get; } = new();

    /// <summary>Upper bound on rows read (a machine runs a few hundred processes).</summary>
    internal const int MaxEntries = 65536;

    public IReadOnlyList<RunningProcessEntry> Take()
    {
        using var snapshot = ProcessNative.CreateToolhelp32Snapshot(ProcessNative.Th32csSnapProcess, 0);
        if (snapshot.IsInvalid)
        {
            return [];
        }

        var entries = new List<RunningProcessEntry>(512);
        var entry = new ProcessNative.ProcessEntry32W { Size = (uint)Marshal.SizeOf<ProcessNative.ProcessEntry32W>() };
        bool ok = ProcessNative.Process32FirstW(snapshot, ref entry);
        while (ok && entries.Count < MaxEntries)
        {
            entries.Add(new RunningProcessEntry((int)entry.ProcessId, (int)entry.ParentProcessId, entry.ExeFile ?? string.Empty));
            ok = ProcessNative.Process32NextW(snapshot, ref entry);
        }

        return entries;
    }
}

/// <summary>Win32 / native calls for the process event source (E8). Query-only rights everywhere.</summary>
internal static unsafe class ProcessNative
{
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint Synchronize = 0x00100000;
    public const int ErrorInvalidParameter = 87;
    public const uint WaitObject0 = 0;
    public const uint WaitTimeout = 0x102;
    public const uint TokenQuery = 0x0008;
    public const int TokenUserClass = 1;
    public const int TokenIntegrityLevelClass = 25;
    public const int ProcessCommandLineInformation = 60;
    public const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    public const int StatusBufferTooSmall = unchecked((int)0xC0000023);
    public const uint Th32csSnapProcess = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ProcessEntry32W
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string? ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] exeName, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, void* info, int length, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, nint info, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32FirstW(SafeFileHandle snapshot, ref ProcessEntry32W entry);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32NextW(SafeFileHandle snapshot, ref ProcessEntry32W entry);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDeviceW(string deviceName, [Out] char[] targetPath, uint max);
}
