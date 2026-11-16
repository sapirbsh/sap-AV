using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using SapAV.Core.Processes;

namespace SapAV.Engine.Processes;

/// <summary>A live ETW real-time session delivering Kernel-Process start/stop records. Faked in tests.</summary>
public interface IKernelProcessSession : IDisposable
{
    string Name { get; }

    /// <summary>Events the OS reports lost for this session so far; null when it can't be read.</summary>
    long? EventsLost { get; }

    /// <summary>Delivers records on the calling thread until the session is stopped. <paramref name="onRecord"/> must not throw.</summary>
    void Run(Action<KernelProcessRecord> onRecord);

    /// <summary>Stops the OS session (Run then returns). Idempotent, callable from any thread, never throws.</summary>
    void Stop();
}

/// <summary>Creates <see cref="IKernelProcessSession"/>s and manages sap-AV's ETW session names. Faked in tests.</summary>
public interface IKernelProcessSessionFactory
{
    /// <summary>True / false when the process can (not) control ETW sessions; null when unknown.</summary>
    bool? IsElevated();

    /// <summary>Names of the ETW sessions running on this machine (empty when they can't be listed).</summary>
    IReadOnlyList<string> GetActiveSessionNames();

    /// <summary>Stops the session with this name if it exists (a leftover from a crashed run). Never throws.</summary>
    bool StopSession(string name);

    /// <summary>Creates the session and enables the provider. Throws on failure (access denied, no resources, …); nothing leaks.</summary>
    IKernelProcessSession Create(string name, int bufferSizeMB);
}

/// <summary>The real factory: TraceEvent's <see cref="TraceEventSession"/> on Microsoft-Windows-Kernel-Process.</summary>
public sealed class TraceEventKernelProcessSessionFactory : IKernelProcessSessionFactory
{
    public static TraceEventKernelProcessSessionFactory Instance { get; } = new();

    public bool? IsElevated() => TraceEventSession.IsElevated();

    public IReadOnlyList<string> GetActiveSessionNames()
    {
        try
        {
            return [.. TraceEventSession.GetActiveSessionNames()];
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return [];
        }
    }

    public bool StopSession(string name)
    {
        try
        {
            using var existing = TraceEventSession.GetActiveSession(name);
            if (existing is null)
            {
                return false;
            }

            existing.StopOnDispose = true;
            return existing.Stop(noThrow: true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return false;
        }
    }

    public IKernelProcessSession Create(string name, int bufferSizeMB) => new TraceEventKernelProcessSession(name, bufferSizeMB);
}

/// <summary>
/// A real-time ETW session with only Microsoft-Windows-Kernel-Process (keyword WINEVENT_KEYWORD_PROCESS: process start and stop)
/// enabled. <see cref="TraceEventSessionOptions.Create"/> replaces a same-name session left by a crashed run, StopOnDispose is
/// on (the finalizer stops it too), and every live session is registered with <see cref="EtwSessionRegistry"/>, which stops
/// it on process exit or an unhandled exception. Only event metadata is read.
/// </summary>
internal sealed class TraceEventKernelProcessSession : IKernelProcessSession
{
    /// <summary>Microsoft-Windows-Kernel-Process.</summary>
    public static readonly Guid ProviderGuid = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    /// <summary>WINEVENT_KEYWORD_PROCESS: ProcessStart (1) and ProcessStop (2).</summary>
    public const ulong ProcessKeyword = 0x10;

    public const int ProcessStartId = 1;
    public const int ProcessStopId = 2;

    private readonly TraceEventSession _session;
    private int _stopped;

    public TraceEventKernelProcessSession(string name, int bufferSizeMB)
    {
        Name = name;
        _session = new TraceEventSession(name, TraceEventSessionOptions.Create)
        {
            StopOnDispose = true,
            BufferSizeMB = Math.Clamp(bufferSizeMB, 1, 64),
        };
        EtwSessionRegistry.Register(this);
        try
        {
            _session.EnableProvider(ProviderGuid, TraceEventLevel.Informational, ProcessKeyword);
        }
        catch
        {
            Stop();
            throw;
        }
    }

    public string Name { get; }

    public long? EventsLost
    {
        get
        {
            try
            {
                return Volatile.Read(ref _stopped) == 0 ? _session.EventsLost : null;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return null;
            }
        }
    }

    public void Run(Action<KernelProcessRecord> onRecord)
    {
        ArgumentNullException.ThrowIfNull(onRecord);
        var source = _session.Source;
        source.Dynamic.All += data =>
        {
            if (data.ProviderGuid != ProviderGuid)
            {
                return;
            }

            int id = (int)data.ID;
            if (id is ProcessStartId or ProcessStopId)
            {
                onRecord(Extract(data, id == ProcessStartId ? ProcessEventKind.Started : ProcessEventKind.Stopped));
            }
        };
        source.Process();
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0)
        {
            return;
        }

        EtwSessionRegistry.Unregister(this);
        try
        {
            _session.Stop(noThrow: true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Dispose below tries again.
        }

        try
        {
            _session.Dispose();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // best effort: the next start replaces a same-name session anyway
        }
    }

    public void Dispose() => Stop();

    /// <summary>The header's process ID is the logging thread's; the subject process is in the payload.</summary>
    private static KernelProcessRecord Extract(TraceEvent data, ProcessEventKind kind)
    {
        var timestamp = KernelProcessPayload.ToUtc(data.TimeStamp) ?? DateTimeOffset.UtcNow;
        int pid = KernelProcessPayload.ToInt32(data.PayloadByName("ProcessID")) ?? data.ProcessID;
        var create = KernelProcessPayload.ToUtc(data.PayloadByName("CreateTime"));
        var image = data.PayloadByName("ImageName") as string;
        if (kind == ProcessEventKind.Started)
        {
            return new KernelProcessRecord(kind, pid, KernelProcessPayload.ToInt32(data.PayloadByName("ParentProcessID")), create,
                KernelProcessPayload.ToInt32(data.PayloadByName("SessionID")), image, timestamp);
        }

        var exit = KernelProcessPayload.ToUtc(data.PayloadByName("ExitTime"));
        return new KernelProcessRecord(kind, pid, null, create, null, image, exit ?? timestamp,
            KernelProcessPayload.ToInt32(data.PayloadByName("ExitCode")));
    }
}

/// <summary>
/// Every ETW session this process owns, stopped on <see cref="AppDomain.ProcessExit"/> and on an unhandled exception, so a
/// crash that still runs managed shutdown code never leaks a kernel trace session. (A hard kill can't run anything: the next
/// start replaces the fixed-name session, and test sessions carry the owner's PID so orphans can be found.)
/// </summary>
internal static class EtwSessionRegistry
{
    private static readonly ConcurrentDictionary<IKernelProcessSession, byte> Sessions = new();
    private static int _hooked;

    public static int Count => Sessions.Count;

    public static void Register(IKernelProcessSession session)
    {
        if (Interlocked.Exchange(ref _hooked, 1) == 0)
        {
            AppDomain.CurrentDomain.ProcessExit += (_, _) => StopAll();
            AppDomain.CurrentDomain.UnhandledException += (_, _) => StopAll();
        }

        Sessions.TryAdd(session, 0);
    }

    public static void Unregister(IKernelProcessSession session) => Sessions.TryRemove(session, out _);

    public static void StopAll()
    {
        foreach (var session in Sessions.Keys)
        {
            try
            {
                session.Stop();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // keep stopping the others
            }
        }
    }
}

/// <summary>sap-AV ETW session names that carry an owner PID (<c>…-p1234-…</c>), for orphan cleanup after a hard kill.</summary>
public static class EtwSessionNames
{
    /// <summary>A unique name <c>{prefix}p{pid}-{suffix}</c> for a short-lived (test) session.</summary>
    public static string WithOwner(string prefix, int ownerPid, string suffix) =>
        string.Create(CultureInfo.InvariantCulture, $"{prefix}p{ownerPid}-{suffix}");

    /// <summary>The sessions under <paramref name="prefix"/> whose owner PID no longer runs.</summary>
    public static IReadOnlyList<string> FindOrphaned(IEnumerable<string> activeNames, string prefix, Func<int, bool> isAlive)
    {
        ArgumentNullException.ThrowIfNull(activeNames);
        ArgumentException.ThrowIfNullOrEmpty(prefix);
        ArgumentNullException.ThrowIfNull(isAlive);
        if (!prefix.StartsWith(ProcessEventSourceOptions.SessionNamePrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException("only sap-AV session names can be cleaned up", nameof(prefix));
        }

        var orphaned = new List<string>();
        foreach (var name in activeNames)
        {
            if (name is null || !name.StartsWith(prefix + "p", StringComparison.Ordinal))
            {
                continue;
            }

            var rest = name.AsSpan(prefix.Length + 1);
            int dash = rest.IndexOf('-');
            if (dash > 0 && int.TryParse(rest[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out int pid) && !isAlive(pid))
            {
                orphaned.Add(name);
            }
        }

        return orphaned;
    }
}
