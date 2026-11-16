using SapAV.Core.Processes;

namespace SapAV.Engine.Processes;

/// <summary>
/// The fields of one Microsoft-Windows-Kernel-Process event, already pulled out of the ETW payload (event 1 ProcessStart /
/// event 2 ProcessStop). Everything is untrusted and may be missing.
/// </summary>
/// <param name="HeaderProcessId">The event header's process ID: the process that logged the event (the creator for a start,
/// the exiting process for a stop).</param>
/// <param name="ProcessId">The payload's subject process ID, or null when it is missing (such an event is rejected).</param>
public sealed record KernelProcessRecord(
    ProcessEventKind Kind,
    int HeaderProcessId,
    int? ProcessId,
    int? ParentProcessId,
    DateTimeOffset? CreateTime,
    int? SessionId,
    string? ImageName,
    DateTimeOffset Timestamp,
    int? ExitCode = null);

/// <summary>Why a <see cref="KernelProcessRecord"/> was dropped (E8 review H1 / L1).</summary>
public enum KernelProcessRejection
{
    None,

    /// <summary>The payload has no process ID or no creation time.</summary>
    Malformed,

    /// <summary>A start whose header (the creator) isn't the payload's parent, or a stop whose header isn't the exiting process.</summary>
    HeaderMismatch,

    /// <summary>A stop for a process instance that is still running.</summary>
    StillRunning,
}

/// <summary>
/// Validates and maps <see cref="KernelProcessRecord"/>s and snapshot rows to <see cref="ProcessEvent"/>s.
/// </summary>
/// <remarks>
/// <para>
/// <b>Forged events (E8 review H1).</b> Any user-mode process can register the Kernel-Process provider GUID and log events that
/// look like the kernel's into our session: a fake stop could hide a running miner, fake starts could forge a parent chain or
/// flood the stream. Checks: a start must be logged by its parent (header PID = payload ParentProcessID: the kernel logs it in
/// the creator's context), a stop by the exiting process (header PID = payload ProcessID), and a stop is accepted only if the
/// process instance is really gone. A second start for a known process is rejected by the hub. A forger can still log a
/// start that names itself as the parent; that is noise, not a hidden process. Rejected events are dropped and counted.
/// Known gap: a real start made with an explicit parent attribute (PPID spoofing) has a header that differs from the payload
/// parent, so it is rejected too and shows up only in the rejected count.
/// The spoof-proof long-term option is the SystemTraceProvider process events (kernel "system logger") in a private
/// system-logger session: only the kernel can log those, and they carry the command line too.
/// </para>
/// <para>
/// A start event has no command line, user or integrity level, so the live process is queried (<see cref="IProcessInfoReader"/>);
/// that answer is used only if its creation time matches the event's, so a PID that was already reused never lends another
/// process's details.
/// </para>
/// </remarks>
public sealed class KernelProcessEventMapper
{
    /// <summary>Largest difference between the event's and the live process's creation time that still counts as the same process.</summary>
    public static readonly TimeSpan StartTimeTolerance = TimeSpan.FromMilliseconds(1);

    private readonly IProcessInfoReader _info;
    private readonly Func<string?, string?> _toWin32;

    public KernelProcessEventMapper(IProcessInfoReader info, Func<string?, string?> toWin32)
    {
        _info = info ?? throw new ArgumentNullException(nameof(info));
        _toWin32 = toWin32 ?? throw new ArgumentNullException(nameof(toWin32));
    }

    /// <summary>The event for <paramref name="record"/>, or null with the reason it was rejected.</summary>
    public ProcessEvent? Map(KernelProcessRecord record, out KernelProcessRejection rejection)
    {
        ArgumentNullException.ThrowIfNull(record);
        rejection = Validate(record);
        if (rejection != KernelProcessRejection.None)
        {
            return null;
        }

        int pid = record.ProcessId!.Value;
        var (imageFromEvent, imageTruncated) = ProcessText.ImagePath(_toWin32(record.ImageName) ?? record.ImageName);
        if (record.Kind == ProcessEventKind.Stopped)
        {
            // The stop event's image name is the short kernel name; the hub completes the rest from the matching start.
            return new ProcessEvent(ProcessEventKind.Stopped, pid, record.ParentProcessId, record.CreateTime, imageFromEvent,
                null, false, record.SessionId, null, ProcessIntegrityLevel.Unknown, record.Timestamp, record.ExitCode, imageTruncated);
        }

        var details = SameProcess(record.CreateTime, _info.TryRead(pid));
        var (commandLine, truncated) = ProcessText.CommandLine(details?.CommandLine);
        var (livePath, livePathTruncated) = ProcessText.ImagePath(details?.ImagePath);
        return new ProcessEvent(ProcessEventKind.Started, pid, record.ParentProcessId, record.CreateTime,
            livePath ?? imageFromEvent, commandLine, truncated, record.SessionId ?? details?.SessionId,
            details?.UserSid, details?.IntegrityLevel ?? ProcessIntegrityLevel.Unknown, record.Timestamp, null,
            livePath is not null ? livePathTruncated : imageTruncated);
    }

    /// <summary>
    /// A pre-existing process from the start-up snapshot, or null when it should be left to the ETW stream: it started after
    /// <paramref name="sessionStartedAt"/> (its start event is on the way) or it no longer runs as the same instance.
    /// </summary>
    public ProcessEvent? MapExisting(RunningProcessEntry entry, DateTimeOffset sessionStartedAt, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var details = entry.ProcessId > 0 ? _info.TryRead(entry.ProcessId) : null;
        if (details?.StartTime is { } started && started >= sessionStartedAt)
        {
            return null;
        }

        var (commandLine, truncated) = ProcessText.CommandLine(details?.CommandLine);
        var (path, pathTruncated) = ProcessText.ImagePath(details?.ImagePath);
        if (path is null)
        {
            (path, pathTruncated) = ProcessText.ImagePath(entry.ExeName);
        }

        int? parent = entry.ProcessId == 0 ? null : entry.ParentProcessId;
        return new ProcessEvent(ProcessEventKind.Existing, entry.ProcessId, parent, details?.StartTime, path, commandLine, truncated,
            details?.SessionId, details?.UserSid, details?.IntegrityLevel ?? ProcessIntegrityLevel.Unknown, now, null, pathTruncated);
    }

    private KernelProcessRejection Validate(KernelProcessRecord record)
    {
        // L1: never fall back to the header PID; a real kernel event always carries both fields.
        if (record.ProcessId is not { } pid || pid <= 0 || record.CreateTime is null)
        {
            return KernelProcessRejection.Malformed;
        }

        if (record.Kind == ProcessEventKind.Started)
        {
            return record.ParentProcessId == record.HeaderProcessId ? KernelProcessRejection.None : KernelProcessRejection.HeaderMismatch;
        }

        if (record.HeaderProcessId != pid)
        {
            return KernelProcessRejection.HeaderMismatch;
        }

        return _info.CheckLiveness(pid, record.CreateTime) == ProcessLiveness.Running
            ? KernelProcessRejection.StillRunning
            : KernelProcessRejection.None;
    }

    private static ProcessDetails? SameProcess(DateTimeOffset? eventCreateTime, ProcessDetails? details)
    {
        if (details?.StartTime is not { } liveStart || eventCreateTime is not { } eventStart)
        {
            return null;
        }

        return (liveStart - eventStart).Duration() <= StartTimeTolerance ? details : null;
    }
}

/// <summary>Converts ETW payload values (as TraceEvent decodes them) to the types the record needs. Never throws.</summary>
public static class KernelProcessPayload
{
    public static int? ToInt32(object? value) => value switch
    {
        int i => i,
        uint u => unchecked((int)u),
        long l when l is >= int.MinValue and <= uint.MaxValue => unchecked((int)l),
        ulong ul when ul <= uint.MaxValue => unchecked((int)ul),
        ushort us => us,
        short s => s,
        _ => null,
    };

    /// <summary>A FILETIME field: TraceEvent gives a <see cref="DateTime"/> (usually local, from <c>FromFileTime</c>); raw integers are FILETIMEs.</summary>
    public static DateTimeOffset? ToUtc(object? value)
    {
        try
        {
            return value switch
            {
                DateTime { Ticks: 0 } => null,
                DateTime d when d.Kind == DateTimeKind.Utc => new DateTimeOffset(d),
                DateTime d => new DateTimeOffset(d.ToUniversalTime(), TimeSpan.Zero),
                DateTimeOffset o => o.ToUniversalTime(),
                long l when l > 0 => DateTimeOffset.FromFileTime(l).ToUniversalTime(),
                ulong ul when ul is > 0 and <= long.MaxValue => DateTimeOffset.FromFileTime((long)ul).ToUniversalTime(),
                _ => null,
            };
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
