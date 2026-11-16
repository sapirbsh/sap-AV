using SapAV.Core.Processes;

namespace SapAV.Engine.Processes;

/// <summary>
/// The fields of one Microsoft-Windows-Kernel-Process event, already pulled out of the ETW payload (event 1 ProcessStart /
/// event 2 ProcessStop). Everything is untrusted and may be missing.
/// </summary>
public sealed record KernelProcessRecord(
    ProcessEventKind Kind,
    int ProcessId,
    int? ParentProcessId,
    DateTimeOffset? CreateTime,
    int? SessionId,
    string? ImageName,
    DateTimeOffset Timestamp,
    int? ExitCode = null);

/// <summary>
/// Maps <see cref="KernelProcessRecord"/>s and snapshot rows to <see cref="ProcessEvent"/>s. A start event has no command
/// line, user or integrity level, so the live process is queried (<see cref="IProcessInfoReader"/>); that answer is used only
/// if its creation time matches the event's, so a PID that was already reused never lends another process's details.
/// </summary>
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

    public ProcessEvent Map(KernelProcessRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var imageFromEvent = ProcessText.ImagePath(_toWin32(record.ImageName) ?? record.ImageName);
        if (record.Kind == ProcessEventKind.Stopped)
        {
            // The stop event's image name is the short kernel name; the hub completes the rest from the matching start.
            return new ProcessEvent(ProcessEventKind.Stopped, record.ProcessId, record.ParentProcessId, record.CreateTime, imageFromEvent,
                null, false, record.SessionId, null, ProcessIntegrityLevel.Unknown, record.Timestamp, record.ExitCode);
        }

        var details = SameProcess(record.CreateTime, _info.TryRead(record.ProcessId));
        var (commandLine, truncated) = ProcessText.CommandLine(details?.CommandLine);
        return new ProcessEvent(ProcessEventKind.Started, record.ProcessId, record.ParentProcessId, record.CreateTime,
            ProcessText.ImagePath(details?.ImagePath) ?? imageFromEvent, commandLine, truncated, record.SessionId ?? details?.SessionId,
            details?.UserSid, details?.IntegrityLevel ?? ProcessIntegrityLevel.Unknown, record.Timestamp);
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
        int? parent = entry.ProcessId == 0 ? null : entry.ParentProcessId;
        return new ProcessEvent(ProcessEventKind.Existing, entry.ProcessId, parent, details?.StartTime,
            ProcessText.ImagePath(details?.ImagePath) ?? ProcessText.ImagePath(entry.ExeName), commandLine, truncated,
            details?.SessionId, details?.UserSid, details?.IntegrityLevel ?? ProcessIntegrityLevel.Unknown, now);
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
