namespace SapAV.Core.Processes;

/// <summary>What a <see cref="ProcessEvent"/> reports.</summary>
public enum ProcessEventKind
{
    /// <summary>The process was already running when the source started (from the start-up snapshot, "pre-existing").</summary>
    Existing,

    /// <summary>The process started while the source was running.</summary>
    Started,

    /// <summary>The process exited.</summary>
    Stopped,
}

/// <summary>The mandatory integrity level of a process token. <see cref="Unknown"/> when it couldn't be read.</summary>
public enum ProcessIntegrityLevel
{
    Unknown,
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
}

/// <summary>
/// Identifies one process instance. A PID alone is reused by Windows; PID + start time (UTC) is not. A start time of
/// <see cref="DateTimeOffset.MinValue"/> means it couldn't be read (e.g. the Idle process); such keys only match each other.
/// </summary>
public readonly record struct ProcessKey(int ProcessId, DateTimeOffset StartTime)
{
    public override string ToString() => $"{ProcessId}@{StartTime.UtcDateTime:O}";
}

/// <summary>
/// One process start / stop / pre-existing record (ROADMAP E8). Only metadata: the engine reads event fields and query-only
/// process information, never file contents. Every string is untrusted (a process chooses its own command line, and its
/// image name can carry any character): strings are already sanitized by <see cref="ProcessText"/>, but consumers must still
/// treat them as attacker-controlled text.
/// </summary>
/// <param name="Kind">Start, stop or pre-existing.</param>
/// <param name="ProcessId">The PID.</param>
/// <param name="ParentProcessId">The parent PID the OS records for the process (the claimed parent), or null when unknown. A
/// process can be created with an explicit parent attribute (PPID spoofing, T1134.004), so when <paramref name="ParentMismatch"/>
/// is set this value is attacker-controlled and <paramref name="CreatorProcessId"/> is the real creator. The parent may have exited and its PID
/// may already be reused: match it with <see cref="ProcessTable.FindParent"/>, which checks the start times.</param>
/// <param name="StartTime">Process creation time (UTC), or null when unknown. With <paramref name="ProcessId"/> it forms the
/// <see cref="Key"/> that defeats PID reuse.</param>
/// <param name="ImagePath">Full Win32 path of the image, or null when unknown (a short name only when nothing better was
/// available). Capped by <see cref="ProcessText.MaxPathChars"/> (head and tail kept).</param>
/// <param name="CommandLine">The command line (raw text, control characters replaced, capped by <see cref="ProcessText"/>), or
/// null when it couldn't be read (e.g. the process exited before it could be queried).</param>
/// <param name="CommandLineTruncated">True when <paramref name="CommandLine"/> was capped (head and tail kept). A very long
/// command line is itself a signal.</param>
/// <param name="SessionId">Terminal Services session, or null when unknown.</param>
/// <param name="UserSid">The token user's SID string, or null when unknown.</param>
/// <param name="IntegrityLevel">The token's integrity level.</param>
/// <param name="Timestamp">When the event happened (stop: exit time; pre-existing: when the snapshot was taken).</param>
/// <param name="ExitCode">Exit code, for <see cref="ProcessEventKind.Stopped"/> only.</param>
/// <param name="ImagePathTruncated">True when <paramref name="ImagePath"/> was capped.</param>
/// <param name="CreatorProcessId">For a live start event: the process that really created it (the ETW header's PID, logged
/// by the kernel in the creator's context). Null for pre-existing entries and when unknown.</param>
/// <param name="ParentMismatch">True when the creator isn't the claimed parent (<paramref name="ParentProcessId"/>): a sign of
/// PPID spoofing (T1134.004) that the parent-child rules (G2a) should judge. Such a start is only accepted when the process
/// was verified to exist with the event's creation time.</param>
public sealed record ProcessEvent(
    ProcessEventKind Kind,
    int ProcessId,
    int? ParentProcessId,
    DateTimeOffset? StartTime,
    string? ImagePath,
    string? CommandLine,
    bool CommandLineTruncated,
    int? SessionId,
    string? UserSid,
    ProcessIntegrityLevel IntegrityLevel,
    DateTimeOffset Timestamp,
    int? ExitCode = null,
    bool ImagePathTruncated = false,
    int? CreatorProcessId = null,
    bool ParentMismatch = false)
{
    /// <summary>PID + start time: the identity of this process instance.</summary>
    public ProcessKey Key => new(ProcessId, StartTime?.ToUniversalTime() ?? DateTimeOffset.MinValue);

    /// <summary>True for entries from the start-up snapshot (already running when the source started).</summary>
    public bool IsPreExisting => Kind == ProcessEventKind.Existing;

    /// <summary>The file name of <see cref="ImagePath"/>, or null.</summary>
    public string? ImageName => string.IsNullOrEmpty(ImagePath) ? null : Path.GetFileName(ImagePath);
}
