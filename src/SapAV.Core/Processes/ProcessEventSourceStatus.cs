namespace SapAV.Core.Processes;

/// <summary>The health of an <see cref="IProcessEventSource"/>.</summary>
public enum ProcessEventSourceHealth
{
    /// <summary>Not started yet (or stopped): no events are produced.</summary>
    Stopped,

    /// <summary>Receiving events.</summary>
    Running,

    /// <summary>
    /// Receiving events, but the operating system reported events lost before they reached the source (e.g. ETW buffers
    /// overflowed). Process chains may have gaps; see <see cref="ProcessEventSourceStatus.LostEvents"/>.
    /// </summary>
    LostEvents,

    /// <summary>The source can't run on this machine or failed (no ETW session could be created, the session died, …).</summary>
    Unavailable,

    /// <summary>The source needs administrator or SYSTEM rights and doesn't have them.</summary>
    AccessDenied,
}

/// <summary>A point-in-time view of an <see cref="IProcessEventSource"/>.</summary>
/// <param name="Health">The current health.</param>
/// <param name="Detail">A short, safe explanation (no secrets), or null.</param>
/// <param name="EventsReceived">Events accepted from the operating system and published (pre-existing entries included).</param>
/// <param name="LostEvents">Events the operating system reported as lost before delivery (ETW-level loss).</param>
/// <param name="DroppedEvents">Events dropped because a subscriber's buffer was full (oldest first), over all subscribers.</param>
/// <param name="SessionName">The OS session name, when there is one (e.g. the ETW session), for diagnostics.</param>
public sealed record ProcessEventSourceStatus(
    ProcessEventSourceHealth Health,
    string? Detail,
    long EventsReceived,
    long LostEvents,
    long DroppedEvents,
    string? SessionName = null)
{
    public static ProcessEventSourceStatus NotStarted { get; } = new(ProcessEventSourceHealth.Stopped, "not started", 0, 0, 0);

    /// <summary>True while events flow (<see cref="ProcessEventSourceHealth.Running"/> or <see cref="ProcessEventSourceHealth.LostEvents"/>).</summary>
    public bool IsReceiving => Health is ProcessEventSourceHealth.Running or ProcessEventSourceHealth.LostEvents;
}
