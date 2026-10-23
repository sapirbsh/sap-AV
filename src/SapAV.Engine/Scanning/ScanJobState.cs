namespace SapAV.Engine.Scanning;

/// <summary>Lifecycle of a scan job. B4 streams every change (<see cref="ScanJob.StateChanged"/>).</summary>
public enum ScanJobState
{
    /// <summary>Created, not started.</summary>
    Created,

    Running,

    /// <summary>Pause requested: files already being scanned finish, nothing new starts.</summary>
    Pausing,

    /// <summary>Every job thread is parked; progress stops until resumed.</summary>
    Paused,

    /// <summary>Cancel requested: in-flight scans are cancelled, the job is ending.</summary>
    Cancelling,

    /// <summary>Every enumerated file was handled.</summary>
    Completed,

    /// <summary>Cancelled by the caller; the results so far are kept.</summary>
    Cancelled,

    /// <summary>The job's time budget ran out (review A L5); the results so far are kept.</summary>
    TimedOut,

    /// <summary>An unexpected engine error ended the job; the results so far are kept.</summary>
    Failed,
}

/// <summary>The allowed <see cref="ScanJobState"/> transitions.</summary>
public static class ScanJobStateMachine
{
    private static readonly Dictionary<ScanJobState, ScanJobState[]> Allowed = new()
    {
        [ScanJobState.Created] = [ScanJobState.Running, ScanJobState.Cancelled],
        [ScanJobState.Running] = [ScanJobState.Pausing, ScanJobState.Cancelling, ScanJobState.Completed, ScanJobState.TimedOut, ScanJobState.Failed],
        [ScanJobState.Pausing] = [ScanJobState.Paused, ScanJobState.Running, ScanJobState.Cancelling, ScanJobState.Completed, ScanJobState.TimedOut, ScanJobState.Failed],
        [ScanJobState.Paused] = [ScanJobState.Running, ScanJobState.Cancelling, ScanJobState.Completed, ScanJobState.Failed],
        [ScanJobState.Cancelling] = [ScanJobState.Cancelled, ScanJobState.Failed],
        [ScanJobState.Completed] = [],
        [ScanJobState.Cancelled] = [],
        [ScanJobState.TimedOut] = [],
        [ScanJobState.Failed] = [],
    };

    public static bool CanTransition(ScanJobState from, ScanJobState to) =>
        Allowed.TryGetValue(from, out var targets) && Array.IndexOf(targets, to) >= 0;

    public static bool IsTerminal(ScanJobState state) => Allowed.TryGetValue(state, out var targets) && targets.Length == 0;
}
