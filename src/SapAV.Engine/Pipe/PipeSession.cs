using SapAV.Core.Pipe;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Pipe;

/// <summary>Where a session's events go (the connection's bounded event queue). Must never block.</summary>
internal interface IPipeEventSink
{
    /// <summary>Queues an event; false if it was dropped (queue full or connection closing).</summary>
    bool TryPost(PipeEventKind kind, object body);
}

/// <summary>The state of one client connection: its identity, Hello, and its job subscriptions.</summary>
internal sealed class PipeSession(IClientIdentity identity, IPipeEventSink sink) : IDisposable
{
    private readonly Lock _lock = new();
    private readonly Dictionary<Guid, Action> _subscriptions = [];
    private bool _disposed;

    public IClientIdentity Identity { get; } = identity ?? throw new ArgumentNullException(nameof(identity));

    public bool HelloDone { get; set; }

    public bool HasSubscriptions
    {
        get
        {
            lock (_lock)
            {
                return _subscriptions.Count > 0;
            }
        }
    }

    /// <summary>Streams the job's state, progress and file results to this session. False if the cap is reached.</summary>
    public bool Subscribe(ScanJob job, int maxSubscriptions)
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return false;
            }

            if (_subscriptions.ContainsKey(job.Id))
            {
                return true;
            }

            if (_subscriptions.Count >= maxSubscriptions)
            {
                return false;
            }

            Action<ScanJobStateChange> state = change =>
            {
                sink.TryPost(PipeEventKind.JobState, new JobStateEvent(change.JobId, PipeMapping.Map(change.From), PipeMapping.Map(change.To), change.Timestamp));
                if (ScanJobStateMachine.IsTerminal(change.To))
                {
                    Unsubscribe(job.Id); // nothing more will come; frees the slot
                }
            };
            Action<ScanJobProgress> progress = p => sink.TryPost(PipeEventKind.JobProgress, PipeMapping.Progress(p));
            Action<int, ScanJobFileResult> file = (id, r) => sink.TryPost(PipeEventKind.JobFileResult, new JobFileResultEvent(job.Id, PipeMapping.Result(id, r, Identity.IsAdmin)));
            job.StateChanged += state;
            job.ProgressChanged += progress;
            job.FileRecorded += file;
            _subscriptions[job.Id] = () =>
            {
                job.StateChanged -= state;
                job.ProgressChanged -= progress;
                job.FileRecorded -= file;
            };
            return true;
        }
    }

    public bool Unsubscribe(Guid jobId)
    {
        Action? remove;
        lock (_lock)
        {
            if (!_subscriptions.Remove(jobId, out remove))
            {
                return false;
            }
        }

        remove();
        return true;
    }

    /// <summary>Detaches every subscription (the connection ended); the identity is disposed too.</summary>
    public void Dispose()
    {
        Action[] removes;
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            removes = [.. _subscriptions.Values];
            _subscriptions.Clear();
        }

        foreach (var remove in removes)
        {
            remove();
        }

        Identity.Dispose();
    }
}
