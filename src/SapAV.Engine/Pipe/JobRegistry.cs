using System.Security.Principal;
using SapAV.Core.Pipe;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Pipe;

/// <summary>
/// Who created which scan job over the pipe, and the per-user job caps (B4, review B3 L5). A client sees and controls only
/// jobs created by its own user SID (and, for a job an administrator created, only from an administrator client: a
/// non-elevated process of the same user can't see or control it, review B4 M3), unless it is an administrator; jobs the
/// engine created itself (no owner) are visible
/// to administrators only.
/// </summary>
internal sealed class JobRegistry(IScanJobService jobs, PipeServerOptions options, TimeProvider time)
{
    private readonly Lock _lock = new();
    private readonly Dictionary<Guid, Owner> _owners = [];

    /// <param name="CreatorIsAdmin">Review B4 M3: an elevated session's jobs stay hidden from the same user's non-elevated processes.</param>
    private sealed record Owner(SecurityIdentifier User, bool CreatorIsAdmin, object Session, DateTimeOffset CreatedAt, ClientScanAccess? Access)
    {
        public bool IsVisibleTo(IClientIdentity client) => User == client.User && (client.IsAdmin || !CreatorIsAdmin);
    }

    /// <summary>The job, if it exists and <paramref name="client"/> may see it (both cases look the same to the client).</summary>
    public ScanJob? Find(IClientIdentity client, Guid jobId)
    {
        var job = jobs.Get(jobId);
        return job is not null && CanSee(client, job) ? job : null;
    }

    public bool CanSee(IClientIdentity client, ScanJob job)
    {
        if (client.IsAdmin)
        {
            return true;
        }

        lock (_lock)
        {
            return _owners.TryGetValue(job.Id, out var owner) && owner.IsVisibleTo(client);
        }
    }

    public bool IsOwner(IClientIdentity client, Guid jobId)
    {
        lock (_lock)
        {
            return _owners.TryGetValue(jobId, out var owner) && owner.IsVisibleTo(client);
        }
    }

    public IReadOnlyList<ScanJob> Visible(IClientIdentity client) => jobs.List().Where(j => CanSee(client, j)).ToArray();

    /// <summary>
    /// Creates a job for <paramref name="client"/> if the caps allow it (checked and registered under one lock, so
    /// concurrent connections of one user can't overshoot). <paramref name="access"/> is owned by the registry from here on.
    /// </summary>
    public (ScanJob? Job, PipeStatus Status, string Error) TryCreate(
        IClientIdentity client, object session, ScanJobRequest request, ClientScanAccess? access)
    {
        lock (_lock)
        {
            PruneLocked();
            var mine = _owners.Where(o => o.Value.User == client.User).Select(o => jobs.Get(o.Key)).OfType<ScanJob>().ToArray();
            int pendingAll = _owners.Keys.Select(jobs.Get).Count(j => j?.State == ScanJobState.Created);
            string? refusal =
                mine.Count(j => j.State == ScanJobState.Created) >= options.MaxPendingJobsPerUser
                    ? $"You already have {options.MaxPendingJobsPerUser} scan job(s) that were created but not started."
                : mine.Count(j => !ScanJobStateMachine.IsTerminal(j.State)) >= options.MaxActiveJobsPerUser
                    ? $"You already have {options.MaxActiveJobsPerUser} unfinished scan job(s)."
                : pendingAll >= options.MaxPendingJobsTotal
                    ? "Too many scan jobs are waiting to be started; try again later."
                : null;
            if (refusal is not null)
            {
                access?.Dispose();
                return (null, PipeStatus.LimitReached, refusal);
            }

            ScanJob job;
            try
            {
                job = jobs.Create(request with { Access = access });
            }
            catch (ArgumentException ex)
            {
                access?.Dispose();
                return (null, PipeStatus.BadRequest, Core.Text.SafeText.Display(ex.Message, 300));
            }

            _owners[job.Id] = new Owner(client.User, client.IsAdmin, session, time.GetUtcNow(), access);
            if (access is not null)
            {
                job.StateChanged += change =>
                {
                    if (ScanJobStateMachine.IsTerminal(change.To))
                    {
                        access.Dispose(); // every job thread has exited by now
                    }
                };
            }

            return (job, PipeStatus.Ok, string.Empty);
        }
    }

    /// <summary>The connection ended: its created-but-never-started jobs are cancelled (review B3 L5).</summary>
    public void CancelPendingOf(object session)
    {
        Guid[] ids;
        lock (_lock)
        {
            ids = _owners.Where(o => ReferenceEquals(o.Value.Session, session)).Select(o => o.Key).ToArray();
        }

        foreach (var id in ids)
        {
            if (jobs.Get(id) is { State: ScanJobState.Created })
            {
                jobs.Cancel(id);
            }
        }
    }

    /// <summary>Cancels expired pending jobs and forgets jobs the service no longer keeps.</summary>
    public void Prune()
    {
        lock (_lock)
        {
            PruneLocked();
        }
    }

    private void PruneLocked()
    {
        var now = time.GetUtcNow();
        foreach (var (id, owner) in _owners.ToArray())
        {
            var job = jobs.Get(id);
            if (job is null)
            {
                owner.Access?.Dispose();
                _owners.Remove(id);
            }
            else if (job.State == ScanJobState.Created && now - owner.CreatedAt > options.PendingJobExpiry)
            {
                jobs.Cancel(id);
            }
        }
    }
}
