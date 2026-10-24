namespace SapAV.Engine.Pipe;

/// <summary>Engine pipe settings (<c>appsettings.json</c> section <c>Pipe</c>).</summary>
public sealed class PipeServerOptions
{
    public const string SectionName = "Pipe";

    /// <summary>Connections served at once (also the pipe's instance limit).</summary>
    public int MaxClients { get; set; } = 16;

    /// <summary>Connections one user (SID) may hold at once.</summary>
    public int MaxConnectionsPerUser { get; set; } = 4;

    /// <summary>Time for a new connection to complete Hello.</summary>
    public TimeSpan HelloTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>A connection with no request and no subscription for this long is closed.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Once a frame header arrived, its body must arrive within this (slow-sender protection).</summary>
    public TimeSpan ReadTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>A frame the client doesn't read within this ends the connection.</summary>
    public TimeSpan WriteTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Jobs one user may have created but not started.</summary>
    public int MaxPendingJobsPerUser { get; set; } = 2;

    /// <summary>Unfinished jobs (created, running, paused) one user may have.</summary>
    public int MaxActiveJobsPerUser { get; set; } = 4;

    /// <summary>Created-but-not-started jobs of all users together (review B3 L5).</summary>
    public int MaxPendingJobsTotal { get; set; } = 8;

    /// <summary>A created job not started within this is cancelled (review B3 L5).</summary>
    public TimeSpan PendingJobExpiry { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Job subscriptions per connection.</summary>
    public int MaxSubscriptionsPerConnection { get; set; } = 8;

    /// <summary>Events waiting to be written per connection; further events are dropped and reported (EventsDropped).</summary>
    public int EventQueueCapacity { get; set; } = 512;

    /// <summary>Requests per second per user (token bucket refill), shared by all of the user's connections.</summary>
    public double RequestsPerSecond { get; set; } = 20;

    /// <summary>Request burst per user (token bucket size).</summary>
    public int RequestBurst { get; set; } = 40;

    /// <summary>Test seam: the pipe name. Internal so configuration can't move the engine's pipe.</summary>
    internal string PipeName { get; set; } = Core.Pipe.PipeProtocol.PipeName;

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxClients, 1, nameof(MaxClients));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxClients, 254, nameof(MaxClients));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxConnectionsPerUser, 1, nameof(MaxConnectionsPerUser));
        ArgumentOutOfRangeException.ThrowIfLessThan(HelloTimeout, TimeSpan.FromMilliseconds(10), nameof(HelloTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(IdleTimeout, TimeSpan.FromMilliseconds(10), nameof(IdleTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(ReadTimeout, TimeSpan.FromMilliseconds(10), nameof(ReadTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(WriteTimeout, TimeSpan.FromMilliseconds(10), nameof(WriteTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingJobsPerUser, 1, nameof(MaxPendingJobsPerUser));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxActiveJobsPerUser, 1, nameof(MaxActiveJobsPerUser));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingJobsTotal, 1, nameof(MaxPendingJobsTotal));
        ArgumentOutOfRangeException.ThrowIfLessThan(PendingJobExpiry, TimeSpan.FromMilliseconds(10), nameof(PendingJobExpiry));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxSubscriptionsPerConnection, 1, nameof(MaxSubscriptionsPerConnection));
        ArgumentOutOfRangeException.ThrowIfLessThan(EventQueueCapacity, 1, nameof(EventQueueCapacity));
        ArgumentOutOfRangeException.ThrowIfLessThan(RequestsPerSecond, 0.01, nameof(RequestsPerSecond));
        ArgumentOutOfRangeException.ThrowIfLessThan(RequestBurst, 1, nameof(RequestBurst));
        ArgumentException.ThrowIfNullOrWhiteSpace(PipeName, nameof(PipeName));
    }
}
