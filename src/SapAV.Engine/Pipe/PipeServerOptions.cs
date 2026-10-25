namespace SapAV.Engine.Pipe;

/// <summary>Engine pipe settings (<c>appsettings.json</c> section <c>Pipe</c>).</summary>
public sealed class PipeServerOptions
{
    public const string SectionName = "Pipe";

    /// <summary>Connections served at once (the pipe's instance limit is one more: the listening instance). Connections are async.</summary>
    public int MaxClients { get; set; } = 64;

    /// <summary>
    /// Connections not identified yet (before their first frame arrived), review B4 M1: anonymous slot exhaustion is capped
    /// below <see cref="MaxClients"/>, so identified users keep slots. Default 32 (half of the default MaxClients).
    /// </summary>
    public int MaxUnidentifiedConnections { get; set; } = 32;

    /// <summary>The cap in effect (never more than <see cref="MaxClients"/>).</summary>
    internal int EffectiveMaxUnidentified => Math.Min(MaxUnidentifiedConnections, MaxClients);

    /// <summary>Connections one user (SID) may hold at once.</summary>
    public int MaxConnectionsPerUser { get; set; } = 4;

    /// <summary>Time for a new connection to send its first frame and complete Hello (short: unidentified connections hold slots).</summary>
    public TimeSpan HelloTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>A connection with no request and no subscription for this long is closed.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The idle limit for a connection with job subscriptions (review B4 L6): long, since a GUI may only listen, but finite,
    /// so a subscription can't hold a connection slot forever. A client resets it with any request (e.g. GetStatus).
    /// </summary>
    public TimeSpan SubscribedIdleTimeout { get; set; } = TimeSpan.FromHours(8);

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

    /// <summary>
    /// Review B H3: a standard user's unfinished jobs are cancelled once that user has had no connection to the engine for
    /// this long (nobody is left to watch, pause or cancel them, and they hold a job slot).
    /// </summary>
    public TimeSpan OrphanJobTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Job subscriptions per connection.</summary>
    public int MaxSubscriptionsPerConnection { get; set; } = 8;

    /// <summary>Events waiting to be written per connection; further events are dropped and reported (EventsDropped).</summary>
    public int EventQueueCapacity { get; set; } = 512;

    /// <summary>Requests per second per user (token bucket refill), shared by all of the user's connections.</summary>
    public double RequestsPerSecond { get; set; } = 20;

    /// <summary>Request burst per user (token bucket size).</summary>
    public int RequestBurst { get; set; } = 40;

    /// <summary>
    /// Section B M1: QuarantineFromResult requests per minute per standard user (token bucket refill; administrators are not
    /// limited). Each one also counts against the user's quarantine quota (<c>Quarantine:MaxItemsPerRequester</c> / bytes).
    /// </summary>
    public double QuarantineRequestsPerMinute { get; set; } = 10;

    /// <summary>QuarantineFromResult burst per standard user (token bucket size).</summary>
    public int QuarantineRequestBurst { get; set; } = 10;

    /// <summary>Test seam: the pipe name. Internal so configuration can't move the engine's pipe.</summary>
    internal string PipeName { get; set; } = Core.Pipe.PipeProtocol.PipeName;

    /// <exception cref="ArgumentOutOfRangeException">A value is outside its range.</exception>
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxClients, 1, nameof(MaxClients));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(MaxClients, 254, nameof(MaxClients));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxUnidentifiedConnections, 1, nameof(MaxUnidentifiedConnections));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxConnectionsPerUser, 1, nameof(MaxConnectionsPerUser));
        ArgumentOutOfRangeException.ThrowIfLessThan(HelloTimeout, TimeSpan.FromMilliseconds(10), nameof(HelloTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(IdleTimeout, TimeSpan.FromMilliseconds(10), nameof(IdleTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(SubscribedIdleTimeout, TimeSpan.FromMilliseconds(10), nameof(SubscribedIdleTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(ReadTimeout, TimeSpan.FromMilliseconds(10), nameof(ReadTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(WriteTimeout, TimeSpan.FromMilliseconds(10), nameof(WriteTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingJobsPerUser, 1, nameof(MaxPendingJobsPerUser));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxActiveJobsPerUser, 1, nameof(MaxActiveJobsPerUser));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxPendingJobsTotal, 1, nameof(MaxPendingJobsTotal));
        ArgumentOutOfRangeException.ThrowIfLessThan(PendingJobExpiry, TimeSpan.FromMilliseconds(10), nameof(PendingJobExpiry));
        ArgumentOutOfRangeException.ThrowIfLessThan(OrphanJobTimeout, TimeSpan.FromMilliseconds(10), nameof(OrphanJobTimeout));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxSubscriptionsPerConnection, 1, nameof(MaxSubscriptionsPerConnection));
        ArgumentOutOfRangeException.ThrowIfLessThan(EventQueueCapacity, 1, nameof(EventQueueCapacity));
        ArgumentOutOfRangeException.ThrowIfLessThan(RequestsPerSecond, 0.01, nameof(RequestsPerSecond));
        ArgumentOutOfRangeException.ThrowIfLessThan(RequestBurst, 1, nameof(RequestBurst));
        ArgumentOutOfRangeException.ThrowIfLessThan(QuarantineRequestsPerMinute, 0.01, nameof(QuarantineRequestsPerMinute));
        ArgumentOutOfRangeException.ThrowIfLessThan(QuarantineRequestBurst, 1, nameof(QuarantineRequestBurst));
        ArgumentException.ThrowIfNullOrWhiteSpace(PipeName, nameof(PipeName));
    }
}
