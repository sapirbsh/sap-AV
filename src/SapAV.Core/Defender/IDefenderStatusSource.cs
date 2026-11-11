namespace SapAV.Core.Defender;

/// <summary>
/// Reads Microsoft Defender's status and exclusions (ROADMAP E5). Read-only by contract: an implementation never changes
/// Defender's configuration. The engine's implementation reads WMI as SYSTEM; tests use <see cref="FixedDefenderStatusSource"/>.
/// </summary>
public interface IDefenderStatusSource
{
    /// <summary>
    /// Takes a snapshot. Never throws for an unavailable, missing, hung or access-denied Defender / WMI: that is reported in
    /// the snapshot. Only cancellation of <paramref name="cancellationToken"/> throws <see cref="OperationCanceledException"/>.
    /// </summary>
    Task<DefenderStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);
}

/// <summary>An <see cref="IDefenderStatusSource"/> that returns a given snapshot: the fake for rule and scan tests.</summary>
public sealed class FixedDefenderStatusSource(DefenderStatusSnapshot snapshot) : IDefenderStatusSource
{
    private volatile DefenderStatusSnapshot _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
    private int _calls;

    /// <summary>How many snapshots were taken.</summary>
    public int Calls => Volatile.Read(ref _calls);

    /// <summary>The snapshot returned from now on.</summary>
    public DefenderStatusSnapshot Snapshot
    {
        get => _snapshot;
        set => _snapshot = value ?? throw new ArgumentNullException(nameof(value));
    }

    public Task<DefenderStatusSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _calls);
        return Task.FromResult(_snapshot);
    }
}
