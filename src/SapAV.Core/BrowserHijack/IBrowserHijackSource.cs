namespace SapAV.Core.BrowserHijack;

/// <summary>
/// Reads the proxy, PAC, WinHTTP and hosts settings a browser hijack changes (ROADMAP E6). Read-only by contract: an
/// implementation never changes a setting or the hosts file. The engine's implementation reads the registry and the hosts file
/// as SYSTEM; tests use <see cref="FixedBrowserHijackSource"/>.
/// </summary>
public interface IBrowserHijackSource
{
    /// <summary>
    /// Takes a snapshot. Never throws for a missing, denied or unreadable part: that is reported in the snapshot as an unknown
    /// state. Only cancellation of <paramref name="cancellationToken"/> throws <see cref="OperationCanceledException"/>.
    /// </summary>
    Task<BrowserHijackSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);
}

/// <summary>An <see cref="IBrowserHijackSource"/> that returns a given snapshot: the fake for rule and scan tests.</summary>
public sealed class FixedBrowserHijackSource(BrowserHijackSnapshot snapshot) : IBrowserHijackSource
{
    private volatile BrowserHijackSnapshot _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
    private int _calls;

    /// <summary>How many snapshots were taken.</summary>
    public int Calls => Volatile.Read(ref _calls);

    /// <summary>The snapshot returned from now on.</summary>
    public BrowserHijackSnapshot Snapshot
    {
        get => _snapshot;
        set => _snapshot = value ?? throw new ArgumentNullException(nameof(value));
    }

    public Task<BrowserHijackSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _calls);
        return Task.FromResult(_snapshot);
    }
}
