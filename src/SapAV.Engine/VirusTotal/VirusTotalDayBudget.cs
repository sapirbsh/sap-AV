namespace SapAV.Engine.VirusTotal;

/// <summary>
/// Whose file the current scan is, for the VirusTotal per-owner budget (review D3 M3). The scan pipeline sets it around the
/// broker call (<see cref="Scanning.ScanBudget.Owner"/>, the D1 owner key: the watched folder's user, or a machine-wide
/// folder's file owner; null = the engine's own share). It flows with the async call into the online lookup, so the broker
/// and the Core scanner don't need to know about it.
/// </summary>
internal static class OnlineLookupOwner
{
    private static readonly AsyncLocal<string?> CurrentOwner = new();

    /// <summary>The owner key of the scan in progress, or null (the engine's share).</summary>
    public static string? Current => CurrentOwner.Value;

    /// <summary>Sets the owner for the rest of this async flow; dispose to restore the previous one.</summary>
    public static IDisposable Use(string? owner)
    {
        var previous = CurrentOwner.Value;
        CurrentOwner.Value = owner;
        return new Restore(previous);
    }

    private sealed class Restore(string? previous) : IDisposable
    {
        public void Dispose() => CurrentOwner.Value = previous;
    }
}

/// <summary>
/// Review D3 M3: real-time VirusTotal requests per owner per UTC day, so one user dropping hundreds of new <c>.exe</c> files can't
/// use up the shared daily budget. <b>In memory</b>: an engine restart starts every owner's count again (the global daily
/// limit in <c>vt-usage.json</c> still holds). Distinct owners are capped; past the cap they share one count. Thread-safe.
/// </summary>
internal sealed class VirusTotalDayBudget(TimeProvider time, int maxOwners = 256)
{
    /// <summary>The key for files with no user owner (machine-wide, admin- or SYSTEM-owned): the engine's share.</summary>
    public const string EngineKey = "engine";

    private const string SharedKey = "*";

    private readonly Lock _lock = new();
    private readonly Dictionary<string, int> _used = new(StringComparer.OrdinalIgnoreCase);
    private DateOnly _day;

    /// <summary>Takes one request for <paramref name="owner"/> if it has fewer than <paramref name="cap"/> today.</summary>
    /// <param name="taken">The key the request was counted under (for <see cref="Refund"/>).</param>
    public bool TryTake(string owner, int cap, out string taken)
    {
        lock (_lock)
        {
            Roll();
            taken = _used.ContainsKey(owner) || _used.Count < maxOwners ? owner : SharedKey;
            int used = _used.GetValueOrDefault(taken);
            if (used >= cap)
            {
                return false;
            }

            _used[taken] = used + 1;
            return true;
        }
    }

    /// <summary>Gives a request back (it was answered from the cache or never sent).</summary>
    public void Refund(string taken)
    {
        lock (_lock)
        {
            Roll();
            if (_used.TryGetValue(taken, out int used) && used > 0)
            {
                _used[taken] = used - 1;
            }
        }
    }

    public int UsedBy(string owner)
    {
        lock (_lock)
        {
            Roll();
            return _used.GetValueOrDefault(owner);
        }
    }

    private void Roll()
    {
        var today = DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime);
        if (today != _day)
        {
            _day = today;
            _used.Clear();
        }
    }
}
