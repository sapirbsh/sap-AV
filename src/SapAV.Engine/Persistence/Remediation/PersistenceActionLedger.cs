namespace SapAV.Engine.Persistence.Remediation;

/// <summary>
/// D5 ↔ D4: tells real-time persistence monitoring about the changes the user made through Block &amp; remove and restore, so
/// they don't come back as alerts. Thread-safe (actions run on pipe threads, the monitor on its own thread).
/// </summary>
/// <remarks>
/// <para><b>Hold.</b> Before an action changes anything, its entry keys are held: the monitor doesn't judge those keys
/// (they wait, unjudged) until the action is done or the hold runs out (<see cref="MaxHold"/>), so a monitor pass that lands
/// between the change and the hand-over can't alert on it.</para>
/// <para><b>Accept.</b> After the change, the action collects the scope again and hands over each touched key's fingerprint
/// as it is now. The monitor marks a waiting record judged, silently, only if its fingerprint is exactly that one, once
/// (<see cref="TryConsume"/>), within <see cref="AcceptFor"/>. Anything else (another value written right after, a later
/// change) is judged and alerted as usual. A removed key needs no hand-over: removals are only logged.</para>
/// </remarks>
internal sealed class PersistenceActionLedger(TimeProvider time)
{
    public static readonly TimeSpan MaxHold = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan AcceptFor = TimeSpan.FromMinutes(10);
    private const int MaxEntries = 4096;

    private readonly Lock _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _held = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (string Fingerprint, DateTimeOffset Until)> _accepted = new(StringComparer.Ordinal);

    /// <summary>Raised (on the acting thread) after <see cref="Accept"/> with the scope to look at again now.</summary>
    public event Action<PersistenceScope>? Accepted;

    /// <summary>Holds every baseline key starting with one of <paramref name="prefixes"/> (an action runs on them).</summary>
    public void Hold(IEnumerable<string> prefixes)
    {
        var until = time.GetUtcNow() + MaxHold;
        lock (_lock)
        {
            Prune();
            foreach (var prefix in prefixes)
            {
                if (_held.Count < MaxEntries)
                {
                    _held[prefix] = until;
                }
            }
        }
    }

    public void Release(IEnumerable<string> prefixes)
    {
        lock (_lock)
        {
            foreach (var prefix in prefixes)
            {
                _held.Remove(prefix);
            }
        }
    }

    /// <summary>The keys' fingerprints right after the user's change (keys that are gone aren't listed).</summary>
    public void Accept(IReadOnlyDictionary<string, string> fingerprints, PersistenceScope scope)
    {
        var until = time.GetUtcNow() + AcceptFor;
        lock (_lock)
        {
            Prune();
            foreach (var (key, fingerprint) in fingerprints)
            {
                if (_accepted.Count < MaxEntries)
                {
                    _accepted[key] = (fingerprint, until);
                }
            }
        }

        Accepted?.Invoke(scope);
    }

    /// <summary>The key is held now (the monitor leaves it unjudged); <paramref name="until"/> is when the hold runs out.</summary>
    public bool IsHeld(string key, out DateTimeOffset until)
    {
        var now = time.GetUtcNow();
        lock (_lock)
        {
            foreach (var (prefix, end) in _held)
            {
                if (end > now && key.StartsWith(prefix, StringComparison.Ordinal))
                {
                    until = end;
                    return true;
                }
            }

            until = default;
            return false;
        }
    }

    /// <summary>True once if the user's change left <paramref name="key"/> with exactly <paramref name="fingerprint"/>.</summary>
    public bool TryConsume(string key, string fingerprint)
    {
        lock (_lock)
        {
            if (!_accepted.TryGetValue(key, out var accepted) || accepted.Until <= time.GetUtcNow()
                || !string.Equals(accepted.Fingerprint, fingerprint, StringComparison.Ordinal))
            {
                return false;
            }

            _accepted.Remove(key);
            return true;
        }
    }

    private void Prune()
    {
        var now = time.GetUtcNow();
        foreach (var key in _held.Where(h => h.Value <= now).Select(h => h.Key).ToArray())
        {
            _held.Remove(key);
        }

        foreach (var key in _accepted.Where(a => a.Value.Until <= now).Select(a => a.Key).ToArray())
        {
            _accepted.Remove(key);
        }
    }
}
