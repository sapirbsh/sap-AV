namespace SapAV.Engine.Persistence.Remediation;

/// <summary>D5: a key's state right after the user's change, and (for a neighbour) the judged state it must have come from.</summary>
internal sealed record LedgerAcceptance(string After, string? JudgedAs = null);

/// <summary>
/// D5 ↔ D4: tells real-time persistence monitoring about the changes the user made through Block &amp; remove and restore, so
/// they don't come back as alerts. Thread-safe (actions run on pipe threads, the monitor on its own thread).
/// </summary>
/// <remarks>
/// <para><b>Hold.</b> Before an action changes anything, its entry keys are held: the monitor doesn't judge those keys
/// (they wait, unjudged) until the action is done or the hold runs out (<see cref="MaxHold"/>), so a monitor pass that lands
/// between the change and the hand-over can't alert on it.</para>
/// <para><b>Accept.</b> After the change, the action collects the scope again and hands over each touched key's fingerprint
/// as it is now: the entry's own key, and (Winlogon, services, tasks) neighbours that were already judged. The monitor marks a
/// waiting record judged, silently, only if its fingerprint is exactly that one, once
/// (<see cref="TryConsume"/>), within <see cref="AcceptFor"/>. Anything else (another value written right after, a later
/// change) is judged and alerted as usual. A removed key needs no hand-over: removals are only logged.</para>
/// </remarks>
internal sealed class PersistenceActionLedger(TimeProvider time)
{
    public static readonly TimeSpan MaxHold = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan AcceptFor = TimeSpan.FromMinutes(10);
    private const int MaxEntries = 4096;

    private readonly Lock _lock = new();
    private readonly Dictionary<string, (int Count, DateTimeOffset Until)> _held = new(StringComparer.Ordinal); // follow-up M1: reference-counted
    private readonly HashSet<string> _rejudge = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (LedgerAcceptance Acceptance, DateTimeOffset Until)> _accepted = new(StringComparer.Ordinal);

    /// <summary>Raised (on the acting thread) after <see cref="Accept"/> with the scope to look at again now.</summary>
    public event Action<PersistenceScope>? Accepted;

    /// <summary>Holds every baseline key starting with one of <paramref name="prefixes"/> (an action runs on them); counted, one <see cref="Release"/> each.</summary>
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
                    _held[prefix] = (_held.TryGetValue(prefix, out var held) ? held.Count + 1 : 1, until);
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
                // Follow-up M1: one release per hold; a key held by two actions stays held until both are done.
                if (_held.TryGetValue(prefix, out var held) && held.Count > 1)
                {
                    _held[prefix] = held with { Count = held.Count - 1 };
                }
                else
                {
                    _held.Remove(prefix);
                }
            }
        }
    }

    /// <summary>
    /// The keys the user's change touched, each with its fingerprint right after the change (keys that are gone aren't
    /// listed). <see cref="LedgerAcceptance.JudgedAs"/> set (review H1, a neighbour of the entry: another program of a Winlogon
    /// value, a service's other entry, a task's other action): the record is accepted only if it was last judged under exactly
    /// that pre-action fingerprint, so a new or unjudged key, or one changed meanwhile, is never accepted.
    /// </summary>
    public void Accept(IReadOnlyDictionary<string, LedgerAcceptance> accepted, PersistenceScope scope)
    {
        var until = time.GetUtcNow() + AcceptFor;
        lock (_lock)
        {
            Prune();
            foreach (var (key, acceptance) in accepted)
            {
                if (_accepted.Count < MaxEntries)
                {
                    _accepted[key] = (acceptance, until);
                }
            }
        }

        Accepted?.Invoke(scope);
    }

    /// <summary>
    /// Section D review H1: the entry isn't in the state the action left (it came back, or changed right after a restore): D4
    /// judges it again even if its content equals what it judged before (the user believes it is blocked).
    /// </summary>
    public void Rejudge(string key, PersistenceScope scope)
    {
        lock (_lock)
        {
            if (_rejudge.Count < MaxEntries)
            {
                _rejudge.Add(key);
            }
        }

        Accepted?.Invoke(scope);
    }

    /// <summary>The keys to judge again (taken: each is returned once).</summary>
    public IReadOnlyList<string> TakeRejudge()
    {
        lock (_lock)
        {
            var keys = _rejudge.ToArray();
            _rejudge.Clear();
            return keys;
        }
    }

    /// <summary>The key is held now (the monitor leaves it unjudged); <paramref name="until"/> is when the hold runs out.</summary>
    public bool IsHeld(string key, out DateTimeOffset until)
    {
        var now = time.GetUtcNow();
        lock (_lock)
        {
            foreach (var (prefix, (_, end)) in _held)
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

    /// <summary>
    /// True once if the user's change left <paramref name="key"/> with exactly <paramref name="fingerprint"/> (and, for a
    /// neighbour, the record was last judged under the handed-over pre-action fingerprint, <paramref name="judgedFingerprint"/>).
    /// </summary>
    public bool TryConsume(string key, string fingerprint, string? judgedFingerprint)
    {
        lock (_lock)
        {
            if (!_accepted.TryGetValue(key, out var accepted) || accepted.Until <= time.GetUtcNow()
                || !string.Equals(accepted.Acceptance.After, fingerprint, StringComparison.Ordinal)
                || (accepted.Acceptance.JudgedAs is { } before && !string.Equals(before, judgedFingerprint, StringComparison.Ordinal)))
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
        foreach (var key in _held.Where(h => h.Value.Until <= now).Select(h => h.Key).ToArray())
        {
            _held.Remove(key);
        }

        foreach (var key in _accepted.Where(a => a.Value.Until <= now).Select(a => a.Key).ToArray())
        {
            _accepted.Remove(key);
        }
    }
}
