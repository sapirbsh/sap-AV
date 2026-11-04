using System.Security.Cryptography;
using System.Text.Json;
using SapAV.Core.Persistence;

namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>Why a baseline record still needs judging (or last needed it).</summary>
internal enum BaselineChange
{
    /// <summary>Seen when its scope was first baselined: judged quietly once (only a Suspicious / Malicious verdict alerts).</summary>
    Initial = 0,

    /// <summary>Appeared after its scope was baselined.</summary>
    New = 1,

    /// <summary>Its content (command, resolution, enabled state, ...) changed after it was known.</summary>
    Changed = 2,
}

/// <summary>
/// One known autostart entry (all entries with the same <see cref="PersistenceEntry.Key"/> together).
/// </summary>
/// <param name="Fingerprint">SHA-256 (hex) of the entries as collected: any change of command line, resolution, enabled state etc. changes it.</param>
/// <param name="Display">Where it is, for the log (location and value name, capped).</param>
/// <param name="Judged">The current fingerprint has been judged (and alerted if it needed to be).</param>
internal sealed record BaselineRecord(string Key, PersistenceScope Scope, string Fingerprint, string Display, bool Judged, BaselineChange Change);

/// <summary>What a baseline holds, for saving and loading.</summary>
/// <param name="Baselined">Scopes whose entries were all seen once in a complete collection.</param>
internal sealed record BaselineSnapshot(IReadOnlyList<BaselineRecord> Records, IReadOnlyList<PersistenceScope> Baselined);

/// <summary>What one collection changed in the baseline.</summary>
/// <param name="Removed">Records dropped because a complete collection of their scope no longer had them.</param>
internal sealed record BaselineDiff(int Added, int Changed, IReadOnlyList<BaselineRecord> Removed, IReadOnlyList<PersistenceScope> NewlyBaselined)
{
    public bool Any => Added > 0 || Changed > 0 || Removed.Count > 0 || NewlyBaselined.Count > 0;
}

/// <summary>Entries of one record that still need judging, from the collection just made.</summary>
internal sealed record PendingJudgement(BaselineRecord Record, IReadOnlyList<PersistenceEntry> Entries);

/// <summary>
/// D4: the baseline of known autostart entries and the diff against a new collection. Not thread-safe (the monitor's own thread).
/// </summary>
/// <remarks>
/// <para><b>Per scope.</b> A collection of some scopes changes only records of those scopes. Within a scope:</para>
/// <list type="bullet">
/// <item>a key not known yet is added unjudged: <see cref="BaselineChange.New"/> once the scope is baselined, else
/// <see cref="BaselineChange.Initial"/> (the first collection of a scope, e.g. at first start or when a user's hive is first
/// seen, alerts only what is Suspicious / Malicious, never "everything is new");</item>
/// <item>a known key with another fingerprint becomes unjudged <see cref="BaselineChange.Changed"/> (or stays Initial if
/// its initial judgement hasn't run yet);</item>
/// <item>a known key that is missing is removed <b>only when the scope's collection was complete</b>
/// (<see cref="PersistenceScopeOutcome.IsComplete"/>): a denied key, an unloaded hive, a cap or the budget never makes entries
/// look removed (and then new again).</item>
/// </list>
/// <para>A scope is baselined after its first complete collection. Unjudged records survive a restart (the store keeps
/// them), so an engine stopped mid-judgement judges them at the next start.</para>
/// </remarks>
internal sealed class PersistenceBaseline
{
    public const int MaxDisplayLength = 512;

    private readonly Dictionary<string, BaselineRecord> _records = new(StringComparer.Ordinal);
    private readonly HashSet<PersistenceScope> _baselined = [];

    public PersistenceBaseline(BaselineSnapshot? snapshot = null)
    {
        foreach (var record in snapshot?.Records ?? [])
        {
            _records[record.Key] = record;
        }

        _baselined.UnionWith(snapshot?.Baselined ?? []);
    }

    public int Count => _records.Count;

    public int Unjudged => _records.Values.Count(r => !r.Judged);

    public bool IsBaselined(PersistenceScope scope) => _baselined.Contains(scope);

    public BaselineRecord? Find(string key) => _records.GetValueOrDefault(key);

    public BaselineSnapshot Snapshot() => new([.. _records.Values], [.. _baselined]);

    /// <summary>Applies a collection of some scopes (see the class remarks).</summary>
    public BaselineDiff Apply(PersistenceScopedCollection collected)
    {
        ArgumentNullException.ThrowIfNull(collected);
        int added = 0, changed = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in Group(collected))
        {
            seen.Add(group.Key);
            string fingerprint = Fingerprint(group.Entries);
            if (!_records.TryGetValue(group.Key, out var known))
            {
                var change = _baselined.Contains(group.Scope) ? BaselineChange.New : BaselineChange.Initial;
                _records[group.Key] = new BaselineRecord(group.Key, group.Scope, fingerprint, Display(group.Entries[0]), false, change);
                added++;
            }
            else if (!string.Equals(known.Fingerprint, fingerprint, StringComparison.Ordinal) || known.Scope != group.Scope)
            {
                var change = !known.Judged && known.Change == BaselineChange.Initial ? BaselineChange.Initial : BaselineChange.Changed;
                _records[group.Key] = known with { Scope = group.Scope, Fingerprint = fingerprint, Display = Display(group.Entries[0]), Judged = false, Change = change };
                changed++;
            }
        }

        var removed = new List<BaselineRecord>();
        var newlyBaselined = new List<PersistenceScope>();
        foreach (var (scope, outcome) in collected.Outcomes)
        {
            if (!outcome.IsComplete)
            {
                continue;
            }

            foreach (var gone in _records.Values.Where(r => r.Scope == scope && !seen.Contains(r.Key)).ToArray())
            {
                _records.Remove(gone.Key);
                removed.Add(gone);
            }

            if (_baselined.Add(scope))
            {
                newlyBaselined.Add(scope);
            }
        }

        return new BaselineDiff(added, changed, removed, newlyBaselined);
    }

    /// <summary>
    /// Unjudged records of <paramref name="collected"/>'s scopes, with their entries from it: New and Changed first, then
    /// Initial; machine-wide before per-user; then collection order. At most <paramref name="maxEntries"/> entries (always at
    /// least one record).
    /// </summary>
    public IReadOnlyList<PendingJudgement> Pending(PersistenceScopedCollection collected, int maxEntries)
    {
        var pending = new List<PendingJudgement>();
        int entries = 0;
        var ordered = Group(collected)
            .Select((g, i) => (Group: g, Index: i, Record: _records.GetValueOrDefault(g.Key)))
            .Where(x => x.Record is { Judged: false }) // Apply just set its fingerprint from this collection
            .OrderBy(x => x.Record!.Change == BaselineChange.Initial ? 1 : 0)
            .ThenBy(x => x.Group.Entries[0].IsMachineScope ? 0 : 1)
            .ThenBy(x => x.Index);
        foreach (var (group, _, record) in ordered)
        {
            if (pending.Count > 0 && entries + group.Entries.Count > maxEntries)
            {
                break;
            }

            pending.Add(new PendingJudgement(record!, group.Entries));
            entries += group.Entries.Count;
        }

        return pending;
    }

    /// <summary>The record was judged under <paramref name="fingerprint"/>; false if it changed or went meanwhile.</summary>
    public bool MarkJudged(string key, string fingerprint)
    {
        if (_records.TryGetValue(key, out var record) && record.Fingerprint == fingerprint)
        {
            _records[key] = record with { Judged = true };
            return true;
        }

        return false;
    }

    /// <summary>Drops the records and the baselined state of users that are no longer profiles (their profile was deleted).</summary>
    public int ForgetUsers(IReadOnlySet<string> keep)
    {
        var gone = _records.Values.Where(r => r.Scope.UserSid is { } sid && !keep.Contains(sid)).Select(r => r.Key).ToArray();
        foreach (var key in gone)
        {
            _records.Remove(key);
        }

        _baselined.RemoveWhere(s => s.UserSid is { } sid && !keep.Contains(sid));
        return gone.Length;
    }

    public bool HasUnjudged(PersistenceScope scope) => _records.Values.Any(r => r.Scope == scope && !r.Judged);

    /// <summary>SHA-256 over the entries' JSON (the model's own serialization, every field).</summary>
    internal static string Fingerprint(IReadOnlyList<PersistenceEntry> entries)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var entry in entries)
        {
            hash.AppendData(JsonSerializer.SerializeToUtf8Bytes(entry));
            hash.AppendData("\n"u8);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static string Display(PersistenceEntry entry)
    {
        string text = entry.ValueName is null ? entry.Location : $@"{entry.Location}\{entry.ValueName}";
        return text.Length <= MaxDisplayLength ? text : text[..MaxDisplayLength];
    }

    private sealed record EntryGroup(string Key, PersistenceScope Scope, List<PersistenceEntry> Entries);

    /// <summary>The collection's entries by key (in first-seen order), each with the scope it was collected in.</summary>
    private static List<EntryGroup> Group(PersistenceScopedCollection collected)
    {
        var groups = new List<EntryGroup>();
        var byKey = new Dictionary<string, EntryGroup>(StringComparer.Ordinal);
        var entries = collected.Collection.Entries;
        for (int i = 0; i < entries.Count && i < collected.EntryScopes.Count; i++)
        {
            string key = entries[i].Key;
            if (!byKey.TryGetValue(key, out var group))
            {
                group = new EntryGroup(key, collected.EntryScopes[i], []);
                byKey[key] = group;
                groups.Add(group);
            }

            group.Entries.Add(entries[i]);
        }

        return groups;
    }
}
