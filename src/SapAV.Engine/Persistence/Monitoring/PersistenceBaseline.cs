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

    /// <summary>Its content (command, resolution, enabled state, target file, ...) changed after it was known.</summary>
    Changed = 2,
}

/// <summary>
/// One known autostart entry (all entries with the same <see cref="PersistenceEntry.Key"/> together).
/// </summary>
/// <param name="Fingerprint">SHA-256 (hex) of the entries as collected: any change of command line, resolution, enabled state etc. changes it.</param>
/// <param name="Display">Where it is, for the log (location and value name, capped).</param>
/// <param name="Judged">The current fingerprint and target stamp have been judged (and alerted if they needed to be).</param>
/// <param name="TargetStamp">Review H2: SHA-256 (hex) of the target files' stamps (file ID, size, times, USN); null = not known.</param>
/// <param name="PendingSince">Review H4: when it last became unjudged, as a sequence number (first in, first judged); not moved by later changes while it waits.</param>
/// <param name="NotBefore">Not judged before this (H1: a retry after a coverage gap; H4: a key that keeps changing).</param>
/// <param name="Attempts">Review H1: judgements in a row that couldn't reach the target (time, a cap, a failed open or scan).</param>
/// <param name="LastJudged">When it was last judged (H4: re-judging a key that keeps changing is rate-limited).</param>
internal sealed record BaselineRecord(
    string Key, PersistenceScope Scope, string Fingerprint, string Display, bool Judged, BaselineChange Change, string? TargetStamp = null,
    long PendingSince = 0, DateTimeOffset? NotBefore = null, int Attempts = 0, DateTimeOffset? LastJudged = null);

/// <summary>Review H3: an autostart location the engine was denied, already reported (until it is readable again).</summary>
internal sealed record HiddenLocation(string Id, PersistenceScope Scope);

/// <summary>What a baseline holds, for saving and loading.</summary>
/// <param name="Baselined">Scopes whose entries were all seen once in a complete collection.</param>
internal sealed record BaselineSnapshot(IReadOnlyList<BaselineRecord> Records, IReadOnlyList<PersistenceScope> Baselined, IReadOnlyList<HiddenLocation>? Hidden = null);

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
/// <item>a known key with another fingerprint, or (review H2) whose target files' stamp changed (a target overwritten after
/// it was judged), becomes unjudged <see cref="BaselineChange.Changed"/>;</item>
/// <item>a known key that is missing is removed <b>only when the scope's collection was complete</b>
/// (<see cref="PersistenceScopeOutcome.IsComplete"/>).</item>
/// </list>
/// <para><b>Order (review H4).</b> Unjudged records are judged first in, first out by <see cref="BaselineRecord.PendingSince"/>,
/// which a later change doesn't move, so keys rewritten over and over can't keep an older entry waiting; a key judged less
/// than the re-judge interval ago waits that long before it is judged again.</para>
/// <para>A scope is baselined after its first complete collection. Unjudged records survive a restart.</para>
/// </remarks>
internal sealed class PersistenceBaseline
{
    public const int MaxDisplayLength = 512;

    /// <summary>Most hidden locations remembered (each user's own keys and folders, and stray task files).</summary>
    public const int MaxHidden = 4096;

    private readonly Dictionary<string, BaselineRecord> _records = new(StringComparer.Ordinal);
    private readonly HashSet<PersistenceScope> _baselined = [];
    private readonly Dictionary<string, PersistenceScope> _hidden = new(StringComparer.Ordinal);
    private long _sequence;

    public PersistenceBaseline(BaselineSnapshot? snapshot = null)
    {
        foreach (var record in snapshot?.Records ?? [])
        {
            _records[record.Key] = record;
            _sequence = Math.Max(_sequence, record.PendingSince);
        }

        _baselined.UnionWith(snapshot?.Baselined ?? []);
        foreach (var hidden in snapshot?.Hidden ?? [])
        {
            _hidden[hidden.Id] = hidden.Scope;
        }
    }

    public int Count => _records.Count;

    public int Unjudged => _records.Values.Count(r => !r.Judged);

    public int HiddenCount => _hidden.Count;

    public bool IsBaselined(PersistenceScope scope) => _baselined.Contains(scope);

    public BaselineRecord? Find(string key) => _records.GetValueOrDefault(key);

    public BaselineSnapshot Snapshot() => new([.. _records.Values], [.. _baselined], [.. _hidden.Select(h => new HiddenLocation(h.Key, h.Value))]);

    /// <summary>Applies a collection of some scopes (see the class remarks).</summary>
    /// <param name="targetStamps">Review H2: each key's target stamp now (keys missing from it aren't compared).</param>
    /// <param name="rejudgeAfter">Review H4: a judged key that changes again within this is judged no earlier than that.</param>
    public BaselineDiff Apply(
        PersistenceScopedCollection collected, IReadOnlyDictionary<string, string>? targetStamps = null, DateTimeOffset? now = null, TimeSpan rejudgeAfter = default)
    {
        ArgumentNullException.ThrowIfNull(collected);
        int added = 0, changed = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in Group(collected))
        {
            seen.Add(group.Key);
            string fingerprint = Fingerprint(group.Entries);
            string? stamp = targetStamps?.GetValueOrDefault(group.Key);
            if (!_records.TryGetValue(group.Key, out var known))
            {
                var change = _baselined.Contains(group.Scope) ? BaselineChange.New : BaselineChange.Initial;
                _records[group.Key] = new BaselineRecord(group.Key, group.Scope, fingerprint, Display(group.Entries[0]), false, change, stamp, ++_sequence);
                added++;
                continue;
            }

            bool targetChanged = stamp is not null && known.TargetStamp is not null && !string.Equals(stamp, known.TargetStamp, StringComparison.Ordinal);
            if (!string.Equals(known.Fingerprint, fingerprint, StringComparison.Ordinal) || known.Scope != group.Scope || targetChanged)
            {
                var updated = known with { Scope = group.Scope, Fingerprint = fingerprint, Display = Display(group.Entries[0]), TargetStamp = stamp ?? known.TargetStamp };
                if (known.Judged)
                {
                    // H4: in line from now on; a key that keeps changing (its last judgement was already for a change) waits for the
                    // re-judge interval. Its first change after the initial judgement is judged right away.
                    var notBefore = known.Change != BaselineChange.Initial && known.LastJudged is { } last && now is { } at && last + rejudgeAfter > at
                        ? last + rejudgeAfter
                        : (DateTimeOffset?)null;
                    updated = updated with { Judged = false, Change = BaselineChange.Changed, PendingSince = ++_sequence, NotBefore = notBefore, Attempts = 0 };
                }

                _records[group.Key] = updated; // still waiting: keeps its place (PendingSince) and its change kind
                changed++;
            }
            else if (stamp is not null && known.TargetStamp is null)
            {
                _records[group.Key] = known with { TargetStamp = stamp };
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
    /// Unjudged records of <paramref name="collected"/>'s scopes that may be judged at <paramref name="now"/>, with their entries
    /// from it, first in, first out (review H4).
    /// </summary>
    public IReadOnlyList<PendingJudgement> Pending(PersistenceScopedCollection collected, DateTimeOffset? now = null) =>
        Group(collected)
            .Select(g => (Group: g, Record: _records.GetValueOrDefault(g.Key)))
            .Where(x => x.Record is { Judged: false } r && (r.NotBefore is null || now is null || r.NotBefore <= now))
            .OrderBy(x => x.Record!.PendingSince)
            .Select(x => new PendingJudgement(x.Record!, x.Group.Entries))
            .ToArray();

    /// <summary>The earliest time a waiting (not yet eligible) record of these scopes may be judged, or null.</summary>
    public DateTimeOffset? NextEligible(IEnumerable<PersistenceScope> scopes)
    {
        var set = scopes.ToHashSet();
        return _records.Values.Where(r => !r.Judged && r.NotBefore is not null && set.Contains(r.Scope)).Min(r => r.NotBefore);
    }

    /// <summary>The record was judged under <paramref name="fingerprint"/>; false if it changed or went meanwhile.</summary>
    public bool MarkJudged(string key, string fingerprint, DateTimeOffset? now = null)
    {
        if (_records.TryGetValue(key, out var record) && record.Fingerprint == fingerprint)
        {
            _records[key] = record with { Judged = true, LastJudged = now, NotBefore = null, Attempts = 0 };
            return true;
        }

        return false;
    }

    /// <summary>
    /// Review H1: the judgement couldn't reach the target (a coverage gap): the record stays unjudged, in its place, and is
    /// tried again after <paramref name="backoff"/>. Returns the attempts so far (0 if it changed or went meanwhile).
    /// </summary>
    public int MarkRetry(string key, string fingerprint, DateTimeOffset now, Func<int, TimeSpan> backoff)
    {
        if (!_records.TryGetValue(key, out var record) || record.Fingerprint != fingerprint)
        {
            return 0;
        }

        int attempts = record.Attempts + 1;
        _records[key] = record with { Attempts = attempts, NotBefore = now + backoff(attempts), LastJudged = now };
        return attempts;
    }

    /// <summary>Review H3: remembers a hidden location; true the first time (until <see cref="KeepHidden"/> drops it).</summary>
    public bool ReportHidden(string id, PersistenceScope scope)
    {
        if (_hidden.ContainsKey(id) || _hidden.Count >= MaxHidden)
        {
            return false;
        }

        _hidden[id] = scope;
        return true;
    }

    /// <summary>Review H3: forgets the hidden locations of <paramref name="scope"/> not in <paramref name="still"/> (readable again: reported anew if hidden again).</summary>
    public bool KeepHidden(PersistenceScope scope, IReadOnlySet<string> still)
    {
        var gone = _hidden.Where(h => h.Value == scope && !still.Contains(h.Key)).Select(h => h.Key).ToArray();
        foreach (var id in gone)
        {
            _hidden.Remove(id);
        }

        return gone.Length > 0;
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
        foreach (var hidden in _hidden.Where(h => h.Value.UserSid is { } sid && !keep.Contains(sid)).Select(h => h.Key).ToArray())
        {
            _hidden.Remove(hidden);
        }

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
    internal static IReadOnlyList<(string Key, IReadOnlyList<PersistenceEntry> Entries)> Groups(PersistenceScopedCollection collected) =>
        Group(collected).Select(g => (g.Key, (IReadOnlyList<PersistenceEntry>)g.Entries)).ToArray();

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
