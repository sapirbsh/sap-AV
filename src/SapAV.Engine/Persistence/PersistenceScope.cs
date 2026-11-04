using SapAV.Core.Persistence;

namespace SapAV.Engine.Persistence;

/// <summary>
/// D4: one part of a collection that can be collected on its own: a source's machine-wide part (<paramref name="UserSid"/>
/// null) or one user's part of it. Real-time persistence monitoring re-collects only the scopes a change touched.
/// </summary>
/// <param name="Source">The source's <see cref="IPersistenceSource.Name"/>, or one of the special names below.</param>
internal readonly record struct PersistenceScope(string Source, string? UserSid)
{
    /// <summary>Not a source: everything (the machine environment changed, so every resolution may have).</summary>
    public static PersistenceScope All { get; } = new("*", null);

    /// <summary>Not a source: the user profiles or the loaded hives changed (a logon, a logoff, a new profile).</summary>
    public static PersistenceScope Profiles { get; } = new("profiles", null);

    public bool IsSpecial => Source is "*" or "profiles";

    /// <summary>The machine or the user whose fair share a pass of this scope counts against.</summary>
    public string Owner => UserSid ?? string.Empty;

    public override string ToString() => UserSid is null ? Source : $"{Source} ({UserSid})";
}

/// <summary>What happened to one scope in a collection.</summary>
/// <param name="Truncated">Entries may be missing without an issue of their own (a cap or a budget ran out during or before it).</param>
/// <param name="Reasons">The issues added while the scope ran.</param>
internal sealed record PersistenceScopeOutcome(bool Truncated, IReadOnlyCollection<PersistenceIssueReason> Reasons)
{
    /// <summary>
    /// Every entry of the scope was seen, so an entry that is gone really is gone. Only problems with one item (a malformed
    /// file, a link not followed, a file too large, a network folder that is never read) still count as complete; a
    /// denied key, an unloaded hive, an unavailable parser, a cap or a budget don't.
    /// </summary>
    public bool IsComplete => !Truncated && Reasons.All(r => r is PersistenceIssueReason.Malformed or PersistenceIssueReason.TooLarge
        or PersistenceIssueReason.LinkNotFollowed or PersistenceIssueReason.NetworkLocation);
}

/// <summary>A collection with the scope of each entry (in the same order as <see cref="PersistenceCollection.Entries"/>).</summary>
/// <param name="Outcomes">One per scope that ran (a scope whose user wasn't found, or that the budget skipped, may be missing).</param>
/// <param name="IssueScopes">D4 review H3: the scope each issue of <see cref="PersistenceCollection.Issues"/> came from (same order; null = none).</param>
internal sealed record PersistenceScopedCollection(
    PersistenceCollection Collection, IReadOnlyList<PersistenceScope> EntryScopes, IReadOnlyDictionary<PersistenceScope, PersistenceScopeOutcome> Outcomes,
    IReadOnlyList<PersistenceScope?>? IssueScopes = null);

/// <summary>What a watch looks at: a registry key (and maybe its subkeys) or a folder.</summary>
internal enum PersistenceWatchKind
{
    RegistryKey,
    Folder,
}

/// <summary>
/// D4: one place a source asks to be watched. A registry key that doesn't exist yet is watched through its nearest existing
/// ancestor until it appears (<see cref="RegistryKeyWatch"/>). A folder is a local path, opened without following links.
/// </summary>
/// <param name="Subtree">Registry: also the subkeys. Folder: also subfolders (Startup folders run only their top level).</param>
internal sealed record PersistenceWatchTarget(PersistenceWatchKind Kind, RegistryRoot Root, string Path, bool Subtree)
{
    public static PersistenceWatchTarget Key(RegistryRoot root, string path, bool subtree = false) => new(PersistenceWatchKind.RegistryKey, root, path, subtree);

    public static PersistenceWatchTarget Folder(string path, bool subtree) => new(PersistenceWatchKind.Folder, RegistryRoot.LocalMachine, path, subtree);

    /// <summary>Identifies the watch (case-insensitive path): scopes asking for the same place share it.</summary>
    public string Id => $"{Kind}|{Root}|{(Subtree ? 1 : 0)}|{Path.ToUpperInvariant()}";

    public override string ToString() => Kind == PersistenceWatchKind.Folder ? Path : (Root == RegistryRoot.LocalMachine ? @"HKLM\" : @"HKU\") + Path;
}

/// <summary>Everything to watch now, and for which scope.</summary>
/// <param name="UserSids">The profiles (ProfileList) and loaded user hives the plan was made for.</param>
/// <param name="LoadedSids">The user hives loaded under HKEY_USERS when the plan was made.</param>
/// <param name="ProfilesComplete">ProfileList and HKEY_USERS were both read (else a user missing from the plan may still exist).</param>
internal sealed record PersistenceWatchPlan(
    IReadOnlyList<(PersistenceScope Scope, PersistenceWatchTarget Target)> Watches, IReadOnlyList<string> SourceNames,
    IReadOnlyList<string> UserSids, IReadOnlyCollection<string> LoadedSids, bool ProfilesComplete = true);

/// <summary>D4: the collector as real-time persistence monitoring uses it. Fake it in tests.</summary>
internal interface IScopedPersistenceCollector : IPersistenceCollector
{
    /// <summary>The registry the collector reads (the monitor lists the loaded hives through it).</summary>
    IRegistryView Registry { get; }

    /// <summary>Collects only <paramref name="scopes"/> (null = everything); otherwise as <see cref="IPersistenceCollector.Collect"/>.</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    PersistenceScopedCollection CollectScoped(IReadOnlyCollection<PersistenceScope>? scopes, CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null);

    /// <summary>Where every source's entries live right now (keys, folders), per scope. Read-only; never throws for a registry problem.</summary>
    PersistenceWatchPlan Plan(CancellationToken cancellationToken = default);
}
