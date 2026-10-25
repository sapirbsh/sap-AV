using System.Text.Json.Serialization;
using SapAV.Core.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.Persistence;

/// <summary>Why part of the persistence collection is missing (ROADMAP C2). Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<PersistenceIssueReason>))]
public enum PersistenceIssueReason
{
    AccessDenied,

    /// <summary>
    /// A user profile whose registry hive isn't loaded (the user isn't logged on): its per-user registry entries weren't
    /// collected. The engine doesn't load NTUSER.DAT itself.
    /// </summary>
    HiveNotLoaded,

    /// <summary>Unparseable content (a task XML, a shortcut, a registry value of the wrong type).</summary>
    Malformed,

    /// <summary>A file or value over its size cap.</summary>
    TooLarge,

    /// <summary>A count cap (entries, files, subkeys, depth) was reached; the rest was skipped.</summary>
    LimitReached,

    /// <summary>A junction / symbolic link where a folder or file was expected; not followed.</summary>
    LinkNotFollowed,

    /// <summary>A folder on a network share (e.g. a redirected Startup folder); the engine doesn't contact servers.</summary>
    NetworkLocation,

    /// <summary>The collection's time budget ran out.</summary>
    TimeBudgetExceeded,

    /// <summary>Any other failure (a source threw, an I/O error).</summary>
    Error,
}

/// <summary>Something that couldn't be collected. Location and message are sanitized and capped.</summary>
public sealed record PersistenceIssue
{
    public const int MaxMessageLength = 512;

    [JsonConstructor]
    public PersistenceIssue(PersistenceKind? kind, string? userSid, string location, PersistenceIssueReason reason, string message)
    {
        if (kind is { } k && !Enum.IsDefined(k))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), k, "Undefined persistence kind.");
        }

        if (userSid is not null && !PersistenceEntry.IsSid(userSid))
        {
            throw new ArgumentException("The user scope must be a SID.", nameof(userSid));
        }

        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(message);
        if (!Enum.IsDefined(reason))
        {
            throw new ArgumentOutOfRangeException(nameof(reason), reason, "Undefined issue reason.");
        }

        Kind = kind;
        UserSid = userSid;
        Location = PersistenceText.Identifier(location, PersistenceEntry.MaxLocationLength);
        Reason = reason;
        Message = SafeText.SingleLine(message, MaxMessageLength);
    }

    /// <summary>The kind that is incomplete, or null when several are (e.g. an unloaded hive).</summary>
    public PersistenceKind? Kind { get; }

    public string? UserSid { get; }

    public string Location { get; }

    [JsonRequired]
    [JsonInclude]
    public PersistenceIssueReason Reason { get; private init; }

    public string Message { get; }
}

/// <summary>The result of one collection: the entries and what couldn't be collected. Never thrown, always returned.</summary>
public sealed record PersistenceCollection
{
    [JsonConstructor]
    public PersistenceCollection(IReadOnlyList<PersistenceEntry> entries, IReadOnlyList<PersistenceIssue> issues, TimeSpan duration)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(issues);
        if (entries.Any(e => e is null) || issues.Any(i => i is null))
        {
            throw new ArgumentException("Entries and issues must not contain null.");
        }

        Entries = Array.AsReadOnly(entries.ToArray());
        Issues = Array.AsReadOnly(issues.ToArray());
        Duration = duration < TimeSpan.Zero ? TimeSpan.Zero : duration;
    }

    public IReadOnlyList<PersistenceEntry> Entries { get; }

    public IReadOnlyList<PersistenceIssue> Issues { get; }

    public TimeSpan Duration { get; }

    /// <summary>True when nothing was skipped.</summary>
    [JsonIgnore]
    public bool IsComplete => Issues.Count == 0;
}
