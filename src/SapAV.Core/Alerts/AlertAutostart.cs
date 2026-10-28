using System.Text.Json.Serialization;
using SapAV.Core.Persistence;

namespace SapAV.Core.Alerts;

/// <summary>
/// The autostart entry a persistence alert (<see cref="AlertType.MaliciousPersistence"/> /
/// <see cref="AlertType.SuspiciousPersistence"/>) is about: where it lives, for SIEM rules and for Block &amp; remove (D5).
/// </summary>
/// <remarks>
/// Entry text is untrusted: <see cref="Location"/> and <see cref="ValueName"/> keep their characters (controls become
/// U+FFFD) and are capped tighter than in <see cref="PersistenceEntry"/>, so every bounded field of an alert still fits one
/// Event Log string (<c>AlertEventMessage.MinMessageChars</c>). The command line isn't repeated here (the reasons say what
/// it runs). In JSON, <c>Kind</c> and <c>Enabled</c> are required.
/// </remarks>
public sealed record AlertAutostart
{
    public const int MaxLocationLength = 512;
    public const int MaxValueNameLength = 256;

    [JsonConstructor]
    public AlertAutostart(PersistenceKind kind, string location, string? valueName, string? userSid, bool enabled)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Undefined persistence kind.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(location);
        if (userSid is not null && !PersistenceEntry.IsSid(userSid))
        {
            throw new ArgumentException("The user scope must be a SID.", nameof(userSid));
        }

        Kind = kind;
        Location = PersistenceText.Identifier(location, MaxLocationLength);
        ValueName = valueName is null ? null : PersistenceText.Identifier(valueName, MaxValueNameLength);
        UserSid = userSid;
        Enabled = enabled;
    }

    /// <summary>The alert form of <paramref name="entry"/>.</summary>
    public static AlertAutostart From(PersistenceEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return new AlertAutostart(entry.Kind, entry.Location, entry.ValueName, entry.UserSid, entry.Enabled);
    }

    [JsonRequired]
    [JsonInclude]
    public PersistenceKind Kind { get; private init; }

    /// <summary>The registry key, task path or Startup folder (capped at <see cref="MaxLocationLength"/>).</summary>
    public string Location { get; }

    public string? ValueName { get; }

    /// <summary>The user the entry belongs to; null for a machine-wide entry.</summary>
    public string? UserSid { get; }

    [JsonRequired]
    [JsonInclude]
    public bool Enabled { get; private init; }

    /// <summary>Identifies the entry for alert aggregation (case-insensitive).</summary>
    [JsonIgnore]
    public string Key => string.Join('|', Kind, UserSid ?? "machine", Location.ToUpperInvariant(), ValueName?.ToUpperInvariant() ?? string.Empty);
}
