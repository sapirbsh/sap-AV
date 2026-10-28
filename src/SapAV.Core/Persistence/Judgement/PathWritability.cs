using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Persistence;

/// <summary>Whether a standard (non-administrator) user can change something (ROADMAP C3). Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<Writability>))]
public enum Writability
{
    /// <summary>Not known (not checked, the object couldn't be opened safely, a link on the way, a remote path).</summary>
    Unknown,

    /// <summary>Only SYSTEM, Administrators, TrustedInstaller (and service identities) can make this change.</summary>
    AdminOnly,

    /// <summary>Some non-administrator principal (a user, Users, Authenticated Users, Everyone, a non-admin owner) can.</summary>
    UserWritable,
}

/// <summary>
/// What the persistence judgement (C3) needs to know about who can change a target, decided from the <b>security
/// descriptors</b> of the file and its folders, never from the folder's name. The engine implements it (it reads the
/// ACLs without following links); tests fake it.
/// </summary>
/// <remarks>Implementations never throw for a path problem: anything they can't decide is <see cref="Writability.Unknown"/>.</remarks>
public interface IPathWritability
{
    /// <summary>
    /// Can a standard user change the existing file at <paramref name="filePath"/> (write or append data, change its ACL or
    /// owner)? <see cref="Writability.Unknown"/> when it doesn't exist or can't be checked.
    /// </summary>
    Writability FileModifiable(string filePath);

    /// <summary>
    /// Can a standard user create a file named <paramref name="filePath"/> (or plant one next to it)? Decided by the folder:
    /// it allows new files; or, when the folder doesn't exist, the nearest existing ancestor allows new subfolders (the
    /// creator then owns them). Whether the file itself exists doesn't matter.
    /// </summary>
    Writability FileCreatable(string filePath);
}

/// <summary>An <see cref="IPathWritability"/> that knows nothing (every answer is <see cref="Writability.Unknown"/>).</summary>
public sealed class UnknownWritability : IPathWritability
{
    public static UnknownWritability Instance { get; } = new();

    public Writability FileModifiable(string filePath) => Writability.Unknown;

    public Writability FileCreatable(string filePath) => Writability.Unknown;
}
