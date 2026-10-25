using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Persistence;

/// <summary>Why a command line has no target path (ROADMAP C2). Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<TargetUnresolvedReason>))]
public enum TargetUnresolvedReason
{
    /// <summary>Empty or only whitespace.</summary>
    EmptyCommand,

    /// <summary>Not parseable (e.g. a NUL character, a lone quote).</summary>
    Malformed,

    /// <summary>Longer than a command line can be.</summary>
    TooLong,

    /// <summary>A <c>%NAME%</c> isn't defined, so the path isn't fully qualified.</summary>
    UnknownEnvironmentVariable,

    /// <summary>A bare name that isn't in System32, Windows or the PATH.</summary>
    NotFoundOnSearchPath,

    /// <summary>A relative path (to an unknown current folder), drive-relative or rooted without a drive.</summary>
    NotFullyQualified,

    /// <summary>A UNC path (<c>\\server\share</c>): never resolved or touched by the engine.</summary>
    NetworkPath,

    /// <summary>A device or object-manager path (<c>\\.\</c>, <c>\\?\GLOBALROOT</c>, <c>\Device\</c>).</summary>
    DevicePath,

    /// <summary>The host runs inline code, there is no file (see <see cref="ResolutionFlag.InlineCommand"/>).</summary>
    InlineCommand,

    /// <summary>The host's payload is a URL (see <see cref="ResolutionFlag.RemotePayload"/>).</summary>
    RemotePayload,

    /// <summary>A host's arguments name no script or DLL.</summary>
    MissingHostArgument,

    /// <summary>A COM handler's CLSID has no (readable) <c>InprocServer32</c>.</summary>
    ComClassNotRegistered,

    /// <summary>A startup item is a symbolic link or junction; the engine doesn't follow links.</summary>
    LinkNotFollowed,

    /// <summary>A shortcut (<c>.lnk</c>) couldn't be parsed, or its target isn't a file-system path.</summary>
    ShortcutUnreadable,

    /// <summary>Hosts nested deeper than the resolver follows (<c>cmd /c cmd /c …</c>).</summary>
    NestingTooDeep,
}
