using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Hashing;

/// <summary>
/// Machine-readable reason why content was not hashed (<see cref="None"/> when it was), so callers don't
/// parse <see cref="HashResult.ErrorMessage"/>. Each reason maps to one <see cref="Models.ScanStatus"/>
/// via <see cref="HashResult.StatusFor"/>. Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<HashFailureReason>))]
public enum HashFailureReason
{
    /// <summary>Hashed successfully.</summary>
    None,

    /// <summary>Empty/whitespace path or one with an embedded NUL or invalid name. Status Error.</summary>
    InvalidPath,

    /// <summary>A device, pipe, console or other non-disk target (also via a symlink). Status Error.</summary>
    NotRegularFile,

    /// <summary>The path is a directory. Status Error.</summary>
    Directory,

    /// <summary>The file or a parent directory does not exist. Status Error.</summary>
    NotFound,

    /// <summary>Permission denied. Status AccessDenied.</summary>
    AccessDenied,

    /// <summary>Sharing or byte-range lock violation. Status Locked.</summary>
    Locked,

    /// <summary>Over the size limit. Status SkippedTooLarge.</summary>
    TooLarge,

    /// <summary>Offline file or cloud placeholder; not read to avoid a download. Status SkippedOffline.</summary>
    Offline,

    /// <summary>The file was modified while being hashed; the hash would be unreliable. Status Error.</summary>
    ChangedDuringHashing,

    /// <summary>
    /// Windows refused the read because another antivirus flagged the file
    /// (ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED). Status Error.
    /// </summary>
    BlockedByAntivirus,

    /// <summary>Any other I/O failure. Status Error.</summary>
    IoError,
}
