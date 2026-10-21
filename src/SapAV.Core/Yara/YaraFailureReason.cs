using System.Text.Json.Serialization;
using SapAV.Core.Hashing;
using SapAV.Core.Serialization;

namespace SapAV.Core.Yara;

/// <summary>
/// Why content was not YARA-scanned (<see cref="None"/> when it was). The file-level reasons mirror
/// <see cref="HashFailureReason"/> one for one (the scanner opens files exactly like the hasher); the last
/// three are YARA-specific. Each maps to one <see cref="Models.ScanStatus"/> via <see cref="YaraScanResult.StatusFor"/>.
/// Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<YaraFailureReason>))]
public enum YaraFailureReason
{
    /// <summary>Scanned (with or without matches).</summary>
    None,

    /// <summary>Empty/whitespace path or one with an embedded NUL or invalid name. Status Error.</summary>
    InvalidPath,

    /// <summary>A device, pipe, console or other non-disk target (also via a link). Status Error.</summary>
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

    /// <summary>The file's size or last-write time changed during the scan. Status Error.</summary>
    ChangedDuringScan,

    /// <summary>Another antivirus blocked the read (ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED). Status Error.</summary>
    BlockedByAntivirus,

    /// <summary>Any other I/O failure, including a page that couldn't be read from the mapped file. Status Error.</summary>
    IoError,

    /// <summary>The scan took longer than the per-scan timeout. Status Error.</summary>
    Timeout,

    /// <summary>
    /// The rule set was disposed (e.g. swapped out by a reload) before this scan could start. Retry with the
    /// current rule set. Status Error.
    /// </summary>
    RulesDisposed,

    /// <summary>The YARA engine reported an error (e.g. out of memory). Status Error.</summary>
    EngineError,
}
