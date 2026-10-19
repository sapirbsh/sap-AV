using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Models;

/// <summary>
/// Whether a file was actually scanned. Anything other than <see cref="Scanned"/> means
/// there is no verdict for the file. Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<ScanStatus>))]
public enum ScanStatus
{
    Scanned,
    SkippedTooLarge,
    AccessDenied,
    Locked,
    Error,

    /// <summary>
    /// Not read because the file is offline or a cloud placeholder (e.g. OneDrive "online-only"),
    /// so scanning doesn't trigger a download.
    /// </summary>
    SkippedOffline,
}
