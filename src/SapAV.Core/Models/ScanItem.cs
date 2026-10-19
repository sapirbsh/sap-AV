using System.Text.Json.Serialization;

namespace SapAV.Core.Models;

/// <summary>A file to be scanned, plus what triggered the scan.</summary>
/// <remarks>
/// In JSON, a missing or null <c>Trigger</c> throws <see cref="System.Text.Json.JsonException"/>
/// (instead of silently defaulting to RealTime); an invalid path throws <see cref="ArgumentException"/>
/// (or a subclass).
/// </remarks>
public sealed record ScanItem
{
    private readonly string _path = string.Empty;
    private readonly ScanTrigger _trigger;

    public ScanItem(string path, ScanTrigger trigger)
    {
        Path = path;
        Trigger = trigger;
    }

    /// <summary>Fully qualified path of the file.</summary>
    /// <exception cref="ArgumentException">The path is empty or not fully qualified.</exception>
    public string Path
    {
        get => _path;
        init
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(Path));
            if (!System.IO.Path.IsPathFullyQualified(value))
            {
                throw new ArgumentException($"Scan path must be fully qualified: '{value}'.", nameof(Path));
            }

            _path = value;
        }
    }

    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined <see cref="ScanTrigger"/>.</exception>
    [JsonRequired]
    public ScanTrigger Trigger
    {
        get => _trigger;
        init
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(nameof(Trigger), value, "Undefined scan trigger.");
            }

            _trigger = value;
        }
    }
}
