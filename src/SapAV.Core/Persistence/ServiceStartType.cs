using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Persistence;

/// <summary>A service's <c>Start</c> value. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<ServiceStartType>))]
public enum ServiceStartType
{
    Boot,
    System,
    Automatic,
    Manual,
    Disabled,

    /// <summary>Missing or not 0-4.</summary>
    Unknown,
}
