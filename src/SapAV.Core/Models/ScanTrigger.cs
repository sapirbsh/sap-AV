using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Models;

/// <summary>What caused an item to be scanned. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<ScanTrigger>))]
public enum ScanTrigger
{
    RealTime,
    QuickScan,
    FullScan,
    CustomScan,
    Persistence,
}
