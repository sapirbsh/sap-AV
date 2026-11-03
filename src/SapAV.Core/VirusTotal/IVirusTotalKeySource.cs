namespace SapAV.Core.VirusTotal;

/// <summary>Where <see cref="VirusTotalLookup"/> gets the key. The returned handle is opaque (<see cref="VirusTotalApiKey"/>).</summary>
public interface IVirusTotalKeySource
{
    /// <summary>The current key, or null if none is set.</summary>
    VirusTotalApiKey? GetKey();
}
