using SapAV.Core.Scanning;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// Counts how often a file version crashed, hung or corrupted a worker. Keyed by the broker's own view of the file
/// (volume serial + file ID, else the path; plus size and last-write time, so an edited file starts over). Bounded:
/// the oldest entries are dropped past <see cref="Capacity"/>. Thread-safe.
/// </summary>
internal sealed class FileFailureTracker(TimeProvider time)
{
    public const int Capacity = 4096;

    private readonly object _gate = new();
    private readonly Dictionary<string, (int Count, DateTimeOffset Last)> _entries = new(StringComparer.Ordinal);

    public static string Key(FileIdentity? identity, string path, long length, DateTime lastWriteUtc) =>
        (identity is null ? "path:" + path.ToUpperInvariant() : $"id:{identity.VolumeSerialNumber:x16}:{identity.FileId}")
        + $"|{length}|{lastWriteUtc.Ticks}";

    public int Count(string key)
    {
        lock (_gate)
        {
            return _entries.TryGetValue(key, out var entry) ? entry.Count : 0;
        }
    }

    /// <summary>Records one more failure and returns the new count.</summary>
    public int Record(string key)
    {
        lock (_gate)
        {
            int count = (_entries.TryGetValue(key, out var entry) ? entry.Count : 0) + 1;
            if (count == 1 && _entries.Count >= Capacity)
            {
                _entries.Remove(_entries.MinBy(e => e.Value.Last).Key);
            }

            _entries[key] = (count, time.GetUtcNow());
            return count;
        }
    }
}
