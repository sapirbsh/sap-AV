using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Scanning.Cache;

namespace SapAV.Engine.Persistence;

/// <summary>
/// D4: the sandboxed worker's parse results for task definitions and shortcuts, kept per collector and reused while the file
/// is unchanged, so a re-collection with nothing changed sends nothing to the worker (the C2 timing item: about 7 s for 212
/// task files on the CI runner). Thread-safe (Quick Scan and real-time persistence monitoring share one collector).
/// </summary>
/// <remarks>
/// <para><b>Unchanged</b> means the same <see cref="FileStamp"/>, taken from the handle the collector opened for the parse:
/// the same file object (volume + 128-bit file ID), size, last-write and change time, <b>and the change-journal USN</b>.
/// The times alone could be put back by whoever can write the file (<c>System32\Tasks</c> lets standard users create
/// files); the USN can't. Without a journal (not NTFS / ReFS, or no active journal) there is no stamp and the file is
/// always parsed again. Keyed by the parse kind and the display path, so a file renamed onto another task's name is parsed.</para>
/// <para><b>What is kept:</b> only <see cref="PersistenceParseStatus.Parsed"/> results (the worker's validated output). A
/// Malformed result (a parse error or a worker failure on that file) is never reused: it is asked again next time, and the
/// broker's per-file failure count handles a file that keeps crashing the worker.</para>
/// <para><b>Stamp before parse.</b> The stamp is taken before the worker reads the handle; if a writer changes the file in
/// between, the kept stamp is older than the content, so the next collection sees a different USN and parses again.</para>
/// </remarks>
internal sealed class ParsedFileCache(int maxEntries = ParsedFileCache.DefaultMaxEntries)
{
    /// <summary>Task files (<see cref="ScheduledTaskSource.MaxFiles"/>) plus Startup items of many users.</summary>
    public const int DefaultMaxEntries = 20_000;

    private readonly Lock _lock = new();
    private readonly Dictionary<string, (FileStamp Stamp, PersistenceParseResult Result)> _items = new(StringComparer.Ordinal);

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _items.Count;
            }
        }
    }

    /// <summary>The stamp of an open definition file, or null when the volume has no change journal (then it isn't cached).</summary>
    public static FileStamp? StampOf(SafeFileHandle file)
    {
        try
        {
            return NativeFile.TryGetFileId(file, out ulong volume, out string id) ? FileStamp.Capture(file, new FileIdentity(volume, id, null)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or ObjectDisposedException)
        {
            return null;
        }
    }

    public bool TryGet(WorkerParseKind kind, string displayPath, FileStamp stamp, out PersistenceParseResult result)
    {
        lock (_lock)
        {
            if (_items.TryGetValue(Key(kind, displayPath), out var kept) && kept.Stamp == stamp)
            {
                result = kept.Result;
                return true;
            }
        }

        result = null!;
        return false;
    }

    /// <summary>Keeps a Parsed result; anything else is dropped (and an older result for the same name with it).</summary>
    public void Put(WorkerParseKind kind, string displayPath, FileStamp stamp, PersistenceParseResult result)
    {
        string key = Key(kind, displayPath);
        lock (_lock)
        {
            if (result.Status != PersistenceParseStatus.Parsed)
            {
                _items.Remove(key);
                return;
            }

            if (_items.Count >= maxEntries && !_items.ContainsKey(key))
            {
                _items.Clear(); // bounded: start over rather than track recency
            }

            _items[key] = (stamp, result);
        }
    }

    private static string Key(WorkerParseKind kind, string displayPath) =>
        ((int)kind).ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + displayPath.ToUpperInvariant();
}
