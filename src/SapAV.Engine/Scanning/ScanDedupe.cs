using SapAV.Core.Hashing;
using SapAV.Core.Scanning;

namespace SapAV.Engine.Scanning;

/// <summary>
/// C4: "one scan per file" across the phases of a job (Quick Scan: processes, persistence, folders, recent files).
/// Two levels:
/// <list type="bullet">
/// <item><b>Paths</b> (<see cref="TryAddPath"/>, case-insensitive, exact <c>\\?\</c> form): a file queued once isn't opened
/// again when a later phase lists it. Capped at <see cref="MaxPaths"/>; past the cap only the identity level applies.</item>
/// <item><b>File identity</b> (<see cref="TryClaim"/>, volume serial + file ID from the scan's own handle): catches the same
/// file under another name (8.3 name, hard link, a persistence target spelled differently). The first claim scans; every
/// later one is a duplicate. Capped at <see cref="MaxIdentities"/>; past the cap files are scanned again rather than missed.</item>
/// </list>
/// While <see cref="KeepReports"/> is on (the phases before persistence), the reports are kept (up to
/// <see cref="MaxReports"/>), so the persistence judgement reuses a running program's scan instead of scanning it twice.
/// Thread-safe.
/// <para>Review C4 L6: memory is bounded for a Full Scan of whole drives: at most 100k paths (the phases that list the
/// same folders twice need them; a Full Scan's drive walk emits every file once anyway), at most 250k identities as
/// 24-byte <see cref="IdentityKey"/> values (a few MB), and the kept reports. Past a cap the dedupe stops recording and
/// a file seen again is scanned again (the scan cache, C5, makes that cheap); nothing is ever missed.</para>
/// </summary>
internal sealed class ScanDedupe(int maxPaths = 100_000, int maxIdentities = 250_000, int maxReports = 16_384)
{
    private readonly Lock _lock = new();
    private readonly HashSet<string> _paths = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<IdentityKey, FileScanReport?> _identities = [];
    private int _reports;
    private long _duplicates;

    public int MaxPaths { get; } = maxPaths;

    public int MaxIdentities { get; } = maxIdentities;

    public int MaxReports { get; } = maxReports;

    /// <summary>Keep the reports of files scanned from now on (for <see cref="TryClaim"/>'s prior report).</summary>
    public bool KeepReports { get; set; }

    /// <summary>Files skipped because they were already queued or scanned in this job.</summary>
    public long Duplicates
    {
        get
        {
            lock (_lock)
            {
                return _duplicates;
            }
        }
    }

    /// <summary>True the first time a path is seen (or once the path cap is reached); false = already queued, skip it.</summary>
    public bool TryAddPath(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string key = ExactPath.ToExtended(path) ?? path;
        lock (_lock)
        {
            if (_paths.Contains(key))
            {
                _duplicates++;
                return false;
            }

            if (_paths.Count < MaxPaths)
            {
                _paths.Add(key);
            }

            return true;
        }
    }

    /// <summary>True (counted as a duplicate) if the path was already recorded; records nothing (see <see cref="Remember"/>).</summary>
    public bool SeenPath(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string key = ExactPath.ToExtended(path) ?? path;
        lock (_lock)
        {
            if (!_paths.Contains(key))
            {
                return false;
            }

            _duplicates++;
            return true;
        }
    }

    /// <summary>Records a path that is queued or scanned (inline), so later phases don't queue it; not counted as a duplicate.</summary>
    public void Remember(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string key = ExactPath.ToExtended(path) ?? path;
        lock (_lock)
        {
            if (_paths.Count < MaxPaths)
            {
                _paths.Add(key);
            }
        }
    }

    /// <summary>
    /// True if this job hasn't scanned the file yet (the caller scans it, then calls <see cref="Complete"/>). False for a
    /// duplicate, with the earlier report when it was kept (null while that scan is still running, or not kept).
    /// </summary>
    public bool TryClaim(FileIdentity identity, out FileScanReport? prior)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var key = IdentityKey.Of(identity);
        lock (_lock)
        {
            if (_identities.TryGetValue(key, out prior))
            {
                _duplicates++;
                return false;
            }

            if (_identities.Count < MaxIdentities)
            {
                _identities[key] = null;
            }

            return true;
        }
    }

    /// <summary>The scan of a claimed file finished; its report is kept while <see cref="KeepReports"/> is on.</summary>
    public void Complete(FileIdentity identity, FileScanReport report)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(report);
        var key = IdentityKey.Of(identity);
        lock (_lock)
        {
            if (KeepReports && _reports < MaxReports && _identities.ContainsKey(key))
            {
                _identities[key] = report;
                _reports++;
            }
        }
    }
}

/// <summary>
/// Review C4 L6: a file identity as a 24-byte value (volume serial + 128-bit file ID) instead of a string tuple, so a
/// Full Scan's identity set costs a fixed, small amount per file. The hex file ID from <see cref="FileIdentity"/> is
/// parsed once; an ID that doesn't parse (never from NTFS / ReFS) falls back to a hash of the string, which can only
/// make two files look like one if both the volume and that 128-bit hash collide.
/// </summary>
internal readonly record struct IdentityKey(ulong Volume, UInt128 FileId)
{
    public static IdentityKey Of(FileIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!UInt128.TryParse(identity.FileId, System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture,
                out var id))
        {
            var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(identity.FileId));
            id = System.Buffers.Binary.BinaryPrimitives.ReadUInt128LittleEndian(hash);
        }

        return new IdentityKey(identity.VolumeSerialNumber, id);
    }
}
