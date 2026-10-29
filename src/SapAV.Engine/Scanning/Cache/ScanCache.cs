using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SapAV.Core.Blocklist;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Scanning.Cache;

/// <summary>What a cached verdict must have been made under to be used now.</summary>
/// <param name="RulesFingerprint">The YARA rule set the workers have loaded (<see cref="RulesLoadSummary.Fingerprint"/>).</param>
/// <param name="Blocklist">The engine's own copy of the current blocklist (every hit's SHA-256 is checked against it).</param>
internal sealed record ScanCacheContext(string RulesFingerprint, HashBlocklist Blocklist, string EngineVersion);

/// <summary>The current fingerprints; null while they aren't known (then the cache isn't used). Fake it in tests.</summary>
internal interface IScanCacheFingerprints
{
    ScanCacheContext? Current();
}

/// <summary>
/// The engine's fingerprints: the rules fingerprint from the broker's last load, and the blocklist loaded by the engine
/// itself from the same engine-owned file the workers get (it is engine data, a list of hashes, not scanned file content).
/// The blocklist is re-read whenever the broker reports a new rule load. If it can't be read, the cache is off until the
/// next load (a cached Clean must never skip a blocklist it can't check).
/// </summary>
internal sealed class EngineScanFingerprints(IScanBroker broker, string blocklistPath, ILogger logger) : IScanCacheFingerprints
{
    private readonly Lock _lock = new();
    private RulesLoadSummary? _loadedFor;
    private HashBlocklist? _blocklist;

    public ScanCacheContext? Current()
    {
        if (broker.Status.Rules is not { } rules)
        {
            return null;
        }

        lock (_lock)
        {
            if (!ReferenceEquals(rules, _loadedFor))
            {
                _loadedFor = rules;
                try
                {
                    _blocklist = HashBlocklist.LoadAsync(blocklistPath).GetAwaiter().GetResult();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
                {
                    _blocklist = null;
                    logger.LogWarning("The scan cache can't read the blocklist ({Why}); scanning uncached until the next rule load.", ex.Message);
                }
            }

            return _blocklist is null ? null : new ScanCacheContext(rules.Fingerprint, _blocklist, EngineInfo.Version);
        }
    }
}

/// <summary>Counters for the log, the status and tests.</summary>
internal sealed record ScanCacheStats(long Hits, long Misses, long Stores, long BlocklistUpgrades, long Tampered, int Rebuilds, string? LastProblem);

/// <summary>
/// The scan cache (ROADMAP C5): skip a file the engine already judged when nothing about it changed.
/// <para><b>Lookup</b> runs after the hardened open, on the scan's own handle (<see cref="FileStamp"/>). A row is a hit only
/// if <b>all</b> of these match: the file object (volume serial + 128-bit file ID: the key), the exact path
/// (case-insensitive), size, last-write time, change time, the USN (both absent, or equal), the YARA rules fingerprint and
/// the engine version. Every hit's SHA-256 is then checked against the current blocklist (an O(1) lookup, no re-read): a
/// match makes it Malicious right there (the row is dropped and the normal verdict handler quarantines through the open
/// handle, which re-hashes the file first). A blocklist change therefore never needs a rescan, and a rules change makes
/// every row a miss (YARA must run again).</para>
/// <para><b>Rename</b>: a hit by identity at a new path does <b>not</b> count. The verdict depends on the path (double
/// extension, Temp / Downloads location heuristics), so a renamed file is scanned again and its row replaced.</para>
/// <para><b>Never cached</b> (the caller only offers engine / administrator-perspective scans of local files opened with
/// writers denied, see <see cref="ScanFilePipeline"/>): NotScanned results, Malicious ones (they are quarantined or need the
/// user), a SHA-256 the current blocklist lists, reports without a complete YARA scan under the current rules, without a
/// hash or identity, or larger than <see cref="ScanCacheOptions.MaxReportBytes"/>.</para>
/// <para>A hit's report is the stored worker report rebuilt through <see cref="WireReportCodec.FromWire"/> (treated as
/// untrusted, like a worker's), with the scan's own identity and a note saying it came from the cache. Never throws:
/// anything wrong is a miss.</para>
/// </summary>
internal sealed class ScanCache : IDisposable
{
    private readonly ScanCacheStore _store;
    private readonly IScanCacheFingerprints _fingerprints;
    private readonly ScanCacheOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private long _hits, _misses, _stores, _upgrades;

    public ScanCache(ScanCacheStore store, IScanCacheFingerprints fingerprints, ScanCacheOptions options, TimeProvider time, ILogger logger)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _fingerprints = fingerprints ?? throw new ArgumentNullException(nameof(fingerprints));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    internal ScanCacheStore Store => _store;

    public ScanCacheStats Stats => new(Interlocked.Read(ref _hits), Interlocked.Read(ref _misses), Interlocked.Read(ref _stores),
        Interlocked.Read(ref _upgrades), _store.Tampered, _store.Rebuilds, _store.LastProblem);

    /// <summary>
    /// The engine's cache, or null when it is off or can't be used safely (logged): the protected folder, its DPAPI key and
    /// the database. Scans then simply run uncached.
    /// </summary>
    internal static ScanCache? TryCreate(
        ScanCacheOptions options, string blocklistPath, IScanBroker broker, IQuarantineKeyProvider keys, QuarantineAccessPolicy policy,
        TimeProvider time, ILogger logger, bool? parentIsDataRoot = null, IScanCacheFingerprints? fingerprints = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.Enabled)
        {
            logger.LogInformation("The scan cache is turned off; every file is scanned every time.");
            return null;
        }

        try
        {
            options.Validate();
            string folder = ScanCacheFolder.Ensure(options.ResolvedFolder, policy, parentIsDataRoot);
            var key = keys.GetOrCreateKey(folder, policy);
            var store = new ScanCacheStore(folder, key, options, time, logger);
            logger.LogInformation("Scan cache: {Path} ({Rows} rows).", store.DatabasePath, store.Count());
            return new ScanCache(store, fingerprints ?? new EngineScanFingerprints(broker, blocklistPath, logger), options, time, logger);
        }
        catch (Exception ex) when (ex is QuarantineStoreException or IOException or UnauthorizedAccessException or SqliteException
            or CryptographicException or ArgumentException)
        {
            logger.LogWarning("The scan cache is not available ({Why}); files are scanned uncached.", ex.Message);
            return null;
        }
    }

    /// <summary>The cached report for this open file, or null (a miss).</summary>
    /// <param name="item">The scan item, already in its canonical path (the handle's final path).</param>
    public FileScanReport? TryHit(ScanItem item, OpenedScanFile opened, FileStamp stamp, IReadOnlyList<ScanNote> openNotes)
    {
        try
        {
            var hit = Hit(item, opened, stamp, openNotes);
            Interlocked.Increment(ref hit is null ? ref _misses : ref _hits);
            return hit;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Scan cache lookup failed for {Path}; scanning it.", item.Path);
            Interlocked.Increment(ref _misses);
            return null;
        }
    }

    /// <summary>Caches a fresh report if it may be cached (see the class remarks). True if it was stored.</summary>
    public bool TryStore(ScanItem item, FileStamp stamp, FileScanReport report)
    {
        try
        {
            if (Row(item, stamp, report) is not { } row)
            {
                return false;
            }

            _store.Put(row);
            Interlocked.Increment(ref _stores);
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogWarning(ex, "Scan cache store failed for {Path}.", item.Path);
            return false;
        }
    }

    public void Dispose() => _store.Dispose();

    /// <summary>The cache key's path: the exact <c>\\?\</c> form (compared case-insensitively).</summary>
    internal static string KeyPath(string path) => Core.Hashing.ExactPath.ToExtended(path) ?? path;

    private FileScanReport? Hit(ScanItem item, OpenedScanFile opened, FileStamp stamp, IReadOnlyList<ScanNote> openNotes)
    {
        if (_fingerprints.Current() is not { } context || _store.Get(stamp.Volume, stamp.FileId) is not { } row)
        {
            return null;
        }

        if (!Matches(row, stamp, KeyPath(item.Path), context))
        {
            return null; // replaced by this scan's store
        }

        var now = _time.GetUtcNow();
        FileScanReport cached;
        try
        {
            cached = WireReportCodec.FromWire(WorkerJson.Deserialize<WireScanReport>(row.Report), item, now);
        }
        catch (WorkerProtocolException ex)
        {
            _logger.LogWarning("A scan cache row for {Path} doesn't rebuild ({Why}); it was dropped.", item.Path, ex.Message);
            _store.Delete(stamp.Volume, stamp.FileId);
            return null;
        }

        var result = cached.Result;
        if (result.Status != ScanStatus.Scanned || result.Verdict is not (Verdict.Clean or Verdict.Suspicious) || result.Verdict != row.Verdict
            || !string.Equals(result.Sha256, row.Sha256, StringComparison.Ordinal) || cached.Hash.Length != stamp.Size)
        {
            _store.Delete(stamp.Volume, stamp.FileId);
            return null;
        }

        var notes = new List<ScanNote>(openNotes)
        {
            new(ScanNoteLevel.Information, $"Verdict from the scan cache: unchanged since it was scanned at {DateTimeOffset.FromUnixTimeMilliseconds(row.ScannedAt):u}."),
        };

        if (context.Blocklist.TryMatch(row.Sha256, out var blocked))
        {
            // The blocklist changed since: Malicious without reading the file again; never cached from here on.
            _store.Delete(stamp.Volume, stamp.FileId);
            Interlocked.Increment(ref _upgrades);
            notes.Add(new(ScanNoteLevel.Warning, "The cached file's SHA-256 is now in the blocklist."));
            var upgraded = new ScanResult(item, [blocked, .. result.Detections], now, result.Sha256, ScanStatus.Scanned, result.SignatureStatus, result.Signer);
            return cached with { Result = upgraded, Identity = opened.Identity, Notes = notes.AsReadOnly() };
        }

        if (!string.Equals(row.BlocklistFingerprint, context.Blocklist.Fingerprint, StringComparison.Ordinal))
        {
            _store.Put(row with { BlocklistFingerprint = context.Blocklist.Fingerprint, LastUsed = now.ToUnixTimeMilliseconds() });
        }
        else
        {
            _store.Touch(row);
        }

        return cached with { Identity = opened.Identity, Notes = notes.AsReadOnly() };
    }

    /// <summary>Every hit condition except the blocklist (that one is re-checked, not compared).</summary>
    internal static bool Matches(ScanCacheRow row, FileStamp stamp, string keyPath, ScanCacheContext context) =>
        row.Stamp == stamp
        && string.Equals(row.Path, keyPath, StringComparison.OrdinalIgnoreCase)
        && string.Equals(row.RulesFingerprint, context.RulesFingerprint, StringComparison.Ordinal)
        && string.Equals(row.EngineVersion, context.EngineVersion, StringComparison.Ordinal);

    private ScanCacheRow? Row(ScanItem item, FileStamp stamp, FileScanReport report)
    {
        var result = report.Result;
        if (_fingerprints.Current() is not { } context
            || result.Status != ScanStatus.Scanned
            || result.Verdict is not (Verdict.Clean or Verdict.Suspicious)
            || result.Sha256 is not { } sha
            || !report.Hash.IsHashed || report.Hash.Length != stamp.Size
            || report.Identity is null
            || report.Yara is not { Status: ScanStatus.Scanned, RulesFingerprint: { } rules }
            || !string.Equals(rules, context.RulesFingerprint, StringComparison.Ordinal)
            || context.Blocklist.Contains(sha))
        {
            return null;
        }

        byte[] bytes;
        try
        {
            bytes = WorkerJson.Serialize(WireReportCodec.ToWire(report with { Notes = [] }), _options.MaxReportBytes);
        }
        catch (WorkerProtocolException)
        {
            return null; // too large to keep
        }

        long now = _time.GetUtcNow().ToUnixTimeMilliseconds();
        string summary = result.Detections.Count == 0
            ? "Clean"
            : string.Join("; ", result.Detections.Take(3).Select(d => $"{d.Verdict} {d.Source} {d.TechniqueId}"));
        return new ScanCacheRow(stamp, KeyPath(item.Path), sha, result.Verdict.Value, summary, result.SignatureStatus, rules,
            context.Blocklist.Fingerprint, context.EngineVersion, bytes, now, now);
    }
}
