using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SapAV.Core.Hashing;

namespace SapAV.Core.VirusTotal;

/// <summary>Lifetimes and size of <see cref="VirusTotalCache"/>.</summary>
public sealed record VirusTotalCacheOptions
{
    /// <summary>
    /// A report where at least one engine flagged the file (default 7 days): detections rarely go away, and a re-check a week later
    /// still picks up changed counts.
    /// </summary>
    public TimeSpan DetectedTtl { get; init; } = TimeSpan.FromDays(7);

    /// <summary>A report with no detections (default 1 day): new malware is often 0/72 on its first day, so clean is re-asked daily.</summary>
    public TimeSpan CleanTtl { get; init; } = TimeSpan.FromDays(1);

    /// <summary>An unknown hash, 404 (default 1 day): someone else may upload the file meanwhile.</summary>
    public TimeSpan NotFoundTtl { get; init; } = TimeSpan.FromDays(1);

    /// <summary>Row cap (default 50,000, roughly 15-20 MB); past it, the oldest rows go (to 90 %).</summary>
    public int MaxEntries { get; init; } = 50_000;

    /// <summary>Hard byte cap through <c>PRAGMA max_page_count</c> (default 64 MiB).</summary>
    public long MaxDatabaseBytes { get; init; } = 64L * 1024 * 1024;

    public TimeSpan BusyTimeout { get; init; } = TimeSpan.FromSeconds(5);

    internal const int PageSize = 4096;

    internal long MaxPageCount => MaxDatabaseBytes / PageSize;

    internal void Validate()
    {
        foreach (var (name, ttl) in new[] { (nameof(DetectedTtl), DetectedTtl), (nameof(CleanTtl), CleanTtl), (nameof(NotFoundTtl), NotFoundTtl) })
        {
            if (ttl <= TimeSpan.Zero || ttl > TimeSpan.FromDays(90))
            {
                throw new ArgumentOutOfRangeException(name, ttl, "A cache lifetime must be between 0 and 90 days.");
            }
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(MaxEntries, 10, nameof(MaxEntries));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxDatabaseBytes, 1024L * 1024, nameof(MaxDatabaseBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(BusyTimeout, TimeSpan.Zero, nameof(BusyTimeout));
    }
}

/// <summary>A cached VirusTotal answer: Found (with its report) or NotFound.</summary>
/// <param name="Sha256">Lowercase SHA-256.</param>
/// <param name="Status"><see cref="VirusTotalStatus.Found"/> or <see cref="VirusTotalStatus.NotFound"/>.</param>
/// <param name="Report">The report for Found, else null.</param>
/// <param name="FetchedAt">When VirusTotal gave the answer.</param>
/// <param name="ExpiresAt">When the row stops being used.</param>
public sealed record VirusTotalCacheEntry(string Sha256, VirusTotalStatus Status, VirusTotalReport? Report, DateTimeOffset FetchedAt, DateTimeOffset ExpiresAt)
{
    /// <summary>How old the answer is at <paramref name="now"/>.</summary>
    public TimeSpan Age(DateTimeOffset now) => now - FetchedAt;
}

/// <summary>
/// VirusTotal result cache (D2): <c>vt.db</c> in the given folder (D3 picks the ACL'd engine folder; tests use temp folders).
/// Same design as the engine's C5 scan cache.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><b>Key</b>: the lowercase SHA-256. Only Found and NotFound are stored; BadKey, quota, transient and error answers never are.</item>
/// <item><b>Lifetimes</b>: <see cref="VirusTotalCacheOptions.DetectedTtl"/> (7 d) for a report with detections,
/// <see cref="VirusTotalCacheOptions.CleanTtl"/> (1 d) for a clean one, <see cref="VirusTotalCacheOptions.NotFoundTtl"/> (1 d) for an
/// unknown hash. Expired rows are misses and are deleted.</item>
/// <item><b>Integrity</b> (review L6): each row has an HMAC-SHA256 over the hash, the answer, every report field, the fetch time and
/// the expiry, keyed with a machine-DPAPI-protected random key (<see cref="LoadOrCreateMacKey"/>). A row that fails the check, or whose
/// fetch time is in the future, is deleted and counted in <see cref="Tampered"/>, never used: a copied or edited database can't turn a
/// flagged file into "VirusTotal: clean" or stretch an old answer's life.</item>
/// <item><b>Size</b>: <see cref="VirusTotalCacheOptions.MaxEntries"/> rows (oldest first out) and a <c>max_page_count</c> byte cap,
/// checked at open and every 500 stores.</item>
/// <item><b>Corruption</b> (SQLITE_CORRUPT / NOTADB, a failed <c>quick_check</c>, an unknown schema version): the files are deleted
/// and the database rebuilt empty (<see cref="Rebuilds"/>, <see cref="LastProblem"/>).</item>
/// <item><b>Threads</b>: a pooled connection per call, writes serialized, a rebuild exclusive against everything.</item>
/// </list>
/// Every method fails soft: a database problem is a miss or a skipped store, never an exception into a scan.
/// </remarks>
public sealed class VirusTotalCache : IDisposable
{
    public const string DatabaseName = "vt.db";
    public const string MacKeyFileName = "vt-cache.key";
    private const int SchemaVersion = 1;
    private const int PruneEvery = 500;
    private const int SqliteCorrupt = 11;
    private const int SqliteNotADatabase = 26;
    private const int SqliteFull = 13;
    private const int MacKeyBytes = 32;
    private const int MaxKeyBlobBytes = 4096;
    private static readonly byte[] MacKeyEntropy = Encoding.UTF8.GetBytes("sap-AV VirusTotal cache HMAC key v1");

    private readonly string _path;
    private readonly byte[] _macKey;
    private readonly VirusTotalCacheOptions _options;
    private readonly TimeProvider _time;
    private readonly string _connectionString;
    private readonly ReaderWriterLockSlim _rebuild = new(LockRecursionPolicy.SupportsRecursion);
    private readonly Lock _writer = new();
    private int _putsSincePrune;
    private long _tampered;
    private int _rebuilds;
    private string? _lastProblem;

    /// <param name="folder">An existing folder for <see cref="DatabaseName"/>.</param>
    /// <param name="macKey">At least 32 bytes (<see cref="LoadOrCreateMacKey"/>).</param>
    public VirusTotalCache(string folder, byte[] macKey, TimeProvider time, VirusTotalCacheOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(folder);
        ArgumentNullException.ThrowIfNull(macKey);
        if (macKey.Length < MacKeyBytes)
        {
            throw new ArgumentException("The cache MAC key must be at least 32 bytes.", nameof(macKey));
        }

        _macKey = (byte[])macKey.Clone();
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options ?? new VirusTotalCacheOptions();
        _options.Validate();
        _path = Path.Combine(folder, DatabaseName);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = Math.Max(1, (int)_options.BusyTimeout.TotalSeconds),
        }.ToString();
        Open();
    }

    /// <summary>
    /// The cache's MAC key from <see cref="MacKeyFileName"/> in <paramref name="folder"/> (machine DPAPI with entropy), created if
    /// missing. A corrupt or foreign key file is replaced with a new key (the old rows then fail their MAC and are dropped: it's a cache).
    /// The engine should call this only on its ACL'd folder.
    /// </summary>
    /// <exception cref="IOException">The key file can't be written.</exception>
    /// <exception cref="UnauthorizedAccessException">The key file can't be written.</exception>
    public static byte[] LoadOrCreateMacKey(string folder)
    {
        ArgumentNullException.ThrowIfNull(folder);
        string path = Path.Combine(folder, MacKeyFileName);
        try
        {
            var info = new FileInfo(path);
            if (info.Exists && info.Length is > 0 and <= MaxKeyBlobBytes)
            {
                var key = MachineDpapi.Unprotect(File.ReadAllBytes(path), MacKeyEntropy);
                if (key.Length == MacKeyBytes)
                {
                    return key;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            // Unreadable or not ours: replaced below.
        }

        var fresh = RandomNumberGenerator.GetBytes(MacKeyBytes);
        string temp = path + ".tmp";
        File.WriteAllBytes(temp, MachineDpapi.Protect(fresh, MacKeyEntropy));
        File.Move(temp, path, overwrite: true);
        return fresh;
    }

    public string DatabasePath => _path;

    /// <summary>Rows that failed the integrity check (deleted when found).</summary>
    public long Tampered => Interlocked.Read(ref _tampered);

    /// <summary>Times the database was deleted and rebuilt.</summary>
    public int Rebuilds => Volatile.Read(ref _rebuilds);

    /// <summary>The last database problem (engine text), or null. For the engine status.</summary>
    public string? LastProblem => Volatile.Read(ref _lastProblem);

    /// <summary>The time-to-live for an answer (Found with detections, Found clean, NotFound).</summary>
    public TimeSpan TtlFor(VirusTotalStatus status, VirusTotalReport? report) => status switch
    {
        VirusTotalStatus.Found when report is { IsDetected: true } => _options.DetectedTtl,
        VirusTotalStatus.Found => _options.CleanTtl,
        VirusTotalStatus.NotFound => _options.NotFoundTtl,
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Only Found and NotFound answers are cached."),
    };

    /// <summary>A fresh, verified entry for the hash, or null (miss, expired, tampered, invalid hash, database problem).</summary>
    public VirusTotalCacheEntry? Get(string sha256)
    {
        if (!Sha256Hex.TryNormalize(sha256, out var hash))
        {
            return null;
        }

        return Run(connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT status, malicious, suspicious, undetected, harmless, total, last_analysis, labels, threat_label,
                       fetched_at, expires_at, mac
                FROM entries WHERE sha256 = $sha
                """;
            command.Parameters.AddWithValue("$sha", hash);
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            var status = (VirusTotalStatus)reader.GetInt32(0);
            VirusTotalReport? report = status == VirusTotalStatus.Found
                ? new VirusTotalReport(reader.GetInt32(1), reader.GetInt32(2), reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5),
                    reader.IsDBNull(6) ? null : DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(6)),
                    SplitLabels(reader.GetString(7)), reader.IsDBNull(8) ? null : reader.GetString(8))
                : null;
            long fetched = reader.GetInt64(9);
            long expires = reader.GetInt64(10);
            var mac = (byte[])reader.GetValue(11);
            reader.Close();

            var now = _time.GetUtcNow();
            var entry = status is VirusTotalStatus.Found or VirusTotalStatus.NotFound
                ? new VirusTotalCacheEntry(hash, status, report, DateTimeOffset.FromUnixTimeMilliseconds(fetched), DateTimeOffset.FromUnixTimeMilliseconds(expires))
                : null;
            if (entry is null || !CryptographicOperations.FixedTimeEquals(mac, Mac(entry))
                || entry.FetchedAt > now + TimeSpan.FromMinutes(5) || entry.ExpiresAt - entry.FetchedAt > TimeSpan.FromDays(90))
            {
                Interlocked.Increment(ref _tampered);
                Volatile.Write(ref _lastProblem, "A VirusTotal cache row failed its integrity check; it was deleted.");
                DeleteCore(connection, hash);
                return null;
            }

            if (entry.ExpiresAt <= now)
            {
                DeleteCore(connection, hash);
                return null;
            }

            return entry;
        }, null);
    }

    /// <summary>Stores a Found or NotFound answer received now. Other statuses are ignored (never cached).</summary>
    /// <returns>The stored entry, or null if not stored.</returns>
    public VirusTotalCacheEntry? Put(string sha256, VirusTotalStatus status, VirusTotalReport? report)
    {
        if (!Sha256Hex.TryNormalize(sha256, out var hash)
            || status is not (VirusTotalStatus.Found or VirusTotalStatus.NotFound)
            || (status == VirusTotalStatus.Found) != (report is not null))
        {
            return null;
        }

        // Millisecond precision, so the MAC of the stored entry matches the one read back.
        var now = DateTimeOffset.FromUnixTimeMilliseconds(_time.GetUtcNow().ToUnixTimeMilliseconds());
        var entry = new VirusTotalCacheEntry(hash, status, report, now, now + TtlFor(status, report));
        bool prune = false;
        bool stored = Run(connection =>
        {
            lock (_writer)
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    INSERT OR REPLACE INTO entries (sha256, status, malicious, suspicious, undetected, harmless, total, last_analysis,
                                                    labels, threat_label, fetched_at, expires_at, mac)
                    VALUES ($sha, $status, $mal, $sus, $und, $harm, $total, $last, $labels, $threat, $fetched, $expires, $mac)
                    """;
                command.Parameters.AddWithValue("$sha", hash);
                command.Parameters.AddWithValue("$status", (int)status);
                command.Parameters.AddWithValue("$mal", report?.Malicious ?? 0);
                command.Parameters.AddWithValue("$sus", report?.Suspicious ?? 0);
                command.Parameters.AddWithValue("$und", report?.Undetected ?? 0);
                command.Parameters.AddWithValue("$harm", report?.Harmless ?? 0);
                command.Parameters.AddWithValue("$total", report?.TotalEngines ?? 0);
                command.Parameters.AddWithValue("$last", report?.LastAnalysisDate is { } d ? d.ToUnixTimeSeconds() : DBNull.Value);
                command.Parameters.AddWithValue("$labels", JoinLabels(report?.Labels));
                command.Parameters.AddWithValue("$threat", (object?)report?.ThreatLabel ?? DBNull.Value);
                command.Parameters.AddWithValue("$fetched", entry.FetchedAt.ToUnixTimeMilliseconds());
                command.Parameters.AddWithValue("$expires", entry.ExpiresAt.ToUnixTimeMilliseconds());
                command.Parameters.AddWithValue("$mac", Mac(entry));
                try
                {
                    command.ExecuteNonQuery();
                }
                catch (SqliteException ex) when ((ex.SqliteErrorCode & 0xFF) == SqliteFull)
                {
                    DeleteOldestLocked(connection, Math.Max(1, CountCore(connection) / 4));
                    command.ExecuteNonQuery();
                }

                prune = ++_putsSincePrune >= PruneEvery;
                if (prune)
                {
                    _putsSincePrune = 0;
                }
            }

            return true;
        }, false);

        if (prune)
        {
            Prune();
        }

        return stored ? entry : null;
    }

    public long Count() => Run(CountCore, 0L);

    /// <summary>Deletes expired rows, then the oldest ones down to 90 % of MaxEntries. Returns rows deleted.</summary>
    public int Prune() => Run(connection =>
    {
        lock (_writer)
        {
            using var expired = connection.CreateCommand();
            expired.CommandText = "DELETE FROM entries WHERE expires_at <= $now";
            expired.Parameters.AddWithValue("$now", _time.GetUtcNow().ToUnixTimeMilliseconds());
            int deleted = expired.ExecuteNonQuery();
            long rows = CountCore(connection);
            if (rows > _options.MaxEntries)
            {
                deleted += DeleteOldestLocked(connection, rows - (long)(_options.MaxEntries * 0.9));
            }

            return deleted;
        }
    }, 0);

    /// <summary>Closes the pooled connections.</summary>
    public void Dispose() => SqliteConnection.ClearPool(new SqliteConnection(_connectionString));

    private static long CountCore(SqliteConnection connection)
    {
        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM entries";
        return (long)count.ExecuteScalar()!;
    }

    private static int DeleteOldestLocked(SqliteConnection connection, long rows)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM entries WHERE sha256 IN (SELECT sha256 FROM entries ORDER BY fetched_at LIMIT $n)";
        command.Parameters.AddWithValue("$n", rows);
        return command.ExecuteNonQuery();
    }

    private void DeleteCore(SqliteConnection connection, string hash)
    {
        lock (_writer)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM entries WHERE sha256 = $sha";
            command.Parameters.AddWithValue("$sha", hash);
            command.ExecuteNonQuery();
        }
    }

    // Labels are single display lines (no control characters), so a line feed separates them unambiguously.
    private static string JoinLabels(IReadOnlyList<string>? labels) => labels is null ? string.Empty : string.Join('\n', labels);

    private static string[] SplitLabels(string value)
    {
        if (value.Length == 0)
        {
            return [];
        }

        var parts = value.Split('\n');
        return parts.Length <= VirusTotalReport.MaxLabels ? parts : parts[..VirusTotalReport.MaxLabels];
    }

    /// <summary>HMAC-SHA256 over the whole entry, length-prefixed so no two entries encode alike.</summary>
    internal byte[] Mac(VirusTotalCacheEntry entry)
    {
        using var buffer = new MemoryStream();
        using (var w = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            w.Write("sap-AV VirusTotal cache row v1");
            w.Write(entry.Sha256);
            w.Write((int)entry.Status);
            var r = entry.Report;
            w.Write(r is not null);
            w.Write(r?.Malicious ?? 0);
            w.Write(r?.Suspicious ?? 0);
            w.Write(r?.Undetected ?? 0);
            w.Write(r?.Harmless ?? 0);
            w.Write(r?.TotalEngines ?? 0);
            w.Write(r?.LastAnalysisDate.HasValue ?? false);
            w.Write(r?.LastAnalysisDate?.ToUnixTimeSeconds() ?? 0);
            w.Write(r?.Labels.Count ?? 0);
            foreach (var label in r?.Labels ?? [])
            {
                w.Write(label);
            }

            w.Write(r?.ThreatLabel is not null);
            w.Write(r?.ThreatLabel ?? string.Empty);
            w.Write(entry.FetchedAt.ToUnixTimeMilliseconds());
            w.Write(entry.ExpiresAt.ToUnixTimeMilliseconds());
        }

        return HMACSHA256.HashData(_macKey, buffer.ToArray());
    }

    // ---- Opening, rebuilding (as in the C5 scan cache) ----

    private void Open()
    {
        string? problem = null;
        try
        {
            using var connection = Connect();
            using (var check = connection.CreateCommand())
            {
                check.CommandText = "PRAGMA quick_check";
                problem = check.ExecuteScalar() as string is "ok" ? null : "the integrity check failed";
            }

            if (problem is null)
            {
                int version = UserVersion(connection);
                problem = version is 0 or SchemaVersion ? null : $"unknown schema version {version}";
            }

            if (problem is null)
            {
                CreateSchema(connection);
            }
        }
        catch (SqliteException ex) when (IsCorruption(ex))
        {
            problem = $"SQLite error {ex.SqliteErrorCode}";
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException)
        {
            Volatile.Write(ref _lastProblem, $"The VirusTotal cache could not be opened ({ex.GetType().Name}); lookups go uncached.");
            return;
        }

        if (problem is not null)
        {
            Rebuild(problem);
            return;
        }

        Prune();
    }

    private void Rebuild(string why)
    {
        _rebuild.EnterWriteLock();
        try
        {
            Interlocked.Increment(ref _rebuilds);
            Volatile.Write(ref _lastProblem, $"The VirusTotal cache was corrupt or unreadable ({why}); it was deleted and rebuilt empty.");
            SqliteConnection.ClearPool(new SqliteConnection(_connectionString));
            foreach (var file in new[] { _path, _path + "-wal", _path + "-shm", _path + "-journal" })
            {
                File.Delete(file);
            }

            using var connection = Connect();
            CreateSchema(connection);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SqliteException)
        {
            Volatile.Write(ref _lastProblem, $"The VirusTotal cache could not be rebuilt ({ex.GetType().Name}); lookups go uncached.");
        }
        finally
        {
            _rebuild.ExitWriteLock();
        }
    }

    private static void CreateSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            PRAGMA page_size = {VirusTotalCacheOptions.PageSize};
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS entries (
                sha256 TEXT NOT NULL PRIMARY KEY,
                status INTEGER NOT NULL,
                malicious INTEGER NOT NULL,
                suspicious INTEGER NOT NULL,
                undetected INTEGER NOT NULL,
                harmless INTEGER NOT NULL,
                total INTEGER NOT NULL,
                last_analysis INTEGER,
                labels TEXT NOT NULL,
                threat_label TEXT,
                fetched_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                mac BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS entries_fetched_at ON entries (fetched_at);
            PRAGMA user_version = {SchemaVersion};
            """;
        command.ExecuteNonQuery();
    }

    private static int UserVersion(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version";
        return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private SqliteConnection Connect()
    {
        var connection = new SqliteConnection(_connectionString);
        try
        {
            connection.Open();
            using var pragmas = connection.CreateCommand();
            pragmas.CommandText = $"PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = {(int)_options.BusyTimeout.TotalMilliseconds}; "
                + $"PRAGMA trusted_schema = OFF; PRAGMA max_page_count = {_options.MaxPageCount};";
            pragmas.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private T Run<T>(Func<SqliteConnection, T> call, T fallback)
    {
        bool corrupt = false;
        string? why = null;
        _rebuild.EnterReadLock();
        try
        {
            using var connection = Connect();
            return call(connection);
        }
        catch (SqliteException ex) when (IsCorruption(ex))
        {
            corrupt = true;
            why = $"SQLite error {ex.SqliteErrorCode}";
        }
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidCastException or InvalidOperationException
            or FormatException or ArgumentException or OverflowException)
        {
            // A wrong-typed or out-of-range value in a row (hand-edited database) is a miss, like any other database problem.
            Volatile.Write(ref _lastProblem, $"A VirusTotal cache call failed ({ex.GetType().Name}).");
        }
        finally
        {
            _rebuild.ExitReadLock();
        }

        if (corrupt)
        {
            Rebuild(why!);
        }

        return fallback;
    }

    private static bool IsCorruption(SqliteException ex) => (ex.SqliteErrorCode & 0xFF) is SqliteCorrupt or SqliteNotADatabase;
}
