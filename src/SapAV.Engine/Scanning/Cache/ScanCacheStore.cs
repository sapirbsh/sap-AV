using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SapAV.Core.Models;
using SapAV.Core.Signatures;

namespace SapAV.Engine.Scanning.Cache;

/// <summary>One cached verdict (C5): the file it was made for and what it was made under.</summary>
/// <param name="Path">The file's exact path (<c>\\?\</c> form) when it was scanned; compared case-insensitively.</param>
/// <param name="Summary">A short engine-side summary of the detections (for diagnostics; the report carries them).</param>
/// <param name="Report">The scan worker's wire report (<see cref="Core.Scanning.Isolation.WireScanReport"/>, notes stripped), as strict JSON.</param>
/// <param name="ScannedAt">Unix milliseconds of the scan.</param>
/// <param name="LastUsed">Unix milliseconds of the last store or hit (for pruning; not covered by the MAC).</param>
internal sealed record ScanCacheRow(
    FileStamp Stamp, string Path, string Sha256, Verdict Verdict, string Summary, SignatureStatus? SignatureStatus,
    string RulesFingerprint, string BlocklistFingerprint, string EngineVersion, byte[] Report, long ScannedAt, long LastUsed);

/// <summary>
/// The scan cache's SQLite database (C5): <c>scan.db</c> in the protected cache folder, written only by the engine.
/// <list type="bullet">
/// <item><b>Key</b>: volume serial + 128-bit file ID (one row per file object). The exact path, size, last-write and change
/// time, USN, SHA-256, verdict, signature status, the rules / blocklist fingerprints and the engine version are values the
/// caller compares (<see cref="ScanCache"/>).</item>
/// <item><b>Integrity</b>: each row carries an HMAC-SHA256 over every value except <c>last_used</c>, keyed with a random key
/// kept DPAPI-machine-protected next to the database (the quarantine's key mechanism). A row whose MAC doesn't verify is
/// deleted and counted as tampered, never used. The ACL is the main protection; the MAC stops a copied or hand-edited
/// database (by anything that can't also read the DPAPI-protected key) from passing a file off as Clean.</item>
/// <item><b>SQL</b>: parameterized statements only, WAL journal, <c>synchronous=NORMAL</c>, a busy timeout.</item>
/// <item><b>Threads</b>: a connection per call from the pool (WAL lets reads run beside the one writer), all writes
/// serialized by one lock (single writer), a rebuild exclusive against everything.</item>
/// <item><b>Corruption</b> (SQLITE_CORRUPT / NOTADB, a failed <c>quick_check</c>, an unknown schema version): the files
/// are deleted and the database rebuilt empty, logged as a warning and recorded in <see cref="LastProblem"/>.</item>
/// <item><b>Size</b>: rows unused for <see cref="ScanCacheOptions.MaxAge"/> are pruned, and past
/// <see cref="ScanCacheOptions.MaxEntries"/> the least recently used ones (to 90 %), at open and every 1,000 stores.</item>
/// </list>
/// Every method fails soft: a database problem is a miss / a skipped store, never a scan failure.
/// </summary>
internal sealed class ScanCacheStore : IDisposable
{
    public const string DatabaseName = "scan.db";
    private const int SchemaVersion = 1;
    private const int PruneEvery = 1000;
    private const int SqliteCorrupt = 11;
    private const int SqliteNotADatabase = 26;

    private readonly string _path;
    private readonly byte[] _macKey;
    private readonly ScanCacheOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly string _connectionString;
    private readonly ReaderWriterLockSlim _rebuild = new(LockRecursionPolicy.SupportsRecursion);
    private readonly Lock _writer = new();
    private int _putsSincePrune;
    private long _tampered;
    private int _rebuilds;
    private string? _lastProblem;

    public ScanCacheStore(string folder, byte[] macKey, ScanCacheOptions options, TimeProvider time, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(folder);
        ArgumentNullException.ThrowIfNull(macKey);
        if (macKey.Length < 32)
        {
            throw new ArgumentException("The cache MAC key must be at least 32 bytes.", nameof(macKey));
        }

        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _macKey = macKey;
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

    public string DatabasePath => _path;

    /// <summary>Rows whose MAC didn't verify (deleted when found).</summary>
    public long Tampered => Interlocked.Read(ref _tampered);

    /// <summary>Times the database was deleted and rebuilt because it was corrupt or unreadable.</summary>
    public int Rebuilds => Volatile.Read(ref _rebuilds);

    /// <summary>The last problem (corruption, I/O), engine text; null if none. For the engine status (health note).</summary>
    public string? LastProblem => Volatile.Read(ref _lastProblem);

    /// <summary>The row of a file object whose MAC verifies, or null.</summary>
    public ScanCacheRow? Get(ulong volume, UInt128 fileId) => Run(connection =>
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT path, size, last_write, change_time, usn, sha256, verdict, summary, signature_status, rules_fp, blocklist_fp,
                   engine_version, report, scanned_at, last_used, mac
            FROM entries WHERE volume = $volume AND file_id = $fileId
            """;
        AddKey(command, volume, fileId);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var row = new ScanCacheRow(
            new FileStamp(volume, fileId, reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), reader.IsDBNull(4) ? null : reader.GetInt64(4)),
            reader.GetString(0), reader.GetString(5), (Verdict)reader.GetInt32(6), reader.GetString(7),
            reader.IsDBNull(8) ? null : (SignatureStatus)reader.GetInt32(8), reader.GetString(9), reader.GetString(10), reader.GetString(11),
            (byte[])reader.GetValue(12), reader.GetInt64(13), reader.GetInt64(14));
        var mac = (byte[])reader.GetValue(15);
        reader.Close();
        if (!CryptographicOperations.FixedTimeEquals(mac, Mac(row)))
        {
            Interlocked.Increment(ref _tampered);
            _logger.LogWarning("Scan cache row for file {FileId:x} on volume {Volume:x} failed its integrity check; it was deleted.", fileId, volume);
            DeleteCore(connection, volume, fileId);
            return null;
        }

        return row;
    }, null);

    /// <summary>Inserts or replaces the row of <paramref name="row"/>'s file object.</summary>
    public void Put(ScanCacheRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        bool prune = false;
        Run(connection =>
        {
            lock (_writer)
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    INSERT INTO entries (volume, file_id, path, size, last_write, change_time, usn, sha256, verdict, summary, signature_status,
                                         rules_fp, blocklist_fp, engine_version, report, scanned_at, last_used, mac)
                    VALUES ($volume, $fileId, $path, $size, $lastWrite, $change, $usn, $sha, $verdict, $summary, $signature,
                            $rules, $blocklist, $engine, $report, $scannedAt, $lastUsed, $mac)
                    ON CONFLICT (volume, file_id) DO UPDATE SET
                        path = excluded.path, size = excluded.size, last_write = excluded.last_write, change_time = excluded.change_time,
                        usn = excluded.usn, sha256 = excluded.sha256, verdict = excluded.verdict, summary = excluded.summary,
                        signature_status = excluded.signature_status, rules_fp = excluded.rules_fp, blocklist_fp = excluded.blocklist_fp,
                        engine_version = excluded.engine_version, report = excluded.report, scanned_at = excluded.scanned_at,
                        last_used = excluded.last_used, mac = excluded.mac
                    """;
                AddKey(command, row.Stamp.Volume, row.Stamp.FileId);
                command.Parameters.AddWithValue("$path", row.Path);
                command.Parameters.AddWithValue("$size", row.Stamp.Size);
                command.Parameters.AddWithValue("$lastWrite", row.Stamp.LastWriteTime);
                command.Parameters.AddWithValue("$change", row.Stamp.ChangeTime);
                command.Parameters.AddWithValue("$usn", (object?)row.Stamp.Usn ?? DBNull.Value);
                command.Parameters.AddWithValue("$sha", row.Sha256);
                command.Parameters.AddWithValue("$verdict", (int)row.Verdict);
                command.Parameters.AddWithValue("$summary", row.Summary);
                command.Parameters.AddWithValue("$signature", row.SignatureStatus is { } s ? (int)s : DBNull.Value);
                command.Parameters.AddWithValue("$rules", row.RulesFingerprint);
                command.Parameters.AddWithValue("$blocklist", row.BlocklistFingerprint);
                command.Parameters.AddWithValue("$engine", row.EngineVersion);
                command.Parameters.AddWithValue("$report", row.Report);
                command.Parameters.AddWithValue("$scannedAt", row.ScannedAt);
                command.Parameters.AddWithValue("$lastUsed", row.LastUsed);
                command.Parameters.AddWithValue("$mac", Mac(row));
                command.ExecuteNonQuery();
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
    }

    /// <summary>Removes a file object's row (e.g. it turned out Malicious under a new blocklist).</summary>
    public void Delete(ulong volume, UInt128 fileId) => Run(connection =>
    {
        DeleteCore(connection, volume, fileId);
        return true;
    }, false);

    /// <summary>Marks a row as used now (not covered by the MAC; at most once per hour per row, to keep hits read-only).</summary>
    public void Touch(ScanCacheRow row)
    {
        long now = _time.GetUtcNow().ToUnixTimeMilliseconds();
        if (now - row.LastUsed < (long)TimeSpan.FromHours(1).TotalMilliseconds)
        {
            return;
        }

        Run(connection =>
        {
            lock (_writer)
            {
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE entries SET last_used = $now WHERE volume = $volume AND file_id = $fileId";
                AddKey(command, row.Stamp.Volume, row.Stamp.FileId);
                command.Parameters.AddWithValue("$now", now);
                command.ExecuteNonQuery();
            }

            return true;
        }, false);
    }

    public long Count() => Run(connection =>
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM entries";
        return (long)command.ExecuteScalar()!;
    }, 0L);

    /// <summary>Deletes rows unused for longer than MaxAge, then the least recently used ones down to 90 % of MaxEntries.</summary>
    /// <returns>Rows deleted.</returns>
    public int Prune() => Run(connection =>
    {
        lock (_writer)
        {
            using var old = connection.CreateCommand();
            old.CommandText = "DELETE FROM entries WHERE last_used < $cutoff";
            old.Parameters.AddWithValue("$cutoff", (_time.GetUtcNow() - _options.MaxAge).ToUnixTimeMilliseconds());
            int deleted = old.ExecuteNonQuery();

            using var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM entries";
            long rows = (long)count.ExecuteScalar()!;
            if (rows > _options.MaxEntries)
            {
                using var lru = connection.CreateCommand();
                lru.CommandText = """
                    DELETE FROM entries WHERE (volume, file_id) IN
                        (SELECT volume, file_id FROM entries ORDER BY last_used LIMIT $excess)
                    """;
                lru.Parameters.AddWithValue("$excess", rows - (long)(_options.MaxEntries * 0.9));
                deleted += lru.ExecuteNonQuery();
            }

            if (deleted > 0)
            {
                _logger.LogInformation("Scan cache: pruned {Rows} rows.", deleted);
            }

            return deleted;
        }
    }, 0);

    /// <summary>Closes the pooled connections (the lock stays usable: a late call simply opens a new connection).</summary>
    public void Dispose() => SqliteConnection.ClearPool(new SqliteConnection(_connectionString));

    // ---- Opening, rebuilding ----

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

        if (problem is not null)
        {
            Rebuild(problem); // the connection is closed by now, so the files can be deleted
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
            Volatile.Write(ref _lastProblem, $"The scan cache was corrupt or unreadable ({why}); it was deleted and rebuilt empty.");
            _logger.LogWarning("Scan cache {Path} was corrupt or unreadable ({Why}); deleting it and starting empty.", _path, why);
            SqliteConnection.ClearAllPools();
            foreach (var file in new[] { _path, _path + "-wal", _path + "-shm", _path + "-journal" })
            {
                File.Delete(file);
            }

            using var connection = Connect();
            CreateSchema(connection);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SqliteException)
        {
            Volatile.Write(ref _lastProblem, $"The scan cache could not be rebuilt ({ex.GetType().Name}); files are scanned uncached.");
            _logger.LogError(ex, "Scan cache {Path} could not be rebuilt.", _path);
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
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS entries (
                volume INTEGER NOT NULL,
                file_id BLOB NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                last_write INTEGER NOT NULL,
                change_time INTEGER NOT NULL,
                usn INTEGER,
                sha256 TEXT NOT NULL,
                verdict INTEGER NOT NULL,
                summary TEXT NOT NULL,
                signature_status INTEGER,
                rules_fp TEXT NOT NULL,
                blocklist_fp TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                report BLOB NOT NULL,
                scanned_at INTEGER NOT NULL,
                last_used INTEGER NOT NULL,
                mac BLOB NOT NULL,
                PRIMARY KEY (volume, file_id)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS entries_last_used ON entries (last_used);
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
            pragmas.CommandText = $"PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = {(int)_options.BusyTimeout.TotalMilliseconds}; PRAGMA trusted_schema = OFF;";
            pragmas.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose(); // otherwise it keeps the file open and a rebuild can't delete it
            throw;
        }
    }

    /// <summary>Runs one call on a pooled connection; corruption rebuilds, any other database error is logged and gives <paramref name="fallback"/>.</summary>
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
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidCastException or InvalidOperationException)
        {
            Volatile.Write(ref _lastProblem, $"A scan cache call failed ({ex.GetType().Name}).");
            _logger.LogWarning(ex, "A scan cache call failed; going on uncached.");
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

    private void DeleteCore(SqliteConnection connection, ulong volume, UInt128 fileId)
    {
        lock (_writer)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM entries WHERE volume = $volume AND file_id = $fileId";
            AddKey(command, volume, fileId);
            command.ExecuteNonQuery();
        }
    }

    private static void AddKey(SqliteCommand command, ulong volume, UInt128 fileId)
    {
        command.Parameters.AddWithValue("$volume", unchecked((long)volume));
        command.Parameters.AddWithValue("$fileId", new FileStamp(volume, fileId, 0, 0, 0, null).FileIdBytes());
    }

    /// <summary>HMAC-SHA256 over every value but last_used, length-prefixed so no two rows encode alike.</summary>
    internal byte[] Mac(ScanCacheRow row)
    {
        using var buffer = new MemoryStream();
        using (var w = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            w.Write("sap-AV scan cache row v1");
            w.Write(row.Stamp.Volume);
            w.Write(row.Stamp.FileIdBytes());
            w.Write(row.Path);
            w.Write(row.Stamp.Size);
            w.Write(row.Stamp.LastWriteTime);
            w.Write(row.Stamp.ChangeTime);
            w.Write(row.Stamp.Usn.HasValue);
            w.Write(row.Stamp.Usn ?? 0);
            w.Write(row.Sha256);
            w.Write((int)row.Verdict);
            w.Write(row.Summary);
            w.Write(row.SignatureStatus.HasValue ? (int)row.SignatureStatus.Value : -1);
            w.Write(row.RulesFingerprint);
            w.Write(row.BlocklistFingerprint);
            w.Write(row.EngineVersion);
            w.Write(row.Report.Length);
            w.Write(row.Report);
            w.Write(row.ScannedAt);
        }

        return HMACSHA256.HashData(_macKey, buffer.ToArray());
    }
}
