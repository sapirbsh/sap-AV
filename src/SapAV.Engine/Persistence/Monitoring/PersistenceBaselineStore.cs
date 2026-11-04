using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SapAV.Core.Persistence;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>How loading the baseline went.</summary>
internal enum BaselineLoadStatus
{
    /// <summary>No baseline yet (first start): every scope is baselined from scratch.</summary>
    Missing,

    Loaded,

    /// <summary>The file failed its MAC or didn't parse: it is ignored and the baseline is taken again.</summary>
    Tampered,
}

internal sealed record BaselineLoadResult(BaselineLoadStatus Status, BaselineSnapshot? Snapshot, string? Problem = null);

/// <summary>Where the baseline is kept; fake it in tests.</summary>
internal interface IPersistenceBaselineStore
{
    /// <summary>Never throws: a missing, unreadable or tampered file is reported in the result.</summary>
    BaselineLoadResult Load();

    /// <exception cref="IOException">The baseline couldn't be written (the monitor keeps going in memory).</exception>
    void Save(BaselineSnapshot snapshot);
}

/// <summary>In memory only (tests, or when the protected folder can't be used): every engine start baselines again.</summary>
internal sealed class MemoryBaselineStore : IPersistenceBaselineStore
{
    public BaselineSnapshot? Saved { get; private set; }

    public int Saves { get; private set; }

    public BaselineLoadResult Load() => Saved is null ? new(BaselineLoadStatus.Missing, null) : new(BaselineLoadStatus.Loaded, Saved);

    public void Save(BaselineSnapshot snapshot)
    {
        Saved = snapshot;
        Saves++;
    }
}

/// <summary>
/// D4: the baseline in <c>%ProgramData%\sap-AV\Persistence\baseline.dat</c>. The folder is created or verified with
/// <see cref="EngineDataSubfolder"/> (SYSTEM + Administrators only; a pre-existing folder with a wider ACL or an untrusted
/// owner is refused), and the file carries an HMAC-SHA256 under the folder's DPAPI-protected key, like the scan cache and the
/// quarantine metadata. A file that fails the MAC or doesn't parse is <b>ignored</b> (reported as tampered) and the baseline
/// is taken again: then existing entries are judged once more (Suspicious / Malicious ones alert again), which is the safe
/// direction, since nothing in a forged baseline can hide an entry.
/// </summary>
/// <remarks>
/// Layout: 64 hex characters of MAC, a newline, then the UTF-8 JSON body; the MAC covers a fixed purpose string and the body.
/// Written to a temporary file in the same folder and moved over the old one, so a crash leaves the old or the new file.
/// Size-capped on read. Engine-written content in an admin-only folder: this is not user-controlled input.
/// </remarks>
internal sealed class FileBaselineStore : IPersistenceBaselineStore
{
    public const string FileName = "baseline.dat";
    public const int MaxBytes = 64 * 1024 * 1024;
    public const int MaxRecords = 500_000;

    private const int Version = 1;
    private static readonly byte[] Purpose = Encoding.UTF8.GetBytes("sap-AV persistence baseline v1\n");

    private readonly byte[] _key;

    public FileBaselineStore(string folder, byte[] key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length < 32)
        {
            throw new ArgumentException("The MAC key must be at least 32 bytes.", nameof(key));
        }

        Folder = folder;
        _key = key;
    }

    public string Folder { get; }

    public string FilePath => Path.Combine(Folder, FileName);

    /// <summary>The engine's store, or null when the protected folder or its key can't be used (logged; the monitor runs in memory).</summary>
    internal static FileBaselineStore? TryCreate(
        string folder, IQuarantineKeyProvider keys, QuarantineAccessPolicy policy, ILogger logger, bool? parentIsDataRoot = null)
    {
        try
        {
            string full = EngineDataSubfolder.Ensure(folder, policy, "persistence baseline", parentIsDataRoot);
            return new FileBaselineStore(full, keys.GetOrCreateKey(full, policy));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogWarning("The persistence baseline folder can't be used ({Type}: {Why}); the baseline is kept in memory and taken again at every start.",
                ex.GetType().Name, ex.Message);
            return null;
        }
    }

    public BaselineLoadResult Load()
    {
        byte[] bytes;
        try
        {
            using var stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaxBytes)
            {
                return new(BaselineLoadStatus.Tampered, null, $"The baseline file is {stream.Length} bytes, over the {MaxBytes}-byte cap.");
            }

            bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
        }
        catch (FileNotFoundException)
        {
            return new(BaselineLoadStatus.Missing, null);
        }
        catch (DirectoryNotFoundException)
        {
            return new(BaselineLoadStatus.Missing, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(BaselineLoadStatus.Tampered, null, $"The baseline file can't be read ({ex.GetType().Name}).");
        }

        return Decode(bytes);
    }

    public void Save(BaselineSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(ToFile(snapshot));
        byte[] mac = Mac(body);
        string temp = FilePath + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(Encoding.ASCII.GetBytes(Convert.ToHexStringLower(mac) + "\n"));
                stream.Write(body);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, FilePath, overwrite: true);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new IOException($"The baseline can't be written ({ex.Message}).", ex);
        }
    }

    private BaselineLoadResult Decode(byte[] bytes)
    {
        const int header = 65;
        if (bytes.Length < header || bytes[64] != (byte)'\n')
        {
            return new(BaselineLoadStatus.Tampered, null, "The baseline file has no MAC.");
        }

        byte[] stored;
        try
        {
            stored = Convert.FromHexString(Encoding.ASCII.GetString(bytes, 0, 64));
        }
        catch (FormatException)
        {
            return new(BaselineLoadStatus.Tampered, null, "The baseline file's MAC isn't hex.");
        }

        var body = bytes.AsSpan(header);
        if (!CryptographicOperations.FixedTimeEquals(stored, Mac(body)))
        {
            return new(BaselineLoadStatus.Tampered, null, "The baseline file's MAC doesn't match.");
        }

        try
        {
            var file = JsonSerializer.Deserialize<BaselineFile>(body) ?? throw new JsonException("Empty baseline.");
            return new(BaselineLoadStatus.Loaded, FromFile(file));
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or FormatException or InvalidDataException)
        {
            return new(BaselineLoadStatus.Tampered, null, $"The baseline file doesn't parse ({ex.GetType().Name}).");
        }
    }

    private byte[] Mac(ReadOnlySpan<byte> body)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        hmac.AppendData(Purpose);
        hmac.AppendData(body);
        return hmac.GetHashAndReset();
    }

    private static BaselineFile ToFile(BaselineSnapshot snapshot) => new()
    {
        Version = Version,
        Records = [.. snapshot.Records.Select(r => new RecordDto
        {
            Key = r.Key, Source = r.Scope.Source, Sid = r.Scope.UserSid, Fingerprint = r.Fingerprint, Display = r.Display, Judged = r.Judged, Change = (int)r.Change,
            TargetStamp = r.TargetStamp, PendingSince = r.PendingSince, NotBefore = r.NotBefore?.UtcTicks, Attempts = r.Attempts, LastJudged = r.LastJudged?.UtcTicks,
        })],
        Baselined = [.. snapshot.Baselined.Select(s => new ScopeDto { Source = s.Source, Sid = s.UserSid })],
        Hidden = [.. (snapshot.Hidden ?? []).Select(h => new HiddenDto { Id = h.Id, Source = h.Scope.Source, Sid = h.Scope.UserSid })],
    };

    /// <exception cref="InvalidDataException">A field is out of range.</exception>
    private static BaselineSnapshot FromFile(BaselineFile file)
    {
        if (file.Version != Version || file.Records is null || file.Baselined is null || file.Records.Count > MaxRecords || file.Baselined.Count > MaxRecords
            || (file.Hidden?.Count ?? 0) > PersistenceBaseline.MaxHidden)
        {
            throw new InvalidDataException("Unknown version or too many records.");
        }

        var records = file.Records.Select(r =>
        {
            if (string.IsNullOrEmpty(r.Key) || r.Key.Length > 8192 || r.Fingerprint is not { Length: 64 } || !Enum.IsDefined((BaselineChange)r.Change)
                || r.Display is null || r.Display.Length > PersistenceBaseline.MaxDisplayLength || r.TargetStamp is not (null or { Length: 64 })
                || r.PendingSince < 0 || r.Attempts is < 0 or > 10_000)
            {
                throw new InvalidDataException("A baseline record is invalid.");
            }

            return new BaselineRecord(r.Key, Scope(r.Source, r.Sid), r.Fingerprint, r.Display, r.Judged, (BaselineChange)r.Change, r.TargetStamp,
                r.PendingSince, Time(r.NotBefore), r.Attempts, Time(r.LastJudged));
        }).ToArray();
        var hidden = (file.Hidden ?? []).Select(h => h.Id is { Length: > 0 and <= 8192 } id
            ? new HiddenLocation(id, Scope(h.Source, h.Sid))
            : throw new InvalidDataException("A hidden location is invalid.")).ToArray();
        return new BaselineSnapshot(records, file.Baselined.Select(s => Scope(s.Source, s.Sid)).ToArray(), hidden);
    }

    private static DateTimeOffset? Time(long? ticks) =>
        ticks is null ? null
        : ticks is >= 0 and <= 3155378975999999999 ? new DateTimeOffset(ticks.Value, TimeSpan.Zero)
        : throw new InvalidDataException("A baseline time is invalid.");

    private static PersistenceScope Scope(string? source, string? sid) =>
        source is { Length: > 0 and <= 64 } && (sid is null || PersistenceEntry.IsSid(sid))
            ? new PersistenceScope(source, sid)
            : throw new InvalidDataException("A baseline scope is invalid.");

    private sealed class BaselineFile
    {
        public int Version { get; set; }

        public List<RecordDto>? Records { get; set; }

        public List<ScopeDto>? Baselined { get; set; }

        public List<HiddenDto>? Hidden { get; set; }
    }

    private sealed class RecordDto
    {
        public string? Key { get; set; }

        public string? Source { get; set; }

        public string? Sid { get; set; }

        public string? Fingerprint { get; set; }

        public string? Display { get; set; }

        public bool Judged { get; set; }

        public int Change { get; set; }

        public string? TargetStamp { get; set; }

        public long PendingSince { get; set; }

        public long? NotBefore { get; set; }

        public int Attempts { get; set; }

        public long? LastJudged { get; set; }
    }

    private sealed class ScopeDto
    {
        public string? Source { get; set; }

        public string? Sid { get; set; }
    }

    private sealed class HiddenDto
    {
        public string? Id { get; set; }

        public string? Source { get; set; }

        public string? Sid { get; set; }
    }
}
