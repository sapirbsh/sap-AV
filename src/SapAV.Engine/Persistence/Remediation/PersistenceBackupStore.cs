using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Persistence.Remediation;

/// <summary>
/// D5: one Block &amp; remove, with everything needed to put it back exactly. Engine data in an admin-only folder, HMAC'd; what
/// it says about the entry (location, names, values) came from the registry / task / folder and is untrusted text for display.
/// </summary>
internal sealed record PersistenceBackupRecord
{
    public const int Version = 1;

    public required string Id { get; init; }

    public required PersistenceKind Kind { get; init; }

    /// <summary>The entry's user; null for a machine-wide entry (administrators only).</summary>
    public string? UserSid { get; init; }

    public required string Location { get; init; }

    public string? ValueName { get; init; }

    public required string CommandLine { get; init; }

    /// <summary>The entry's <see cref="PersistenceEntry.Key"/> (real-time monitoring is told about the change by it).</summary>
    public required string EntryKey { get; init; }

    public required PersistenceBackupAction Action { get; init; }

    public PersistenceBackupState State { get; init; }

    public required string BlockedBy { get; init; }

    /// <summary>Review M2: the block was an administrator's; only an administrator may restore or purge it.</summary>
    public bool BlockedByAdmin { get; init; }

    public required DateTimeOffset BlockedAtUtc { get; init; }

    public DateTimeOffset? RestoredAtUtc { get; init; }

    public string? RestoredBy { get; init; }

    // Registry values (Run, RunOnce, IFEO, SilentProcessExit, Winlogon)

    public RegistryRoot? Root { get; init; }

    public string? KeyPath { get; init; }

    /// <summary>The exact value name (UTF-16LE bytes: a stored name may hold characters a JSON string can't carry).</summary>
    public byte[]? RawValueName { get; init; }

    public int? ValueType { get; init; }

    /// <summary>The value's raw bytes before the change.</summary>
    public byte[]? ValueData { get; init; }

    /// <summary>Winlogon: what was written instead (the Windows default).</summary>
    public int? ReplacementType { get; init; }

    public byte[]? ReplacementData { get; init; }

    // Services

    public string? ServiceName { get; init; }

    public int? OldStartType { get; init; }

    public bool? WasRunning { get; init; }

    // Scheduled tasks

    public string? TaskPath { get; init; }

    /// <summary>The task's definition before it was disabled (null when over the cap; see the notes).</summary>
    public string? TaskXml { get; init; }

    /// <summary>SHA-256 of the definition right after it was disabled: restore re-enables only that exact task.</summary>
    public string? DisabledXmlSha256 { get; init; }

    // Startup folder items

    public string? QuarantineItemId { get; init; }

    public string? OriginalPath { get; init; }

    public IReadOnlyList<string> Notes { get; init; } = [];

    [System.Text.Json.Serialization.JsonIgnore]
    public string RawName => RawValueName is null ? string.Empty : new string(System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(RawValueName));

    /// <summary>The exact UTF-16 code units of <paramref name="name"/> (no encoder, so even a lone surrogate survives).</summary>
    public static byte[] NameBytes(string name) => System.Runtime.InteropServices.MemoryMarshal.AsBytes(name.AsSpan()).ToArray();

    [System.Text.Json.Serialization.JsonIgnore]
    public RawRegistryValue? Before => ValueType is { } type && ValueData is { } data ? new RawRegistryValue(type, data) : null;

    [System.Text.Json.Serialization.JsonIgnore]
    public RawRegistryValue? Replacement => ReplacementType is { } type && ReplacementData is { } data ? new RawRegistryValue(type, data) : null;
}

internal enum BackupLoadStatus
{
    Ok,
    NotFound,

    /// <summary>The record failed its MAC or validation: never acted on.</summary>
    Invalid,
}

/// <summary>D5: where Block &amp; remove backups are kept; fake it (or point it at a temp folder) in tests.</summary>
internal interface IPersistenceBackupStore
{
    /// <exception cref="IOException">The record couldn't be written.</exception>
    void Save(PersistenceBackupRecord record);

    BackupLoadStatus TryLoad(string id, out PersistenceBackupRecord? record);

    /// <summary>Every record (an invalid one as null, with its ID).</summary>
    IReadOnlyList<(string Id, PersistenceBackupRecord? Record)> List();

    /// <summary>Removes the record (true if it existed).</summary>
    /// <exception cref="IOException">It couldn't be removed.</exception>
    bool Delete(string id);
}

/// <summary>
/// D5: one file per record in <c>%ProgramData%\sap-AV\PersistenceBackups</c>, created or verified with
/// <see cref="EngineDataSubfolder"/> (SYSTEM + Administrators only), each carrying an HMAC-SHA256 under the folder's
/// DPAPI-protected key (like the baseline, the scan cache and the quarantine metadata). A record that fails the MAC, doesn't
/// parse, or names another ID than its file is <b>invalid</b> and never acted on. Layout: 64 hex characters of MAC, a newline,
/// the UTF-8 JSON body; written to a temporary file and moved into place.
/// </summary>
internal sealed partial class FilePersistenceBackupStore : IPersistenceBackupStore
{
    public const string Extension = ".backup";
    public const int MaxBytes = 2 * 1024 * 1024;
    public const int MaxRecords = 10_000;

    private static readonly byte[] Purpose = Encoding.UTF8.GetBytes("sap-AV persistence backup v1\n");

    private readonly byte[] _key;

    public FilePersistenceBackupStore(string folder, byte[] key)
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

    /// <summary>The engine's store, or null when the protected folder or its key can't be used (logged; Block &amp; remove is then unavailable).</summary>
    internal static FilePersistenceBackupStore? TryCreate(string folder, IQuarantineKeyProvider keys, QuarantineAccessPolicy policy, ILogger logger)
    {
        try
        {
            string full = EngineDataSubfolder.Ensure(folder, policy, "persistence backup");
            return new FilePersistenceBackupStore(full, keys.GetOrCreateKey(full, policy));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            logger.LogWarning("The persistence backup folder can't be used ({Type}: {Why}); Block & remove is unavailable.", ex.GetType().Name, ex.Message);
            return null;
        }
    }

    /// <summary>A new random record ID.</summary>
    public static string NewId() => "pb-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    /// <summary>Format only (checked before the ID is ever used in a file name).</summary>
    public static bool IsId(string? id) => id is not null && IdRegex().IsMatch(id);

    public void Save(PersistenceBackupRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (!IsId(record.Id))
        {
            throw new ArgumentException("Not a backup ID.", nameof(record));
        }

        byte[] body = JsonSerializer.SerializeToUtf8Bytes(record);
        if (body.Length + 65 > MaxBytes)
        {
            throw new IOException("The backup record is over the size cap.");
        }

        string path = PathOf(record.Id);
        string temp = path + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(Encoding.ASCII.GetBytes(Convert.ToHexStringLower(Mac(body)) + "\n"));
                stream.Write(body);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, path, overwrite: true);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new IOException($"The backup record can't be written ({ex.Message}).", ex);
        }
    }

    public BackupLoadStatus TryLoad(string id, out PersistenceBackupRecord? record)
    {
        record = null;
        if (!IsId(id))
        {
            return BackupLoadStatus.NotFound;
        }

        byte[] bytes;
        try
        {
            using var stream = new FileStream(PathOf(id), FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaxBytes)
            {
                return BackupLoadStatus.Invalid;
            }

            bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return BackupLoadStatus.NotFound;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return BackupLoadStatus.Invalid;
        }

        record = Decode(id, bytes);
        return record is null ? BackupLoadStatus.Invalid : BackupLoadStatus.Ok;
    }

    public IReadOnlyList<(string Id, PersistenceBackupRecord? Record)> List()
    {
        var all = new List<(string, PersistenceBackupRecord?)>();
        foreach (var file in Directory.EnumerateFiles(Folder, "*" + Extension).Take(MaxRecords))
        {
            string id = Path.GetFileNameWithoutExtension(file);
            if (IsId(id))
            {
                all.Add((id, TryLoad(id, out var record) == BackupLoadStatus.Ok ? record : null));
            }
        }

        return all;
    }

    public bool Delete(string id)
    {
        if (!IsId(id))
        {
            return false;
        }

        string path = PathOf(id);
        if (!File.Exists(path))
        {
            return false;
        }

        File.Delete(path);
        return true;
    }

    private string PathOf(string id) => Path.Combine(Folder, id + Extension);

    private PersistenceBackupRecord? Decode(string id, byte[] bytes)
    {
        const int header = 65;
        if (bytes.Length < header || bytes[64] != (byte)'\n')
        {
            return null;
        }

        byte[] stored;
        try
        {
            stored = Convert.FromHexString(Encoding.ASCII.GetString(bytes, 0, 64));
        }
        catch (FormatException)
        {
            return null;
        }

        var body = bytes.AsSpan(header);
        if (!CryptographicOperations.FixedTimeEquals(stored, Mac(body)))
        {
            return null;
        }

        try
        {
            var record = JsonSerializer.Deserialize<PersistenceBackupRecord>(body);
            return record is not null && Valid(record, id) ? record : null;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or FormatException)
        {
            return null;
        }
    }

    /// <summary>Cross-field checks: the record names its own file, its kind matches its action, and the action has its data.</summary>
    private static bool Valid(PersistenceBackupRecord r, string id) =>
        r.Id == id && Enum.IsDefined(r.Kind) && Enum.IsDefined(r.Action) && Enum.IsDefined(r.State)
        && (r.UserSid is null || PersistenceEntry.IsSid(r.UserSid)) && PersistenceEntry.IsSid(r.BlockedBy)
        && r.Action switch
        {
            PersistenceBackupAction.ValueDeleted or PersistenceBackupAction.ValueReset =>
                r.Root is { } root && Enum.IsDefined(root) && !string.IsNullOrEmpty(r.KeyPath) && r.RawValueName is not null && r.Before is not null
                && (r.Action == PersistenceBackupAction.ValueDeleted) == (r.Replacement is null),
            PersistenceBackupAction.ServiceDisabled => r.Kind == PersistenceKind.Service && !string.IsNullOrEmpty(r.ServiceName) && r.OldStartType is >= 0 and <= 4,
            PersistenceBackupAction.TaskDisabled => r.Kind == PersistenceKind.ScheduledTask && !string.IsNullOrEmpty(r.TaskPath) && r.DisabledXmlSha256 is { Length: 64 },
            PersistenceBackupAction.FileQuarantined => r.Kind == PersistenceKind.StartupFolder && !string.IsNullOrEmpty(r.QuarantineItemId) && !string.IsNullOrEmpty(r.OriginalPath),
            _ => false,
        };

    private byte[] Mac(ReadOnlySpan<byte> body)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _key);
        hmac.AppendData(Purpose);
        hmac.AppendData(body);
        return hmac.GetHashAndReset();
    }

    [GeneratedRegex(@"\Apb-[0-9a-f]{32}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdRegex();
}
