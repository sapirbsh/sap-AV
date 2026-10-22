using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Serialization;

namespace SapAV.Core.Quarantine;

/// <summary>
/// Journal state of a quarantine item (ROADMAP B2). The metadata is always written <b>before</b> the file system step
/// it announces, so after a crash the engine knows what may be half done (see <c>SapAV.Engine.Quarantine</c>).
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<QuarantineState>))]
public enum QuarantineState
{
    /// <summary>Being moved in. The original, the staged raw file or the stored copy is intact.</summary>
    Quarantining,

    /// <summary>Complete: the neutralised copy is in the store, the original is gone.</summary>
    Quarantined,

    /// <summary>Being restored. The stored copy is intact; a temp file may exist in the target folder.</summary>
    Restoring,

    /// <summary>Restored to the target; only the store entry is left to remove.</summary>
    Restored,
}

/// <summary>How the file got into the store.</summary>
[JsonConverter(typeof(StrictEnumConverter<QuarantineMoveKind>))]
public enum QuarantineMoveKind
{
    /// <summary>Same volume: renamed by handle into the store, then neutralised.</summary>
    SameVolume,

    /// <summary>Different volume: copied (neutralised) from the handle, verified, then the original deleted by handle.</summary>
    CrossVolume,
}

/// <summary>
/// Everything needed to restore one quarantined file, stored as signed JSON next to it
/// (<see cref="QuarantineMetadataCodec"/>). <see cref="Validate"/> runs on every write and every read (after the HMAC).
/// </summary>
public sealed record QuarantineMetadata
{
    public const int CurrentSchemaVersion = 1;

    /// <summary>Most reasons kept.</summary>
    public const int MaxReasons = 64;

    /// <summary>Largest Zone.Identifier stream kept.</summary>
    public const int MaxZoneIdentifierBytes = 64 * 1024;

    /// <summary>Longest SDDL string kept.</summary>
    public const int MaxSddlLength = 64 * 1024;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>The item ID: 32 lowercase hex characters (128 random bits). Also the stored file's name.</summary>
    public required string Id { get; init; }

    public required QuarantineState State { get; init; }

    public required QuarantineMoveKind MoveKind { get; init; }

    /// <summary>
    /// Where the file really was (final path of the opened handle, drive-letter form). The only restore target.
    /// </summary>
    public required string OriginalPath { get; init; }

    /// <summary>The path the scan was asked for (may differ by case, short names or links). Information only.</summary>
    public required string ScannedPath { get; init; }

    public required long SizeBytes { get; init; }

    /// <summary>Lowercase hex SHA-256 of the original content.</summary>
    public required string Sha256 { get; init; }

    /// <summary>The original <see cref="FileAttributes"/>, as a number.</summary>
    public required int Attributes { get; init; }

    public required DateTimeOffset CreationTimeUtc { get; init; }

    public required DateTimeOffset LastWriteTimeUtc { get; init; }

    public required DateTimeOffset LastAccessTimeUtc { get; init; }

    /// <summary>Original owner, group and DACL (SDDL), or null if it couldn't be read.</summary>
    public string? SecurityDescriptor { get; init; }

    /// <summary>The raw <c>Zone.Identifier</c> stream (Mark-of-the-Web), captured before the move; null if none.</summary>
    public byte[]? ZoneIdentifier { get; init; }

    public required Verdict Verdict { get; init; }

    public required IReadOnlyList<string> Reasons { get; init; }

    /// <summary>MITRE technique IDs, primary (worst detection) first.</summary>
    public required IReadOnlyList<string> TechniqueIds { get; init; }

    public required ScanTrigger Trigger { get; init; }

    public required DateTimeOffset ScanTimestamp { get; init; }

    public required DateTimeOffset QuarantinedAtUtc { get; init; }

    /// <summary>The alert that led to the quarantine, if any.</summary>
    public Guid? AlertId { get; init; }

    /// <summary>Always <see cref="QuarantineContentTransform.Algorithm"/>.</summary>
    public required string TransformAlgorithm { get; init; }

    /// <summary>The per-item XOR key (<see cref="QuarantineContentTransform.KeyLength"/> bytes).</summary>
    public required byte[] TransformKey { get; init; }

    /// <summary>
    /// While <see cref="State"/> is Restoring: the random temp file name used in the target folder (so recovery only
    /// ever removes a file whose unguessable name it chose itself). Null otherwise.
    /// </summary>
    public string? RestoreTempName { get; init; }

    /// <summary>Checks every field; throws <see cref="InvalidDataException"/> on the first problem.</summary>
    public void Validate()
    {
        Check(SchemaVersion == CurrentSchemaVersion, $"Unsupported schema version {SchemaVersion}.");
        Check(QuarantineItemId.IsValid(Id), "Invalid item ID.");
        Check(Enum.IsDefined(State) && Enum.IsDefined(MoveKind), "Undefined state or move kind.");
        Check(QuarantinePath.TryValidateOriginalPath(OriginalPath, out var why), $"Invalid original path: {why}");
        Check(!string.IsNullOrWhiteSpace(ScannedPath) && ScannedPath.Length <= QuarantinePath.MaxPathLength
            && !ScannedPath.Contains('\0'), "Invalid scanned path.");
        Check(SizeBytes >= 0, "Negative size.");
        Check(Sha256 is { Length: 64 } && Sha256.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f'), "Invalid SHA-256.");
        Check(SecurityDescriptor is null || (SecurityDescriptor.Length <= MaxSddlLength && !SecurityDescriptor.Contains('\0')),
            "Invalid security descriptor.");
        Check(ZoneIdentifier is null || ZoneIdentifier.Length <= MaxZoneIdentifierBytes, "Zone.Identifier too large.");
        Check(Verdict is Verdict.Suspicious or Verdict.Malicious, "The verdict must be Suspicious or Malicious.");
        Check(Reasons is not null && Reasons.Count <= MaxReasons
            && Reasons.All(r => r is not null && r.Length is > 0 and <= Detection.MaxReasonLength), "Invalid reasons.");
        Check(TechniqueIds is not null && TechniqueIds.Count <= MaxReasons * 4
            && TechniqueIds.All(MitreTechniqueIdFormat.IsValid), "Invalid technique IDs.");
        Check(Enum.IsDefined(Trigger), "Undefined trigger.");
        Check(TransformAlgorithm == QuarantineContentTransform.Algorithm, "Unknown transform.");
        Check(TransformKey is { Length: QuarantineContentTransform.KeyLength }, "Invalid transform key.");
        Check(AlertId != Guid.Empty, "Empty alert ID.");
        Check(State == QuarantineState.Restoring
                ? RestoreTempName is not null && QuarantinePath.IsRestoreTempName(RestoreTempName)
                : RestoreTempName is null,
            "The restore temp name must be set exactly while restoring.");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidDataException(message);
        }
    }
}

/// <summary>Quarantine item IDs.</summary>
public static class QuarantineItemId
{
    /// <summary>A new random ID (128 bits, 32 lowercase hex characters).</summary>
    public static string New() => Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

    /// <summary>True for exactly 32 lowercase hex characters (so an ID is always a safe file name).</summary>
    public static bool IsValid(string? id) =>
        id is { Length: 32 } && id.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');
}
