using System.Text.Json.Serialization;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Serialization;
using SapAV.Core.Signatures;
using SapAV.Core.Yara;

namespace SapAV.Core.Scanning.Isolation;

// The wire form of a FileScanReport (worker to engine). Plain data with no invariants of its own: the engine turns
// it back into the validated Core types with WireReportCodec.FromWire, which rejects anything inconsistent or over a
// cap. Identity is deliberately absent: it comes from the broker's own handle, never from the worker.

public sealed record WireScanReport
{
    public required WireResult Result { get; init; }

    public required WireHash Hash { get; init; }

    public required WireSignature? Signature { get; init; }

    public required WireYara? Yara { get; init; }

    public required WireMarkOfTheWeb? MarkOfTheWeb { get; init; }

    public required WireHeuristics? Heuristics { get; init; }

    public required IReadOnlyList<WireNote> Notes { get; init; }
}

/// <summary>The verdict part of the result. The item and the timestamp are the engine's own.</summary>
public sealed record WireResult
{
    public required ScanStatus Status { get; init; }

    public required string? Sha256 { get; init; }

    public required SignatureStatus? SignatureStatus { get; init; }

    public required string? Signer { get; init; }

    public required IReadOnlyList<Detection> Detections { get; init; }
}

public sealed record WireHash
{
    public required HashFailureReason FailureReason { get; init; }

    public required string? Sha256 { get; init; }

    public required long? Length { get; init; }

    public required string? ErrorMessage { get; init; }

    public required DateTime? LastWriteTimeUtc { get; init; }

    public required int? Attributes { get; init; }
}

public sealed record WireSignature
{
    public required SignatureStatus? Status { get; init; }

    public required SignatureFailureReason FailureReason { get; init; }

    public required HashFailureReason NotCheckedReason { get; init; }

    public required SignatureKind Kind { get; init; }

    public required WireSigner? Signer { get; init; }

    public required string? CatalogPath { get; init; }

    public required int TrustResult { get; init; }

    public required string? Message { get; init; }
}

public sealed record WireSigner
{
    public required IReadOnlyList<WireCertificate> Chain { get; init; }

    public required DateTimeOffset? Timestamp { get; init; }
}

public sealed record WireCertificate
{
    public required string Subject { get; init; }

    public required string Issuer { get; init; }

    public required string Sha1Thumbprint { get; init; }

    public required string Sha256Thumbprint { get; init; }

    public required DateTime NotBeforeUtc { get; init; }

    public required DateTime NotAfterUtc { get; init; }
}

public sealed record WireYara
{
    public required YaraFailureReason FailureReason { get; init; }

    public required IReadOnlyList<WireYaraMatch> Matches { get; init; }

    public required long? Length { get; init; }

    public required string? ErrorMessage { get; init; }

    public required string? RulesFingerprint { get; init; }
}

public sealed record WireYaraMatch
{
    public required string File { get; init; }

    public required string Identifier { get; init; }

    public required IReadOnlyList<string> Tags { get; init; }

    public required Verdict Verdict { get; init; }

    public required string TechniqueId { get; init; }

    public required IReadOnlyList<string> SecondaryTechniqueIds { get; init; }

    public required string? Description { get; init; }
}

public sealed record WireMarkOfTheWeb
{
    [JsonConverter(typeof(StrictEnumConverter<MarkOfTheWebStatus>))]
    public required MarkOfTheWebStatus Status { get; init; }

    /// <summary>The raw <c>ZoneId</c> (the zone is derived from it, as in <see cref="Motw.MarkOfTheWeb.Parse"/>).</summary>
    public required int? RawZoneId { get; init; }

    public required string? HostUrl { get; init; }

    public required string? ReferrerUrl { get; init; }

    public required HashFailureReason NotReadReason { get; init; }

    public required string? Message { get; init; }
}

public sealed record WireHeuristics
{
    public required IReadOnlyList<WireFinding> Findings { get; init; }

    public required int Threshold { get; init; }

    public required bool ContentInspected { get; init; }

    public required string? ContentError { get; init; }
}

public sealed record WireFinding
{
    [JsonConverter(typeof(StrictEnumConverter<HeuristicKind>))]
    public required HeuristicKind Kind { get; init; }

    public required int Score { get; init; }

    public required string Reason { get; init; }

    public required string TechniqueId { get; init; }
}

public sealed record WireNote
{
    [JsonConverter(typeof(StrictEnumConverter<ScanNoteLevel>))]
    public required ScanNoteLevel Level { get; init; }

    public required string Message { get; init; }
}
