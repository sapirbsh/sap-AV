using System.Text.Json.Serialization;
using SapAV.Core.Signatures;

namespace SapAV.Core.Models;

/// <summary>
/// The outcome of scanning one <see cref="ScanItem"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Verdict"/> is always derived, never stored: if <see cref="Status"/> is
/// <see cref="ScanStatus.Scanned"/> it is the worst of <see cref="Detections"/> (Clean when there are none);
/// otherwise it is <c>null</c>, because a file that was not scanned has no verdict and must never look Clean.
/// A non-Scanned result therefore cannot carry detections.
/// </para>
/// <para>
/// <see cref="Status"/> is set only through the constructor or the factories (no <c>with</c>), so the
/// status/detections rule is checked in a fixed order, regardless of property order in JSON.
/// </para>
/// <para>
/// JSON: <c>Status</c> and <c>Timestamp</c> are required (<see cref="JsonRequiredAttribute"/>), so a missing
/// status can't default to Scanned (which would read as Clean) and a missing timestamp can't become
/// 0001-01-01. If either is missing or null, or an enum value
/// is not an exact name, <see cref="System.Text.Json.JsonException"/> is thrown. Invalid content
/// (bad SHA-256, detections on a non-Scanned result, ...) throws <see cref="ArgumentException"/>
/// (or a subclass). A <c>"Verdict"</c> property in incoming JSON is ignored.
/// </para>
/// <para>
/// Optional signature information (A3): <see cref="SignatureStatus"/> records why a Clean result is clean
/// (e.g. Microsoft-signed) and <see cref="Signer"/> carries the trusted signer's name for logs and the Event
/// Log payload (X2). Both are <c>null</c> when the signature wasn't checked, and always <c>null</c> on a
/// non-Scanned result. <see cref="Signer"/> is only allowed with Microsoft or OtherTrusted, because the
/// name in a broken signature is an unverified claim. Older JSON without these properties still reads.
/// </para>
/// </remarks>
public sealed record ScanResult
{
    private readonly ScanItem _item = null!;
    private readonly ScanStatus _status;
    private readonly IReadOnlyList<Detection> _detections = [];
    private readonly Verdict? _verdict;
    private readonly string? _sha256;
    private readonly SignatureStatus? _signatureStatus;
    private readonly string? _signer;

    public ScanResult(
        ScanItem item,
        IReadOnlyList<Detection> detections,
        DateTimeOffset timestamp,
        string? sha256 = null,
        ScanStatus status = ScanStatus.Scanned,
        SignatureStatus? signatureStatus = null,
        string? signer = null)
    {
        // Status first: the Detections and signature setters check against it. Signer after its status.
        Status = status;
        Item = item;
        Detections = detections;
        Timestamp = timestamp;
        Sha256 = sha256;
        SignatureStatus = signatureStatus;
        Signer = signer;
    }

    /// <summary>Creates a scanned result with no detections (verdict Clean).</summary>
    public static ScanResult Clean(
        ScanItem item,
        DateTimeOffset timestamp,
        string? sha256 = null,
        SignatureStatus? signatureStatus = null,
        string? signer = null) =>
        new(item, [], timestamp, sha256, ScanStatus.Scanned, signatureStatus, signer);

    /// <summary>Creates a result for a file that could not be scanned (verdict <c>null</c>).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="status"/> is Scanned or undefined.</exception>
    public static ScanResult NotScanned(
        ScanItem item, ScanStatus status, DateTimeOffset timestamp, string? sha256 = null)
    {
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "Undefined scan status.");
        }

        if (status == ScanStatus.Scanned)
        {
            throw new ArgumentOutOfRangeException(nameof(status), status,
                "Use the constructor or Clean() for scanned results.");
        }

        return new(item, [], timestamp, sha256, status);
    }

    public ScanItem Item
    {
        get => _item;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(Item));
            _item = value;
        }
    }

    /// <summary>Whether the file was actually scanned.</summary>
    /// <remarks>
    /// The setter is private (only the constructor uses it; it exists so <see cref="JsonRequiredAttribute"/>
    /// can apply). It is validated anyway, so the status/detections rule holds in any assignment order.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined <see cref="ScanStatus"/>.</exception>
    [JsonRequired]
    [JsonInclude]
    public ScanStatus Status
    {
        get => _status;
        private init
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(nameof(Status), value, "Undefined scan status.");
            }

            EnsureDetectionsAllowed(value, _detections.Count);
            _status = value;
            _verdict = ComputeVerdict(value, _detections);
        }
    }

    /// <summary>Findings, as a read-only copy. Always empty when <see cref="Status"/> is not Scanned.</summary>
    /// <exception cref="ArgumentException">Contains null, or is non-empty on a non-Scanned result.</exception>
    public IReadOnlyList<Detection> Detections
    {
        get => _detections;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(Detections));
            var copy = value.ToArray();
            if (Array.Exists(copy, d => d is null))
            {
                throw new ArgumentException("Detections must not contain null.", nameof(Detections));
            }

            EnsureDetectionsAllowed(_status, copy.Length);
            _detections = Array.AsReadOnly(copy);
            _verdict = ComputeVerdict(_status, copy);
        }
    }

    private static void EnsureDetectionsAllowed(ScanStatus status, int detectionCount)
    {
        if (status != ScanStatus.Scanned && detectionCount > 0)
        {
            throw new ArgumentException(
                $"A result with status {status} cannot have detections.", nameof(Detections));
        }
    }

    private static Verdict? ComputeVerdict(ScanStatus status, IReadOnlyList<Detection> detections) =>
        status != ScanStatus.Scanned
            ? null
            : detections.Count == 0 ? Models.Verdict.Clean : detections.Max(d => d.Verdict);

    /// <summary>
    /// Worst verdict among <see cref="Detections"/>, Clean if there are none, or <c>null</c> if the
    /// file was not scanned (<see cref="Status"/> is not Scanned).
    /// </summary>
    public Verdict? Verdict => _verdict;

    /// <summary>Lowercase hex SHA-256 of the file, if it was computed.</summary>
    /// <exception cref="ArgumentException">The value is not 64 hex characters.</exception>
    public string? Sha256
    {
        get => _sha256;
        init
        {
            if (value is null)
            {
                _sha256 = null;
                return;
            }

            if (value.Length != 64 || !value.All(char.IsAsciiHexDigit))
            {
                throw new ArgumentException("SHA-256 must be 64 hexadecimal characters.", nameof(Sha256));
            }

            _sha256 = value.ToLowerInvariant();
        }
    }

    [JsonRequired]
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// Authenticode outcome (Microsoft / OtherTrusted / UnsignedOrInvalid), or <c>null</c> if it wasn't checked.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not a defined <see cref="Signatures.SignatureStatus"/>.</exception>
    /// <exception cref="ArgumentException">Set on a non-Scanned result, or not trusted while <see cref="Signer"/> is set.</exception>
    public SignatureStatus? SignatureStatus
    {
        get => _signatureStatus;
        init
        {
            if (value is { } status && !Enum.IsDefined(status))
            {
                throw new ArgumentOutOfRangeException(nameof(SignatureStatus), value, "Undefined signature status.");
            }

            if (value is not null && _status != ScanStatus.Scanned)
            {
                throw new ArgumentException(
                    $"A result with status {_status} cannot have signature information.", nameof(SignatureStatus));
            }

            if (_signer is not null && !IsTrustedStatus(value))
            {
                throw new ArgumentException("A signer name requires a Microsoft or OtherTrusted signature.", nameof(SignatureStatus));
            }

            _signatureStatus = value;
        }
    }

    /// <summary>
    /// Name (certificate CN) of the trusted signer, e.g. "Microsoft Windows". Only with a Microsoft or
    /// OtherTrusted <see cref="SignatureStatus"/>; otherwise <c>null</c>.
    /// </summary>
    /// <exception cref="ArgumentException">Blank, set on a non-Scanned result, or without a trusted <see cref="SignatureStatus"/>.</exception>
    public string? Signer
    {
        get => _signer;
        init
        {
            if (value is null)
            {
                _signer = null;
                return;
            }

            ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(Signer));
            if (_status != ScanStatus.Scanned)
            {
                throw new ArgumentException(
                    $"A result with status {_status} cannot have signature information.", nameof(Signer));
            }

            if (!IsTrustedStatus(_signatureStatus))
            {
                throw new ArgumentException("A signer name requires a Microsoft or OtherTrusted signature.", nameof(Signer));
            }

            _signer = value;
        }
    }

    private static bool IsTrustedStatus(SignatureStatus? status) =>
        status is Signatures.SignatureStatus.Microsoft or Signatures.SignatureStatus.OtherTrusted;

    /// <summary>Value equality, comparing <see cref="Detections"/> element by element (order matters).</summary>
    public bool Equals(ScanResult? other) =>
        other is not null
        && (ReferenceEquals(this, other)
            || (_status == other._status
                && _item.Equals(other._item)
                && Timestamp.Equals(other.Timestamp)
                && string.Equals(_sha256, other._sha256, StringComparison.Ordinal)
                && _signatureStatus == other._signatureStatus
                && string.Equals(_signer, other._signer, StringComparison.Ordinal)
                && _detections.SequenceEqual(other._detections)));

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(_status);
        hash.Add(_item);
        hash.Add(Timestamp);
        hash.Add(_sha256, StringComparer.Ordinal);
        hash.Add(_signatureStatus);
        hash.Add(_signer, StringComparer.Ordinal);
        foreach (var detection in _detections)
        {
            hash.Add(detection);
        }

        return hash.ToHashCode();
    }
}
