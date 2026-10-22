using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.Text;

namespace SapAV.Core.Alerts;

/// <summary>
/// One alert per incident (for a file: one alert per scanned file with a Suspicious or Malicious verdict,
/// carrying all its reasons). This is the payload of the Windows Event Log (X2), the SIEM feed and, later, the
/// pipe. Field names are stable; <see cref="SchemaVersion"/> changes if they ever have to.
/// </summary>
/// <remarks>
/// <para>
/// Every alert is valid and log-safe by construction, whether built by <see cref="FromReport"/>, the constructor
/// or JSON: free text is sanitised with <see cref="SafeText.SingleLine"/>, the path with
/// <see cref="SafeText.Identifier"/>, the URL with <see cref="MarkOfTheWeb.SanitizeUrlForLog"/>, and
/// <see cref="Timestamp"/> is converted to UTC.
/// </para>
/// <para>
/// JSON (same rules as the A1 models): required members missing or null, or an enum value that is not an exact
/// name, throw <see cref="System.Text.Json.JsonException"/>; invalid content throws <see cref="ArgumentException"/>
/// (or a subclass). All values go through the constructor, so cross-field rules don't depend on property order.
/// The required properties have a <c>private init</c> only because <see cref="JsonRequiredAttribute"/> needs a
/// setter; nothing outside this type can set them, so <c>with</c> can't bypass the constructor's checks.
/// </para>
/// </remarks>
public sealed record Alert
{
    /// <summary>Version of the JSON field set.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Longest <see cref="Signer"/> kept, in characters.</summary>
    public const int MaxSignerLength = 256;

    /// <summary>Longest <see cref="EngineVersion"/> accepted, in characters.</summary>
    public const int MaxEngineVersionLength = 64;

    /// <summary>The <see cref="Signer"/> value for a signer name that sanitises to nothing.</summary>
    public const string UnreadableSigner = "\uFFFD";

    private readonly IReadOnlyList<string> _secondaryTechniqueIds;
    private readonly IReadOnlyList<string> _reasons;

    /// <exception cref="ArgumentException">A value is invalid (see each property).</exception>
    [JsonConstructor]
    public Alert(
        Guid alertId,
        DateTimeOffset timestamp,
        AlertType type,
        Verdict verdict,
        string filePath,
        string? sha256,
        SignatureStatus? signatureStatus,
        string? signer,
        string? techniqueId,
        IReadOnlyList<string>? secondaryTechniqueIds,
        IReadOnlyList<string>? reasons,
        string? sourceUrl,
        AlertAction action,
        ScanTrigger trigger,
        string engineVersion)
    {
        if (alertId == Guid.Empty)
        {
            throw new ArgumentException("The alert ID must not be empty.", nameof(alertId));
        }

        EnsureDefined(type, nameof(type));
        EnsureDefined(verdict, nameof(verdict));
        EnsureDefined(action, nameof(action));
        EnsureDefined(trigger, nameof(trigger));
        EnsureVerdictFitsType(type, verdict);

        AlertId = alertId;
        Timestamp = timestamp.ToUniversalTime();
        Type = type;
        Verdict = verdict;
        FilePath = ValidatePath(filePath);
        Sha256 = ValidateSha256(sha256);
        (SignatureStatus, Signer) = ValidateSignature(signatureStatus, signer);
        TechniqueId = ValidateTechniqueId(type, techniqueId);
        _secondaryTechniqueIds = ValidateSecondaryTechniqueIds(secondaryTechniqueIds);
        _reasons = ValidateReasons(type, reasons);
        SourceUrl = MarkOfTheWeb.SanitizeUrlForLog(sourceUrl);
        Action = action;
        Trigger = trigger;
        EngineVersion = ValidateEngineVersion(engineVersion);
    }

    /// <summary>Always <see cref="CurrentSchemaVersion"/> (written to JSON; ignored when reading).</summary>
    public int SchemaVersion => CurrentSchemaVersion;

    /// <summary>
    /// Stable ID: <see cref="FromReport"/> derives it from the incident (<see cref="ComputeAlertId"/>), so building
    /// the alert again for the same scan gives the same ID, and the Event Log, the pipe and quarantine metadata
    /// can refer to the same alert.
    /// </summary>
    [JsonRequired]
    [JsonInclude]
    public Guid AlertId { get; private init; }

    /// <summary>When the incident happened (the scan time for a file), always UTC (offset zero).</summary>
    [JsonRequired]
    [JsonInclude]
    public DateTimeOffset Timestamp { get; private init; }

    [JsonRequired]
    [JsonInclude]
    public AlertType Type { get; private init; }

    /// <summary>Must match <see cref="Type"/>: MaliciousFile = Malicious, SuspiciousFile / PUP = Suspicious; never Clean.</summary>
    [JsonRequired]
    [JsonInclude]
    public Verdict Verdict { get; private init; }

    /// <summary>Full path of the file. Never cut; controls and unpaired surrogates become U+FFFD.</summary>
    [JsonRequired]
    [JsonInclude]
    public string FilePath { get; private init; }

    /// <summary>Lowercase hex SHA-256, or null if it wasn't computed.</summary>
    public string? Sha256 { get; }

    /// <summary>Authenticode outcome, or null if the signature wasn't checked.</summary>
    public SignatureStatus? SignatureStatus { get; }

    /// <summary>Trusted signer name (only with Microsoft / OtherTrusted), sanitised and capped at <see cref="MaxSignerLength"/>.
    /// A name with nothing printable left becomes <see cref="UnreadableSigner"/> (U+FFFD).</summary>
    public string? Signer { get; }

    /// <summary>Primary MITRE ATT&amp;CK technique (from the worst detection). Required for file detection types.</summary>
    public string? TechniqueId { get; }

    /// <summary>Other techniques of all detections, distinct, without the primary one. Read-only copy.</summary>
    public IReadOnlyList<string> SecondaryTechniqueIds => _secondaryTechniqueIds;

    /// <summary>
    /// One line per detection, worst verdict first, each sanitised and capped at <see cref="Detection.MaxReasonLength"/>.
    /// At least one for file detection types. Read-only copy.
    /// </summary>
    public IReadOnlyList<string> Reasons => _reasons;

    /// <summary>Mark-of-the-Web download URL in log form (user info redacted, no query / fragment), or null.</summary>
    public string? SourceUrl { get; }

    [JsonRequired]
    [JsonInclude]
    public AlertAction Action { get; private init; }

    [JsonRequired]
    [JsonInclude]
    public ScanTrigger Trigger { get; private init; }

    /// <summary>Version of the engine that raised the alert, e.g. <c>0.1.0+3b681a8</c>.</summary>
    [JsonRequired]
    [JsonInclude]
    public string EngineVersion { get; private init; }

    /// <summary>
    /// Builds the alert for a scan, or returns null when there is nothing to report (Clean, or not scanned:
    /// a file that wasn't scanned has no verdict and is logged by the engine, not alerted).
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="report"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="engineVersion"/> or <paramref name="action"/> is invalid.</exception>
    public static Alert? FromReport(FileScanReport report, AlertAction action, string engineVersion)
    {
        ArgumentNullException.ThrowIfNull(report);
        return FromScanResult(report.Result, report.SourceUrl, action, engineVersion);
    }

    /// <summary>
    /// Builds the alert for a scan result (see <see cref="FromReport"/>). <paramref name="sourceUrl"/> is the
    /// Mark-of-the-Web URL, if any; it is converted to the log form.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="result"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="engineVersion"/> or <paramref name="action"/> is invalid.</exception>
    public static Alert? FromScanResult(ScanResult result, string? sourceUrl, AlertAction action, string engineVersion)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Verdict is not { } verdict || verdict == Verdict.Clean)
        {
            return null;
        }

        var type = verdict == Verdict.Malicious ? AlertType.MaliciousFile : AlertType.SuspiciousFile;

        // Worst first (stable), so the primary technique and the first reasons belong to the worst finding,
        // and a size cap that drops reasons from the end drops the least severe ones.
        var ordered = result.Detections.OrderByDescending(d => d.Verdict).ToArray();
        string primary = ordered[0].TechniqueId;
        var secondaries = ordered
            .SelectMany(d => d.SecondaryTechniqueIds.Prepend(d.TechniqueId))
            .Where(id => id != primary)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var timestamp = result.Timestamp.ToUniversalTime();
        var id = ComputeAlertId(type, timestamp, result.Item.Path, result.Sha256, result.Item.Trigger);

        return new Alert(id, timestamp, type, verdict, result.Item.Path, result.Sha256, result.SignatureStatus,
            result.Signer, primary, secondaries, ordered.Select(d => d.Reason).ToArray(), sourceUrl, action,
            result.Item.Trigger, engineVersion);
    }

    /// <summary>
    /// Deterministic alert ID: an RFC 9562 version-8 GUID from the SHA-256 of the incident's identifying values.
    /// The same file, hash, time (to the tick), type and trigger always give the same ID; anything else differs.
    /// </summary>
    public static Guid ComputeAlertId(
        AlertType type, DateTimeOffset timestamp, string filePath, string? sha256, ScanTrigger trigger)
    {
        ArgumentNullException.ThrowIfNull(filePath);
        string canonical = string.Join('\n',
            "sap-AV alert v1",
            type.ToString(),
            timestamp.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            filePath,
            sha256?.ToLowerInvariant() ?? string.Empty,
            trigger.ToString());

        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.UTF8.GetBytes(canonical), hash);
        var bytes = hash[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80); // version 8
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80); // RFC variant
        return new Guid(bytes, bigEndian: true);
    }

    private static void EnsureDefined<T>(T value, string name)
        where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(name, value, $"Undefined {typeof(T).Name}.");
        }
    }

    private static void EnsureVerdictFitsType(AlertType type, Verdict verdict)
    {
        bool fits = type switch
        {
            AlertType.MaliciousFile => verdict == Verdict.Malicious,
            AlertType.SuspiciousFile or AlertType.PotentiallyUnwantedFile => verdict == Verdict.Suspicious,
            _ => verdict != Verdict.Clean,
        };

        if (!fits)
        {
            throw new ArgumentException($"Verdict {verdict} does not fit alert type {type}.", nameof(verdict));
        }
    }

    private static bool IsFileDetection(AlertType type) =>
        type is AlertType.MaliciousFile or AlertType.SuspiciousFile or AlertType.PotentiallyUnwantedFile;

    private static string ValidatePath(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath, nameof(filePath));
        return SafeText.Identifier(filePath);
    }

    private static string? ValidateSha256(string? sha256)
    {
        if (sha256 is null)
        {
            return null;
        }

        if (sha256.Length != 64 || !sha256.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException("SHA-256 must be 64 hexadecimal characters.", nameof(sha256));
        }

        return sha256.ToLowerInvariant();
    }

    private static (SignatureStatus?, string?) ValidateSignature(SignatureStatus? status, string? signer)
    {
        if (status is { } s)
        {
            EnsureDefined(s, "signatureStatus");
        }

        if (signer is null)
        {
            return (status, null);
        }

        if (status is not (Signatures.SignatureStatus.Microsoft or Signatures.SignatureStatus.OtherTrusted))
        {
            throw new ArgumentException("A signer name requires a Microsoft or OtherTrusted signature.", nameof(signer));
        }

        // A certificate CN can be nothing but control characters or blanks. Never drop the alert for that: a
        // trusted-signed malicious file must still be reported, so an empty result becomes U+FFFD.
        var clean = SafeText.SingleLine(signer, MaxSignerLength);
        return (status, clean.Length == 0 ? UnreadableSigner : clean);
    }

    private static string? ValidateTechniqueId(AlertType type, string? techniqueId)
    {
        if (techniqueId is null)
        {
            if (IsFileDetection(type))
            {
                throw new ArgumentException($"Alert type {type} needs a MITRE technique ID.", nameof(techniqueId));
            }

            return null;
        }

        MitreTechniqueIdFormat.EnsureValid(techniqueId, nameof(techniqueId));
        return techniqueId;
    }

    private static IReadOnlyList<string> ValidateSecondaryTechniqueIds(IReadOnlyList<string>? secondaryTechniqueIds)
    {
        var copy = secondaryTechniqueIds?.ToArray() ?? [];
        foreach (var id in copy)
        {
            MitreTechniqueIdFormat.EnsureValid(id, nameof(secondaryTechniqueIds));
        }

        return Array.AsReadOnly(copy);
    }

    private static IReadOnlyList<string> ValidateReasons(AlertType type, IReadOnlyList<string>? reasons)
    {
        var copy = new string[reasons?.Count ?? 0];
        for (int i = 0; i < copy.Length; i++)
        {
            var reason = reasons![i] ?? throw new ArgumentException("Reasons must not contain null.", nameof(reasons));
            copy[i] = SafeText.SingleLine(reason, Detection.MaxReasonLength);
            if (copy[i].Length == 0)
            {
                throw new ArgumentException("Reasons must not be blank.", nameof(reasons));
            }
        }

        if (copy.Length == 0 && IsFileDetection(type))
        {
            throw new ArgumentException($"Alert type {type} needs at least one reason.", nameof(reasons));
        }

        return Array.AsReadOnly(copy);
    }

    private static string ValidateEngineVersion(string engineVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(engineVersion, nameof(engineVersion));
        if (engineVersion.Length > MaxEngineVersionLength
            || !engineVersion.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '+' or '_'))
        {
            throw new ArgumentException(
                $"The engine version must be 1-{MaxEngineVersionLength} characters of A-Z, a-z, 0-9, '.', '-', '+', '_'.",
                nameof(engineVersion));
        }

        return engineVersion;
    }

    /// <summary>Value equality, comparing the lists element by element (order matters).</summary>
    public bool Equals(Alert? other) =>
        other is not null
        && (ReferenceEquals(this, other)
            || (AlertId == other.AlertId
                && Timestamp.Equals(other.Timestamp)
                && Type == other.Type
                && Verdict == other.Verdict
                && string.Equals(FilePath, other.FilePath, StringComparison.Ordinal)
                && string.Equals(Sha256, other.Sha256, StringComparison.Ordinal)
                && SignatureStatus == other.SignatureStatus
                && string.Equals(Signer, other.Signer, StringComparison.Ordinal)
                && string.Equals(TechniqueId, other.TechniqueId, StringComparison.Ordinal)
                && _secondaryTechniqueIds.SequenceEqual(other._secondaryTechniqueIds, StringComparer.Ordinal)
                && _reasons.SequenceEqual(other._reasons, StringComparer.Ordinal)
                && string.Equals(SourceUrl, other.SourceUrl, StringComparison.Ordinal)
                && Action == other.Action
                && Trigger == other.Trigger
                && string.Equals(EngineVersion, other.EngineVersion, StringComparison.Ordinal)));

    public override int GetHashCode() => HashCode.Combine(AlertId, Timestamp, Type, Verdict, FilePath, Sha256, Action);
}
