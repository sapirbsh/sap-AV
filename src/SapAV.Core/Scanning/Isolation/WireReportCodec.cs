using System.Diagnostics.CodeAnalysis;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Signatures;
using SapAV.Core.Text;
using SapAV.Core.Yara;

namespace SapAV.Core.Scanning.Isolation;

/// <summary>
/// Converts a <see cref="FileScanReport"/> to its wire form in the worker (<see cref="ToWire"/>, clipping every list
/// and string to <see cref="WorkerLimits"/>) and back in the engine (<see cref="FromWire"/>, which treats the input as
/// <b>untrusted</b>: every count, length, enum and cross-field invariant is checked, and anything wrong is a
/// <see cref="WorkerProtocolException"/>, never a partly trusted report).
/// </summary>
public static class WireReportCodec
{
    private const string DroppedNotesFormat = "{0} more notes were dropped (worker message cap).";

    // ---- Worker side ----

    /// <summary>The wire form of <paramref name="report"/>, clipped to the protocol caps (worst detections kept).</summary>
    public static WireScanReport ToWire(FileScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var result = report.Result;
        return new WireScanReport
        {
            Result = new WireResult
            {
                Status = result.Status,
                Sha256 = result.Sha256,
                SignatureStatus = result.SignatureStatus,
                Signer = result.Signer is null ? null : Clip(result.Signer, WorkerLimits.MaxTextLength),
                Detections = WorstFirst(result.Detections, d => d.Verdict, WorkerLimits.MaxDetections),
            },
            Hash = ToWire(report.Hash),
            Signature = report.Signature is null ? null : ToWire(report.Signature),
            Yara = report.Yara is null ? null : ToWire(report.Yara),
            MarkOfTheWeb = report.MarkOfTheWeb is null ? null : ToWire(report.MarkOfTheWeb),
            Heuristics = report.Heuristics is null ? null : ToWire(report.Heuristics),
            Notes = ClipNotes(report.Notes),
        };
    }

    private static WireHash ToWire(HashResult hash) => new()
    {
        FailureReason = hash.FailureReason,
        Sha256 = hash.Sha256,
        Length = hash.Length,
        ErrorMessage = ClipOrNull(hash.ErrorMessage, WorkerLimits.MaxTextLength),
        LastWriteTimeUtc = hash.LastWriteTimeUtc,
        Attributes = hash.Attributes is { } a ? (int)a : null,
    };

    private static WireSignature ToWire(SignatureCheckResult signature) => new()
    {
        Status = signature.Status,
        FailureReason = signature.FailureReason,
        NotCheckedReason = signature.NotCheckedReason,
        Kind = signature.Kind,
        Signer = signature.Signer is { } signer
            ? new WireSigner { Chain = ClipChain(signer.Chain), Timestamp = signer.Timestamp }
            : null,
        CatalogPath = ClipOrNull(signature.CatalogPath, WorkerLimits.MaxPathLength),
        TrustResult = signature.TrustResult,
        Message = ClipOrNull(signature.Message, WorkerLimits.MaxTextLength),
    };

    private static IReadOnlyList<WireCertificate> ClipChain(IReadOnlyList<SignatureCertificate> chain)
    {
        // Keep the leaf and the root (what classification looks at); drop middle intermediates if ever over the cap.
        var kept = chain.Count <= WorkerLimits.MaxChainLength
            ? chain
            : [.. chain.Take(WorkerLimits.MaxChainLength - 1), chain[^1]];
        return kept.Select(c => new WireCertificate
        {
            Subject = Clip(c.Subject, WorkerLimits.MaxTextLength),
            Issuer = Clip(c.Issuer, WorkerLimits.MaxTextLength),
            Sha1Thumbprint = c.Sha1Thumbprint,
            Sha256Thumbprint = c.Sha256Thumbprint,
            NotBeforeUtc = c.NotBeforeUtc,
            NotAfterUtc = c.NotAfterUtc,
        }).ToArray();
    }

    private static WireYara ToWire(YaraScanResult yara) => new()
    {
        FailureReason = yara.FailureReason,
        Matches = WorstFirst(yara.Matches, m => m.Verdict, WorkerLimits.MaxYaraMatches).Select(m => new WireYaraMatch
        {
            File = Clip(m.File, WorkerLimits.MaxPathLength),
            Identifier = Clip(m.Identifier, WorkerLimits.MaxIdentifierLength),
            Tags = m.Tags.Take(WorkerLimits.MaxTags).Select(t => Clip(t, WorkerLimits.MaxTagLength)).ToArray(),
            Verdict = m.Verdict,
            TechniqueId = m.Mitre.PrimaryId,
            SecondaryTechniqueIds = m.Mitre.SecondaryIds.Take(WorkerLimits.MaxSecondaryTechniques).ToArray(),
            Description = ClipOrNull(m.Description, WorkerLimits.MaxTextLength),
        }).ToArray(),
        Length = yara.Length,
        ErrorMessage = ClipOrNull(yara.ErrorMessage, WorkerLimits.MaxTextLength),
        RulesFingerprint = yara.RulesFingerprint,
    };

    private static WireMarkOfTheWeb ToWire(MarkOfTheWebResult motw) => new()
    {
        Status = motw.Status,
        RawZoneId = motw.Mark?.RawZoneId,
        HostUrl = motw.Mark?.HostUrl,
        ReferrerUrl = motw.Mark?.ReferrerUrl,
        NotReadReason = motw.NotReadReason,
        Message = ClipOrNull(motw.Message, WorkerLimits.MaxTextLength),
    };

    private static WireHeuristics ToWire(HeuristicResult heuristics) => new()
    {
        Findings = heuristics.Findings.Take(WorkerLimits.MaxFindings).Select(f => new WireFinding
        {
            Kind = f.Kind,
            Score = f.Score,
            Reason = Clip(f.Reason, WorkerLimits.MaxTextLength),
            TechniqueId = f.TechniqueId,
        }).ToArray(),
        Threshold = heuristics.Threshold,
        ContentInspected = heuristics.ContentInspected,
        ContentError = ClipOrNull(heuristics.ContentError, WorkerLimits.MaxTextLength),
    };

    private static IReadOnlyList<WireNote> ClipNotes(IReadOnlyList<ScanNote> notes)
    {
        var wire = notes.Take(WorkerLimits.MaxNotes).Select(n => new WireNote
        {
            Level = n.Level,
            Message = Clip(n.Message, WorkerLimits.MaxNoteLength),
        }).ToList();
        if (notes.Count > WorkerLimits.MaxNotes)
        {
            wire[^1] = new WireNote
            {
                Level = ScanNoteLevel.Warning,
                Message = string.Format(System.Globalization.CultureInfo.InvariantCulture, DroppedNotesFormat, notes.Count - WorkerLimits.MaxNotes + 1),
            };
        }

        return wire;
    }

    private static T[] WorstFirst<T>(IReadOnlyList<T> items, Func<T, Verdict> verdict, int max) =>
        items.Count <= max ? [.. items] : [.. items.OrderByDescending(verdict).Take(max)];

    private static string Clip(string value, int max) => SafeText.SingleLine(value, max) is { Length: > 0 } s ? s : "?";

    private static string? ClipOrNull(string? value, int max) => value is null ? null : Clip(value, max);

    // ---- Engine side ----

    /// <summary>
    /// Rebuilds the report from untrusted worker output. <paramref name="item"/> and <paramref name="now"/> are the
    /// engine's own (the worker's view of the path and time is never used); Identity is left for the broker to set.
    /// </summary>
    /// <exception cref="WorkerProtocolException">Anything missing, over a cap, out of range or inconsistent.</exception>
    public static FileScanReport FromWire(WireScanReport wire, ScanItem item, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(item);
        Require(wire is not null, "report is null");
        try
        {
            var hash = FromWire(Required(wire!.Hash, "Hash"));
            var signature = wire.Signature is null ? null : FromWire(wire.Signature);
            var yara = wire.Yara is null ? null : FromWire(wire.Yara);
            var motw = wire.MarkOfTheWeb is null ? null : FromWire(wire.MarkOfTheWeb);
            var heuristics = wire.Heuristics is null ? null : FromWire(wire.Heuristics);
            var notes = FromWire(Required(wire.Notes, "Notes"));
            var result = FromWire(Required(wire.Result, "Result"), item, now, hash, signature);
            return new FileScanReport(result, hash, signature, yara, motw, heuristics, notes);
        }
        catch (ArgumentException ex)
        {
            throw new WorkerProtocolException($"Invalid scan report: {ex.Message}", ex);
        }
        catch (InvalidOperationException ex)
        {
            throw new WorkerProtocolException($"Invalid scan report: {ex.Message}", ex);
        }
    }

    private static ScanResult FromWire(WireResult wire, ScanItem item, DateTimeOffset now, HashResult hash, SignatureCheckResult? signature)
    {
        var detections = Required(wire.Detections, "Result.Detections");
        Require(detections.Count <= WorkerLimits.MaxDetections, $"{detections.Count} detections, over {WorkerLimits.MaxDetections}");
        Require(detections.All(d => d is not null), "a detection is null");
        Require(wire.Signer is null || wire.Signer.Length <= WorkerLimits.MaxTextLength, "signer name too long");

        if (wire.Sha256 is not null)
        {
            Require(hash.IsHashed && string.Equals(hash.Sha256, wire.Sha256.ToLowerInvariant(), StringComparison.Ordinal),
                "the result's SHA-256 doesn't match the hash step");
        }

        if (wire.Status == ScanStatus.Scanned)
        {
            // A scanned result has the file's hash, except an oversized file that only the name/padding heuristics saw.
            Require(hash.IsHashed ? wire.Sha256 is not null : hash.FailureReason == HashFailureReason.TooLarge,
                "a scanned result without the hash step's SHA-256");
            Require(wire.SignatureStatus == signature?.Status, "the result's signature status doesn't match the signature step");
            Require(string.Equals(wire.Signer, signature?.TrustedSignerName, StringComparison.Ordinal),
                "the result's signer doesn't match the signature step");
        }

        return new ScanResult(item, detections, now, wire.Sha256, wire.Status, wire.SignatureStatus, wire.Signer);
    }

    private static HashResult FromWire(WireHash wire)
    {
        Require(wire.Length is null or >= 0, "negative length");
        if (wire.FailureReason == HashFailureReason.None)
        {
            Require(wire.Sha256 is not null && wire.Length is not null, "a hashed result without SHA-256 or length");
            return HashResult.Hashed(wire.Sha256!, wire.Length!.Value, wire.LastWriteTimeUtc, (FileAttributes?)wire.Attributes);
        }

        Require(wire.Sha256 is null, "a failed hash with a SHA-256");
        return HashResult.NotHashed(wire.FailureReason, Text(wire.ErrorMessage, WorkerLimits.MaxTextLength), wire.Length,
            wire.LastWriteTimeUtc, (FileAttributes?)wire.Attributes);
    }

    private static SignatureCheckResult FromWire(WireSignature wire)
    {
        var signer = wire.Signer is null ? null : FromWire(wire.Signer);
        string? catalogPath = Text(wire.CatalogPath, WorkerLimits.MaxPathLength);
        string? message = Text(wire.Message, WorkerLimits.MaxTextLength);
        switch (wire.Status)
        {
            case null:
                Require(wire.FailureReason == SignatureFailureReason.None && wire.Kind == SignatureKind.None && signer is null,
                    "a not-checked signature with signature details");
                return SignatureCheckResult.NotChecked(wire.NotCheckedReason, message);

            case SignatureStatus.Microsoft or SignatureStatus.OtherTrusted:
                Require(wire.FailureReason == SignatureFailureReason.None && wire.NotCheckedReason == HashFailureReason.None
                    && signer is not null, "a trusted signature without a signer, or with a failure");
                return SignatureCheckResult.Trusted(wire.Status.Value, wire.Kind, signer!, catalogPath, message);

            case SignatureStatus.UnsignedOrInvalid when wire.FailureReason == SignatureFailureReason.NotSigned:
                Require(wire.Kind == SignatureKind.None && signer is null && wire.NotCheckedReason == HashFailureReason.None,
                    "a not-signed result with signature details");
                return SignatureCheckResult.NotSigned(message);

            case SignatureStatus.UnsignedOrInvalid:
                Require(wire.NotCheckedReason == HashFailureReason.None, "an invalid signature with a not-checked reason");
                return SignatureCheckResult.Invalid(wire.FailureReason, wire.Kind, wire.TrustResult, signer, catalogPath, message);

            default:
                throw new WorkerProtocolException($"Undefined signature status {wire.Status}.");
        }
    }

    private static SignatureSigner FromWire(WireSigner wire)
    {
        var chain = Required(wire.Chain, "Signer.Chain");
        Require(chain.Count is > 0 and <= WorkerLimits.MaxChainLength, $"a chain of {chain.Count} certificates");
        return new SignatureSigner(chain.Select(c =>
        {
            Require(c is not null, "a null certificate");
            return new SignatureCertificate(
                Text(Required(c.Subject, "Subject"), WorkerLimits.MaxTextLength, allowEmpty: true)!,
                Text(Required(c.Issuer, "Issuer"), WorkerLimits.MaxTextLength, allowEmpty: true)!,
                Required(c.Sha1Thumbprint, "Sha1Thumbprint"),
                Required(c.Sha256Thumbprint, "Sha256Thumbprint"),
                c.NotBeforeUtc,
                c.NotAfterUtc);
        }).ToArray(), wire.Timestamp);
    }

    private static YaraScanResult FromWire(WireYara wire)
    {
        var matches = Required(wire.Matches, "Yara.Matches");
        Require(matches.Count <= WorkerLimits.MaxYaraMatches, $"{matches.Count} YARA matches, over {WorkerLimits.MaxYaraMatches}");
        Require(wire.Length is null or >= 0, "negative YARA length");
        Require(wire.RulesFingerprint is null || (wire.RulesFingerprint.Length == 64 && wire.RulesFingerprint.All(char.IsAsciiHexDigitLower)),
            "malformed rules fingerprint");
        string? error = Text(wire.ErrorMessage, WorkerLimits.MaxTextLength);
        if (wire.FailureReason != YaraFailureReason.None)
        {
            Require(matches.Count == 0, "a failed YARA scan with matches");
            return YaraScanResult.NotScanned(wire.FailureReason, error, wire.Length, wire.RulesFingerprint);
        }

        Require(wire.Length is not null && wire.RulesFingerprint is not null, "a YARA scan without length or rules fingerprint");
        return YaraScanResult.Scanned(matches.Select(FromWire).ToArray(), wire.Length!.Value, wire.RulesFingerprint!);
    }

    private static YaraRuleInfo FromWire(WireYaraMatch wire)
    {
        Require(wire is not null, "a null YARA match");
        Require(wire!.Verdict is Verdict.Suspicious or Verdict.Malicious, "a YARA match must be Suspicious or Malicious");
        var tags = Required(wire.Tags, "Tags");
        Require(tags.Count <= WorkerLimits.MaxTags && tags.All(t => t is not null && t.Length <= WorkerLimits.MaxTagLength), "bad tags");
        var secondary = Required(wire.SecondaryTechniqueIds, "SecondaryTechniqueIds");
        Require(secondary.Count <= WorkerLimits.MaxSecondaryTechniques, "too many secondary techniques");
        return new YaraRuleInfo(
            Text(Required(wire.File, "File"), WorkerLimits.MaxPathLength)!,
            Text(Required(wire.Identifier, "Identifier"), WorkerLimits.MaxIdentifierLength)!,
            tags.Select(t => SafeText.SingleLine(t, WorkerLimits.MaxTagLength)).ToArray(),
            wire.Verdict,
            new MitreTechniqueSelection(Required(wire.TechniqueId, "TechniqueId"), secondary.ToArray()),
            Text(wire.Description, WorkerLimits.MaxTextLength));
    }

    private static MarkOfTheWebResult FromWire(WireMarkOfTheWeb wire)
    {
        Require(wire.HostUrl is null || wire.HostUrl.Length <= MarkOfTheWeb.MaxUrlLength, "host URL too long");
        Require(wire.ReferrerUrl is null || wire.ReferrerUrl.Length <= MarkOfTheWeb.MaxUrlLength, "referrer URL too long");
        string? message = Text(wire.Message, WorkerLimits.MaxTextLength);
        bool hasMark = wire.RawZoneId is not null || wire.HostUrl is not null || wire.ReferrerUrl is not null;
        switch (wire.Status)
        {
            case MarkOfTheWebStatus.Present:
                Require(wire.NotReadReason == HashFailureReason.None, "a present mark with a not-read reason");
                SecurityZone? zone = wire.RawZoneId is >= 0 and <= 4 ? (SecurityZone)wire.RawZoneId.Value : null;
                return MarkOfTheWebResult.Present(new MarkOfTheWeb(zone, wire.RawZoneId,
                    wire.HostUrl is null ? null : MarkOfTheWeb.SanitizeUrl(wire.HostUrl),
                    wire.ReferrerUrl is null ? null : MarkOfTheWeb.SanitizeUrl(wire.ReferrerUrl)));

            case MarkOfTheWebStatus.Absent:
                Require(!hasMark && wire.NotReadReason == HashFailureReason.None, "an absent mark with mark details");
                return MarkOfTheWebResult.Absent(message);

            case MarkOfTheWebStatus.NotRead:
                Require(!hasMark, "an unread mark with mark details");
                return MarkOfTheWebResult.NotRead(wire.NotReadReason, message);

            default:
                throw new WorkerProtocolException($"Undefined Mark-of-the-Web status {wire.Status}.");
        }
    }

    private static HeuristicResult FromWire(WireHeuristics wire)
    {
        var findings = Required(wire.Findings, "Heuristics.Findings");
        Require(findings.Count <= WorkerLimits.MaxFindings, $"{findings.Count} heuristic findings, over {WorkerLimits.MaxFindings}");
        Require(wire.Threshold is > 0 and <= WorkerLimits.MaxFindingScore, "heuristic threshold out of range");
        var rebuilt = findings.Select(f =>
        {
            Require(f is not null, "a null finding");
            Require(f!.Score is >= 0 and <= WorkerLimits.MaxFindingScore, "finding score out of range");
            MitreTechniqueIdFormat.EnsureValid(f.TechniqueId, nameof(f.TechniqueId));
            return new HeuristicFinding(f.Kind, f.Score, Text(Required(f.Reason, "Reason"), WorkerLimits.MaxTextLength)!, f.TechniqueId);
        }).ToArray();
        return new HeuristicResult(rebuilt, wire.Threshold, wire.ContentInspected, Text(wire.ContentError, WorkerLimits.MaxTextLength));
    }

    private static IReadOnlyList<ScanNote> FromWire(IReadOnlyList<WireNote> wire)
    {
        Require(wire.Count <= WorkerLimits.MaxNotes, $"{wire.Count} notes, over {WorkerLimits.MaxNotes}");
        return wire.Select(n =>
        {
            Require(n is not null, "a null note");
            return new ScanNote(n!.Level, Text(Required(n.Message, "Note"), WorkerLimits.MaxNoteLength)!);
        }).ToArray();
    }

    /// <summary>Length-checked (reject, never trust the worker to have clipped), then sanitized to one line.</summary>
    private static string? Text(string? value, int max, bool allowEmpty = false)
    {
        if (value is null)
        {
            return null;
        }

        Require(value.Length <= max, $"a string of {value.Length} characters, over {max}");
        var clean = SafeText.SingleLine(value, max);
        Require(allowEmpty || clean.Length > 0, "an empty string");
        return clean;
    }

    private static T Required<T>(T? value, string what)
        where T : class =>
        value ?? throw new WorkerProtocolException($"{what} is missing.");

    private static void Require([DoesNotReturnIf(false)] bool condition, string what)
    {
        if (!condition)
        {
            throw new WorkerProtocolException($"Invalid scan report: {what}.");
        }
    }
}
