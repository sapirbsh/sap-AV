namespace SapAV.Core.VirusTotal;

/// <summary>Outcome of one VirusTotal hash request (<see cref="VirusTotalClient"/>).</summary>
public enum VirusTotalStatus
{
    /// <summary>200: VirusTotal knows the file; <see cref="VirusTotalResponse.Report"/> is set. Cacheable.</summary>
    Found,

    /// <summary>404: VirusTotal has never seen the hash (an "unknown", cacheable for a short time).</summary>
    NotFound,

    /// <summary>401/403: the key is wrong or disabled. Stop querying until the key changes.</summary>
    BadKey,

    /// <summary>429 or <c>QuotaExceededError</c>: back off.</summary>
    QuotaExceeded,

    /// <summary>5xx, a timeout or a network error (offline). Try again later; never cached.</summary>
    Transient,

    /// <summary>Any other status code, a redirect, or a response that isn't a valid report. Never cached.</summary>
    Error,
}

/// <summary>
/// The small, sanitized part of a VirusTotal file report that sap-AV keeps (the response is untrusted input).
/// Every string is one display-safe line (<see cref="Text.SafeText.Display"/>) and capped, so it can go to the Event Log,
/// a SIEM and the pipe as is.
/// </summary>
/// <param name="Malicious">Engines that said malicious.</param>
/// <param name="Suspicious">Engines that said suspicious.</param>
/// <param name="Undetected">Engines that found nothing.</param>
/// <param name="Harmless">Engines that said harmless.</param>
/// <param name="TotalEngines">Sum of every analysis-stats category (including timeouts and unsupported types).</param>
/// <param name="LastAnalysisDate">When VirusTotal last analysed the file, or null if missing or implausible.</param>
/// <param name="Labels">Up to <see cref="MaxLabels"/> "Engine: result" labels of engines that flagged the file.</param>
/// <param name="ThreatLabel">VirusTotal's suggested threat label (e.g. "trojan.xyz"), or null.</param>
public sealed record VirusTotalReport(
    int Malicious, int Suspicious, int Undetected, int Harmless, int TotalEngines, DateTimeOffset? LastAnalysisDate,
    IReadOnlyList<string> Labels, string? ThreatLabel)
{
    public const int MaxLabels = 5;
    public const int MaxEngineNameLength = 48;
    public const int MaxResultLength = 96;
    public const int MaxThreatLabelLength = 96;

    /// <summary>Upper bound of one count (no real report has more than ~100 engines).</summary>
    public const int MaxCount = 1000;

    /// <summary>At least one engine flagged the file (malicious or suspicious).</summary>
    public bool IsDetected => Malicious > 0 || Suspicious > 0;

    /// <summary>"12/72 engines" style summary.</summary>
    public string DetectionRatio => $"{Malicious + Suspicious}/{TotalEngines}";
}

/// <summary>What <see cref="VirusTotalClient.LookupAsync"/> returns. Never contains the API key.</summary>
/// <param name="Status">The outcome.</param>
/// <param name="Report">The report for <see cref="VirusTotalStatus.Found"/>, else null.</param>
/// <param name="RetryAfter">The server's Retry-After (capped), if it sent one.</param>
/// <param name="Detail">A short engine-written note for logs (status code, error code), never server free text or the key.</param>
public sealed record VirusTotalResponse(VirusTotalStatus Status, VirusTotalReport? Report, TimeSpan? RetryAfter, string Detail);
