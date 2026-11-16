using System.Text.Json.Serialization;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.BrowserHijack;

/// <summary>Stable IDs of the browser-hijack rules (E6). The UI, tests and E11's removal step key on them.</summary>
public static class BrowserHijackRuleIds
{
    // Proxy / PAC (WinINet keys and the WinHTTP proxy).
    public const string ProxyLocal = "proxy-local";
    public const string ProxyPublicAddress = "proxy-public-address";
    public const string ProxyUnmanaged = "proxy-unmanaged";
    public const string PacUserFolderFile = "pac-user-folder-file";
    public const string PacLocalFile = "pac-local-file";
    public const string PacLocal = "pac-local";
    public const string PacPublicAddress = "pac-public-address";
    public const string PacUnmanaged = "pac-unmanaged";
    public const string PacUnusualUrl = "pac-unusual-url";

    /// <summary>A localhost proxy plus a PAC script in a user-writable folder for the same account: a local interception kit.</summary>
    public const string LocalProxyWithUserPac = "proxy-local-with-user-pac";

    public const string ProxyValueTruncated = "proxy-value-truncated";
    public const string WinHttpValueTooLarge = "winhttp-value-too-large";
    public const string ProfilesTruncated = "profiles-truncated";

    // Hosts entries.
    public const string HostsRedirectsListedDomain = "hosts-redirect-listed-domain";
    public const string HostsBlocksDefenderDomain = "hosts-block-defender-domain";
    public const string HostsBlocksSecurityDomain = "hosts-block-security-domain";
    public const string HostsNonCanonicalAddress = "hosts-noncanonical-address";

    /// <summary>More flagged hosts entries of one rule than are reported one by one (<see cref="BrowserHijackRules.MaxHostsFindingsPerRule"/>).</summary>
    public const string HostsMoreFlagged = "hosts-more-flagged";

    // The hosts file itself.
    public const string HostsEncodingMismatch = "hosts-encoding-mismatch";
    public const string HostsTruncated = "hosts-truncated";
    public const string HostsWritableByUsers = "hosts-writable-by-users";
    public const string HostsHardLinks = "hosts-hard-links";
    public const string HostsPathRedirected = "hosts-path-redirected";
    public const string HostsDataBasePathRedirected = "hosts-databasepath-redirected";
    public const string HostsDataBasePathUserFolder = "hosts-databasepath-user-folder";
}

/// <summary>What a <see cref="BrowserHijackFinding"/> is about. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<BrowserHijackFindingKind>))]
public enum BrowserHijackFindingKind
{
    /// <summary>A WinINet proxy or PAC setting (per user, machine, or a Group Policy key).</summary>
    Proxy,

    /// <summary>The machine-wide WinHTTP proxy.</summary>
    WinHttpProxy,

    /// <summary>One hosts-file entry.</summary>
    HostsEntry,

    /// <summary>The hosts file itself (encoding, size, permissions, links, where the resolver reads it from).</summary>
    HostsFile,
}

/// <summary>Where a flagged setting lives. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<BrowserHijackLocation>))]
public enum BrowserHijackLocation
{
    None,

    /// <summary><c>HKU\&lt;SID&gt;\Software\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</summary>
    UserSettings,

    /// <summary><c>HKU\&lt;SID&gt;\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</summary>
    UserPolicy,

    /// <summary><c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</summary>
    MachineSettings,

    /// <summary><c>HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</summary>
    MachinePolicy,

    /// <summary><c>HKLM\...\Internet Settings\Connections\WinHttpSettings</c>.</summary>
    WinHttp,

    /// <summary>The hosts file (<see cref="HostsFileSnapshot.Path"/>).</summary>
    HostsFile,

    /// <summary><c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath</c>.</summary>
    DataBasePath,
}

/// <summary>
/// The exact raw item a finding is about, so a later user-confirmed removal (E11 / Phase 2) changes exactly that and nothing
/// else. Every string is untrusted (malware chose it): <b>never display or log it</b>; the finding's
/// <see cref="BrowserHijackFinding.Reason"/> carries the display form.
/// </summary>
/// <param name="Location">The key, file or value it was read from.</param>
/// <param name="Sid">The account (for <see cref="BrowserHijackLocation.UserSettings"/> / <see cref="BrowserHijackLocation.UserPolicy"/>), else null.</param>
/// <param name="ValueName">The registry value (<c>ProxyServer</c>, <c>AutoConfigURL</c>, <c>DefaultConnectionSettings</c>, ...), else null.</param>
/// <param name="RawValue">The value or the hosts address as stored, else null.</param>
/// <param name="HostsLine">The 1-based hosts line, else null.</param>
/// <param name="HostsName">The hosts name as stored, else null.</param>
public sealed record BrowserHijackItem(
    BrowserHijackLocation Location,
    string? Sid = null,
    string? ValueName = null,
    string? RawValue = null,
    int? HostsLine = null,
    string? HostsName = null);

/// <summary>
/// One browser-hijack finding (ROADMAP E6, threat pack "Browser hijack"): Suspicious or Malicious, with its own category
/// (<see cref="ThreatCategory.BrowserHijack"/>, or <see cref="ThreatCategory.DefenderTampering"/> for hosts entries that block
/// Windows Update / Defender) and MITRE technique. A finding about the system, not a file: it is never quarantined, and nothing is
/// changed automatically. The user decides; removing a setting or a hosts line is a later user-confirmed action.
/// </summary>
public sealed record BrowserHijackFinding
{
    public const int MaxReasonLength = 900;

    /// <summary>Shown with every finding: what the user can do, and that sap-AV doesn't change it on its own.</summary>
    public const string UserDecides =
        "You decide: if you didn't set this up (and your organization didn't), remove it. sap-AV never changes these settings on its own.";

    private static readonly string[] AllowedTechniques =
        [MitreTechniqueIds.AdversaryInTheMiddle, MitreTechniqueIds.StoredDataManipulation, MitreTechniqueIds.DisableOrModifyTools];

    public BrowserHijackFinding(string ruleId, Verdict verdict, BrowserHijackFindingKind kind, string reason, string techniqueId,
        ThreatCategory category = ThreatCategory.BrowserHijack, BrowserHijackItem? item = null, IReadOnlyList<string>? secondaryTechniqueIds = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        ArgumentNullException.ThrowIfNull(reason);
        if (verdict is not (Verdict.Suspicious or Verdict.Malicious))
        {
            throw new ArgumentOutOfRangeException(nameof(verdict), verdict, "A browser-hijack finding is Suspicious or Malicious.");
        }

        if (!Enum.IsDefined(kind) || category is not (ThreatCategory.BrowserHijack or ThreatCategory.DefenderTampering))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "Undefined kind, or a category other than BrowserHijack / DefenderTampering.");
        }

        if (!AllowedTechniques.Contains(techniqueId) || (secondaryTechniqueIds?.Any(t => !AllowedTechniques.Contains(t)) ?? false))
        {
            throw new ArgumentException("Browser-hijack findings map to T1557, T1565.001 or T1562.001.", nameof(techniqueId));
        }

        string safe = SafeText.Display(reason, MaxReasonLength);
        RuleId = ruleId;
        Verdict = verdict;
        Kind = kind;
        Reason = safe.Length == 0 ? ruleId : safe;
        TechniqueId = techniqueId;
        SecondaryTechniqueIds = Array.AsReadOnly((secondaryTechniqueIds ?? []).Where(t => t != techniqueId).Distinct().ToArray());
        Category = category;
        Item = item;
    }

    /// <summary>A <see cref="BrowserHijackRuleIds"/> value.</summary>
    public string RuleId { get; }

    /// <summary>Suspicious or Malicious.</summary>
    public Verdict Verdict { get; }

    public BrowserHijackFindingKind Kind { get; }

    /// <summary>What is wrong and why it matters, one display line (<see cref="SafeText.Display"/>; untrusted values in it are capped and quoted).</summary>
    public string Reason { get; }

    /// <summary>T1557 (proxy / PAC), T1565.001 (hosts redirection and hosts-file tampering) or T1562.001 (blocking security sites).</summary>
    public string TechniqueId { get; }

    public IReadOnlyList<string> SecondaryTechniqueIds { get; }

    public ThreatCategory Category { get; }

    /// <summary>The exact raw item, for removal. Untrusted: never display or log it. Null when the finding isn't about one item.</summary>
    [JsonIgnore]
    public BrowserHijackItem? Item { get; }

    /// <summary>
    /// The finding as a <see cref="Detection"/> for alerts, results and the Event Log. Source is
    /// <see cref="DetectionSource.Heuristic"/> until a dedicated system-state source exists (E7).
    /// </summary>
    public Detection ToDetection() => new(Verdict, Reason, TechniqueId, DetectionSource.Heuristic, SecondaryTechniqueIds, Category);
}

/// <summary>What the browser-hijack check came to. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<BrowserHijackOutcome>))]
public enum BrowserHijackOutcome
{
    /// <summary>Everything the rules need was read, and nothing was found.</summary>
    Clean,

    /// <summary>Nothing was found, but part of the state couldn't be judged. Never reported as Clean; see <see cref="BrowserHijackAssessment.Unverified"/>.</summary>
    Unverified,

    Suspicious,
    Malicious,
}

/// <summary>The result of <see cref="BrowserHijackRules.Evaluate"/>: findings, plus what couldn't be judged.</summary>
public sealed record BrowserHijackAssessment
{
    public const int MaxUnverifiedReasons = 16;

    public BrowserHijackAssessment(IReadOnlyList<BrowserHijackFinding> findings, IReadOnlyList<string> unverified)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(unverified);
        Findings = Array.AsReadOnly(findings.OrderByDescending(f => f.Verdict).ToArray());
        Unverified = Array.AsReadOnly(unverified.Select(r => SafeText.Display(r, BrowserHijackFinding.MaxReasonLength))
            .Where(r => r.Length > 0).Distinct(StringComparer.Ordinal).Take(MaxUnverifiedReasons).ToArray());
    }

    /// <summary>Worst first.</summary>
    public IReadOnlyList<BrowserHijackFinding> Findings { get; }

    /// <summary>What couldn't be judged and why (empty when everything was read). Display lines.</summary>
    public IReadOnlyList<string> Unverified { get; }

    /// <summary>The worst finding's verdict; Clean when there are none, which doesn't mean verified: read <see cref="Outcome"/>.</summary>
    public Verdict Verdict => Findings.Count == 0 ? Verdict.Clean : Findings[0].Verdict;

    public BrowserHijackOutcome Outcome => Verdict switch
    {
        Verdict.Malicious => BrowserHijackOutcome.Malicious,
        Verdict.Suspicious => BrowserHijackOutcome.Suspicious,
        _ when Unverified.Count > 0 => BrowserHijackOutcome.Unverified,
        _ => BrowserHijackOutcome.Clean,
    };

    /// <summary>The findings as detections, worst first.</summary>
    public IReadOnlyList<Detection> Detections => [.. Findings.Select(f => f.ToDetection())];
}
