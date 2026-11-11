namespace SapAV.Core.Defender;

/// <summary>
/// Whether a part of the Microsoft Defender status could be read (ROADMAP E5). Every value other than
/// <see cref="Available"/> is a normal outcome, never an exception: the values that part would have filled are unknown (null).
/// </summary>
public enum DefenderReadState
{
    /// <summary>Read. Single values can still be unknown (missing on this Defender version, or hidden from the caller).</summary>
    Available,

    /// <summary>The Defender WMI namespace or class doesn't exist: Defender isn't installed (e.g. some Server SKUs).</summary>
    NotInstalled,

    /// <summary>Defender is installed but its service isn't running (typical when a third-party antivirus took over, or tampering).</summary>
    ServiceNotRunning,

    /// <summary>WMI itself isn't reachable (the Winmgmt service is stopped, broken or the RPC call failed).</summary>
    WmiUnavailable,

    /// <summary>The caller isn't allowed to read it.</summary>
    AccessDenied,

    /// <summary>The WMI call didn't answer within the configured timeout (or an earlier call is still hung).</summary>
    TimedOut,

    /// <summary>Any other failure; <see cref="DefenderStatusSnapshot.Detail"/> says what.</summary>
    Failed,
}

/// <summary>Defender's <c>AMRunningMode</c>, which says whether it is the active antivirus.</summary>
public enum DefenderRunningMode
{
    /// <summary>Not read, or a value this version doesn't know (the raw text is in <see cref="DefenderProtectionState.RunningModeText"/>).</summary>
    Unknown,

    /// <summary>Active antivirus.</summary>
    Normal,

    /// <summary>Passive: another antivirus is the active one; Defender doesn't block.</summary>
    Passive,

    /// <summary>Passive with limited periodic scanning (side-by-side).</summary>
    SideBySidePassive,

    /// <summary>EDR in block mode (Defender for Endpoint remediates behind another antivirus).</summary>
    EdrBlock,
}

/// <summary>
/// Defender's effective protection state from <c>MSFT_MpComputerStatus</c>. Each flag is <c>null</c> when unknown.
/// </summary>
public sealed record DefenderProtectionState
{
    public static DefenderProtectionState Unknown { get; } = new();

    /// <summary><c>AMServiceEnabled</c>: the antimalware service (product) is enabled.</summary>
    public bool? AntimalwareServiceEnabled { get; init; }

    /// <summary><c>AntivirusEnabled</c>.</summary>
    public bool? AntivirusEnabled { get; init; }

    /// <summary><c>AntispywareEnabled</c>.</summary>
    public bool? AntispywareEnabled { get; init; }

    /// <summary><c>RealTimeProtectionEnabled</c>.</summary>
    public bool? RealTimeProtectionEnabled { get; init; }

    /// <summary><c>OnAccessProtectionEnabled</c>.</summary>
    public bool? OnAccessProtectionEnabled { get; init; }

    /// <summary><c>BehaviorMonitorEnabled</c>.</summary>
    public bool? BehaviorMonitorEnabled { get; init; }

    /// <summary><c>IoavProtectionEnabled</c>: scanning of downloaded files and attachments.</summary>
    public bool? IoavProtectionEnabled { get; init; }

    /// <summary><c>IsTamperProtected</c>.</summary>
    public bool? TamperProtected { get; init; }

    /// <summary><c>AMRunningMode</c>, parsed.</summary>
    public DefenderRunningMode RunningMode { get; init; }

    /// <summary><c>AMRunningMode</c> as reported (sanitized, capped), or null.</summary>
    public string? RunningModeText { get; init; }

    /// <summary><c>AMProductVersion</c> (sanitized, capped), or null.</summary>
    public string? ProductVersion { get; init; }
}

/// <summary>
/// Defender's configured switches from <c>MSFT_MpPreference</c> (the policy, which can differ from the effective state,
/// e.g. while tamper protection overrides it). Each flag is <c>null</c> when unknown.
/// </summary>
public sealed record DefenderPreferenceFlags
{
    public static DefenderPreferenceFlags Unknown { get; } = new();

    /// <summary><c>DisableRealtimeMonitoring</c>.</summary>
    public bool? RealtimeMonitoringDisabled { get; init; }

    /// <summary><c>DisableBehaviorMonitoring</c>.</summary>
    public bool? BehaviorMonitoringDisabled { get; init; }

    /// <summary><c>DisableIOAVProtection</c>.</summary>
    public bool? IoavProtectionDisabled { get; init; }
}

/// <summary>Whether an exclusion list's content is known.</summary>
public enum DefenderExclusionListState
{
    /// <summary>The list was read; <see cref="DefenderExclusionList.Items"/> is the whole list (possibly empty), unless truncated.</summary>
    Known,

    /// <summary>
    /// Defender answered with its <c>N/A: Must be an administrator to view exclusions</c> placeholder: the list exists but is
    /// hidden from this caller. Unknown content, not "no exclusions".
    /// </summary>
    Hidden,

    /// <summary>Not read (the preference read failed, or this Defender version has no such list).</summary>
    Unknown,
}

/// <summary>One Defender exclusion list (paths, extensions, processes or IP addresses).</summary>
/// <remarks>
/// Items are untrusted text (anyone with admin rights, including malware, chose them): each is one sanitized line
/// (<see cref="Text.SafeText.SingleLine"/>), capped at <see cref="MaxItemLength"/>; the list keeps at most
/// <see cref="MaxItems"/> entries and sets <see cref="Truncated"/> when it cut any.
/// </remarks>
public sealed record DefenderExclusionList
{
    public const int MaxItems = 4096;
    public const int MaxItemLength = 2048;

    public static DefenderExclusionList Unknown { get; } = new(DefenderExclusionListState.Unknown, [], truncated: false);

    public static DefenderExclusionList Hidden { get; } = new(DefenderExclusionListState.Hidden, [], truncated: false);

    public static DefenderExclusionList Empty { get; } = new(DefenderExclusionListState.Known, [], truncated: false);

    private DefenderExclusionList(DefenderExclusionListState state, IReadOnlyList<string> items, bool truncated)
    {
        State = state;
        Items = items;
        Truncated = truncated;
    }

    public DefenderExclusionListState State { get; }

    /// <summary>The entries (only when <see cref="State"/> is <see cref="DefenderExclusionListState.Known"/>; empty otherwise).</summary>
    public IReadOnlyList<string> Items { get; }

    /// <summary>True when the list or an item was cut to the caps.</summary>
    public bool Truncated { get; }

    /// <summary>A known list, sanitized and capped. Blank entries are dropped.</summary>
    public static DefenderExclusionList Known(IEnumerable<string?> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        var kept = new List<string>();
        bool truncated = false;
        foreach (var raw in items)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            if (kept.Count == MaxItems)
            {
                truncated = true;
                break;
            }

            truncated |= raw.Length > MaxItemLength;
            kept.Add(Text.SafeText.SingleLine(raw.Trim(), MaxItemLength));
        }

        return kept.Count == 0 && !truncated ? Empty : new DefenderExclusionList(DefenderExclusionListState.Known, kept.AsReadOnly(), truncated);
    }
}

/// <summary>Defender's four exclusion lists.</summary>
public sealed record DefenderExclusions
{
    public static DefenderExclusions Unknown { get; } = new();

    /// <summary><c>ExclusionPath</c>: files and folders.</summary>
    public DefenderExclusionList Paths { get; init; } = DefenderExclusionList.Unknown;

    /// <summary><c>ExclusionExtension</c>.</summary>
    public DefenderExclusionList Extensions { get; init; } = DefenderExclusionList.Unknown;

    /// <summary><c>ExclusionProcess</c>: files opened by these processes aren't scanned.</summary>
    public DefenderExclusionList Processes { get; init; } = DefenderExclusionList.Unknown;

    /// <summary><c>ExclusionIpAddress</c> (network inspection); Unknown on versions without it.</summary>
    public DefenderExclusionList IpAddresses { get; init; } = DefenderExclusionList.Unknown;
}

/// <summary>An antivirus product registered with Windows Security Center (<c>root\SecurityCenter2</c> <c>AntiVirusProduct</c>).</summary>
/// <param name="DisplayName">The product's name (sanitized, capped). Self-reported by the product: informational only.</param>
/// <param name="IsDefender">True for Defender's own registration (decided by its fixed instance GUID, not the name).</param>
/// <param name="Enabled">True when its real-time scanner reports "on" in <c>productState</c>; null when the state is missing.</param>
public sealed record RegisteredAntivirus(string DisplayName, bool IsDefender, bool? Enabled);

/// <summary>
/// A read-only snapshot of Microsoft Defender's status and exclusions (ROADMAP E5), from <see cref="IDefenderStatusSource"/>.
/// The input for the Defender-tampering rules (E5, detection-dev) and the Quick Scan check (E7).
/// </summary>
/// <remarks>
/// "Defender not installed / not running / third-party antivirus active / WMI unavailable / access denied / timed out" are
/// all ordinary snapshots: see <see cref="Availability"/>, <see cref="ComputerStatusRead"/> and <see cref="PreferenceRead"/>.
/// Anything not read is null / <see cref="DefenderExclusionListState.Unknown"/>, never a guessed default: a rule must not
/// report "protection disabled" or "no exclusions" from an unknown value.
/// </remarks>
public sealed record DefenderStatusSnapshot
{
    public const int MaxDetailLength = 512;

    /// <summary>When the snapshot was taken.</summary>
    public required DateTimeOffset CollectedAt { get; init; }

    /// <summary>How the <c>MSFT_MpComputerStatus</c> read went (fills <see cref="Protection"/>).</summary>
    public required DefenderReadState ComputerStatusRead { get; init; }

    /// <summary>How the <c>MSFT_MpPreference</c> read went (fills <see cref="Exclusions"/> and <see cref="Preferences"/>).</summary>
    public required DefenderReadState PreferenceRead { get; init; }

    /// <summary>The overall state: <see cref="ComputerStatusRead"/> unless that is Available, then <see cref="PreferenceRead"/>.</summary>
    public DefenderReadState Availability => ComputerStatusRead != DefenderReadState.Available ? ComputerStatusRead : PreferenceRead;

    /// <summary>A short reason when a read wasn't Available (sanitized, capped), for logs and the UI.</summary>
    public string? Detail { get; init; }

    public DefenderProtectionState Protection { get; init; } = DefenderProtectionState.Unknown;

    public DefenderPreferenceFlags Preferences { get; init; } = DefenderPreferenceFlags.Unknown;

    public DefenderExclusions Exclusions { get; init; } = DefenderExclusions.Unknown;

    /// <summary>Antivirus products registered with Security Center; null when unknown (e.g. Windows Server has no Security Center).</summary>
    public IReadOnlyList<RegisteredAntivirus>? RegisteredAntivirus { get; init; }

    /// <summary>True when Defender is the active antivirus, false when it isn't (passive, not running, another product active), null when unknown.</summary>
    public bool? DefenderIsActiveAntivirus { get; init; }

    /// <summary>True when Security Center lists an enabled antivirus other than Defender.</summary>
    public bool ThirdPartyAntivirusActive => RegisteredAntivirus?.Any(p => !p.IsDefender && p.Enabled == true) == true;
}
