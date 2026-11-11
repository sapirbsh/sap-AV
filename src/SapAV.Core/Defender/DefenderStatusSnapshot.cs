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
    /// Defender answered with exactly its <c>N/A: Must be an administrator to view exclusions</c> placeholder (one entry,
    /// trimmed, case-insensitive) and the registry fallback couldn't read the list either: unknown content, not "no exclusions".
    /// Seen as SYSTEM, it is unexpected (see <see cref="DefenderStatusSnapshot.ExclusionsHiddenFromSystem"/>).
    /// </summary>
    Hidden,

    /// <summary>Not read (the preference read failed, or this Defender version has no such list).</summary>
    Unknown,
}

/// <summary>Where a known exclusion list came from.</summary>
public enum DefenderExclusionSource
{
    /// <summary>Not read (the list is Hidden or Unknown).</summary>
    None,

    /// <summary>WMI <c>MSFT_MpPreference</c>.</summary>
    Wmi,

    /// <summary>
    /// The read-only registry fallback (<c>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\*</c> plus the Group Policy key
    /// <c>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\*</c>), used when WMI hid or didn't return the list.
    /// </summary>
    Registry,
}

/// <summary>One Defender exclusion list (paths, extensions, processes or IP addresses).</summary>
/// <remarks>
/// <para>
/// Items are untrusted (anyone with admin rights, including malware, chose them) and stored <b>raw</b> in the
/// <see cref="Text.SafeText.Identifier"/> style: characters that can't be logged on one line (controls, line breaks, unpaired
/// surrogates) become U+FFFD; nothing is trimmed, collapsed or ellipsized, so rules match what Defender actually excludes. An item
/// longer than <see cref="MaxItemLength"/> is cut at the cap (never inside a surrogate pair) and sets <see cref="Truncated"/>.
/// Use <see cref="ForDisplay"/> to show an item. Null, empty and whitespace-only items are dropped and counted in
/// <see cref="BlankItemsDropped"/> (Defender doesn't store such entries, so a non-zero count is odd in itself).
/// </para>
/// <para>
/// At most <see cref="MaxItems"/> entries are kept: the first and the last <see cref="MaxItems"/>/2, with
/// <see cref="TotalCount"/> holding the real count. <b><see cref="Truncated"/> is itself suspicious</b>: legitimate setups have a
/// handful of exclusions, and a padded list is a way to push the bad entry out of view. Rules should report a truncated list.
/// </para>
/// </remarks>
public sealed record DefenderExclusionList
{
    public const int MaxItems = 512;
    public const int MaxItemLength = 2048;
    public const int DisplayLength = 260;

    public static DefenderExclusionList Unknown { get; } = new(DefenderExclusionListState.Unknown, DefenderExclusionSource.None, [], 0, false, 0);

    public static DefenderExclusionList Hidden { get; } = new(DefenderExclusionListState.Hidden, DefenderExclusionSource.None, [], 0, false, 0);

    private DefenderExclusionList(DefenderExclusionListState state, DefenderExclusionSource source, IReadOnlyList<string> items,
        int totalCount, bool truncated, int blankItemsDropped)
    {
        State = state;
        Source = source;
        Items = items;
        TotalCount = totalCount;
        Truncated = truncated;
        BlankItemsDropped = blankItemsDropped;
    }

    public DefenderExclusionListState State { get; }

    public DefenderExclusionSource Source { get; }

    /// <summary>The entries (only when <see cref="State"/> is <see cref="DefenderExclusionListState.Known"/>; empty otherwise).</summary>
    public IReadOnlyList<string> Items { get; }

    /// <summary>How many non-blank entries the list really had (more than <see cref="Items"/> when truncated).</summary>
    public int TotalCount { get; }

    /// <summary>True when entries were left out (<see cref="MaxItems"/>) or an entry was cut (<see cref="MaxItemLength"/>). Suspicious.</summary>
    public bool Truncated { get; }

    /// <summary>Null, empty or whitespace-only entries that were dropped.</summary>
    public int BlankItemsDropped { get; }

    /// <summary>An item as one display line (<see cref="Text.SafeText.Display"/>), for logs and the UI only; never for matching.</summary>
    public static string ForDisplay(string item) => Text.SafeText.Display(item ?? string.Empty, DisplayLength);

    /// <summary>A known list from <paramref name="source"/>, stored raw (see the remarks).</summary>
    public static DefenderExclusionList Known(IEnumerable<string?> items, DefenderExclusionSource source = DefenderExclusionSource.Wmi)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (source == DefenderExclusionSource.None || !Enum.IsDefined(source))
        {
            throw new ArgumentOutOfRangeException(nameof(source), source, "A known list needs a source.");
        }

        const int half = MaxItems / 2;
        var head = new List<string>(Math.Min(half, 64));
        var tail = new Queue<string>();
        int total = 0, blanks = 0;
        bool cut = false;
        foreach (var raw in items)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                blanks++;
                continue;
            }

            total++;
            var item = Raw(raw, ref cut);
            if (head.Count < half)
            {
                head.Add(item);
                continue;
            }

            tail.Enqueue(item);
            if (tail.Count > half)
            {
                tail.Dequeue();
            }
        }

        head.AddRange(tail);
        return new DefenderExclusionList(DefenderExclusionListState.Known, source, head.AsReadOnly(), total, cut || total > MaxItems, blanks);
    }

    private static string Raw(string value, ref bool cut)
    {
        if (value.Length > MaxItemLength)
        {
            cut = true;
            int length = char.IsHighSurrogate(value[MaxItemLength - 1]) ? MaxItemLength - 1 : MaxItemLength;
            value = value[..length];
        }

        return Text.SafeText.Identifier(value);
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

    /// <summary>
    /// True when Defender is the active antivirus, false when it isn't, null when unknown. Decided by Defender's own running mode
    /// when its status was read; by Security Center only when Defender's classes don't exist (<see cref="DefenderReadState.NotInstalled"/>);
    /// any other failed read gives null. <see cref="ActiveAntivirusDecidedBy"/> says which.
    /// </summary>
    public bool? DefenderIsActiveAntivirus { get; init; }

    /// <summary>What decided <see cref="DefenderIsActiveAntivirus"/>.</summary>
    public DefenderActiveSource ActiveAntivirusDecidedBy { get; init; }

    /// <summary>True when Security Center lists an enabled antivirus other than Defender; null when Security Center is unknown.</summary>
    public bool? ThirdPartyAntivirusActive => RegisteredAntivirus?.Any(p => !p.IsDefender && p.Enabled == true);

    /// <summary>
    /// True when Defender should be present: a client SKU (Windows 10/11, <c>ProductType</c> = <c>WinNT</c>), where Defender is
    /// part of the OS. On such a machine <see cref="DefenderReadState.NotInstalled"/> is a <b>tamper sign</b> (its WMI provider was
    /// removed or broken), not a normal state. False on Server SKUs (Defender is an optional feature), null when unknown.
    /// </summary>
    public bool? DefenderExpected { get; init; }

    /// <summary>Whether the collector ran as LocalSystem (null when unknown). As SYSTEM, Defender shows the exclusion lists.</summary>
    public bool? CollectedAsSystem { get; init; }

    /// <summary>
    /// True when the collector ran as SYSTEM and Defender's WMI still answered with the "N/A" placeholder for a list. Unexpected,
    /// so worth reporting even when the registry fallback then read the list.
    /// </summary>
    public bool ExclusionsHiddenFromSystem { get; init; }
}

/// <summary>What decided <see cref="DefenderStatusSnapshot.DefenderIsActiveAntivirus"/>.</summary>
public enum DefenderActiveSource
{
    /// <summary>Nothing: the value is null.</summary>
    Unknown,

    /// <summary>Defender's <c>AMRunningMode</c> (and <c>AntivirusEnabled</c>).</summary>
    RunningMode,

    /// <summary>Security Center, because Defender's WMI classes don't exist.</summary>
    SecurityCenter,
}
