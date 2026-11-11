using SapAV.Core.Defender;
using SapAV.Core.Text;

namespace SapAV.Engine.Defender;

/// <summary>
/// Turns the three WMI reads (<c>MSFT_MpComputerStatus</c>, <c>MSFT_MpPreference</c>, Security Center <c>AntiVirusProduct</c>)
/// into a <see cref="DefenderStatusSnapshot"/>. Pure: no WMI, testable with fake property bags.
/// </summary>
/// <remarks>
/// Values of the wrong type count as unknown. An exclusion list that is exactly Defender's one-item
/// <c>N/A: Must be an administrator to view exclusions</c> placeholder is <see cref="DefenderExclusionListState.Hidden"/>; any
/// other list is kept as-is (an "N/A:" lookalike added next to real exclusions can't hide them).
/// </remarks>
public static class DefenderStatusMapper
{
    public const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    public const string ComputerStatusClass = "MSFT_MpComputerStatus";
    public const string PreferenceClass = "MSFT_MpPreference";
    public const string SecurityCenterNamespace = @"root\SecurityCenter2";
    public const string AntivirusProductClass = "AntiVirusProduct";

    /// <summary>Defender's fixed Security Center instance GUID.</summary>
    public static readonly Guid DefenderSecurityCenterGuid = new("D68DDC3A-831F-4fae-9E44-DA132C1ACF46");

    public const int MaxRegisteredProducts = 32;
    private const int MaxShortText = 128;

    public static readonly IReadOnlyCollection<string> ComputerStatusProperties =
    [
        "AMServiceEnabled", "AntivirusEnabled", "AntispywareEnabled", "RealTimeProtectionEnabled", "OnAccessProtectionEnabled",
        "BehaviorMonitorEnabled", "IoavProtectionEnabled", "IsTamperProtected", "AMRunningMode", "AMProductVersion",
    ];

    public static readonly IReadOnlyCollection<string> PreferenceProperties =
    [
        "ExclusionPath", "ExclusionExtension", "ExclusionProcess", "ExclusionIpAddress",
        "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection",
    ];

    public static readonly IReadOnlyCollection<string> AntivirusProductProperties = ["displayName", "instanceGuid", "productState"];

    public static DefenderStatusSnapshot Map(WmiReadResult computerStatus, WmiReadResult preference, WmiReadResult securityCenter, DateTimeOffset collectedAt)
    {
        ArgumentNullException.ThrowIfNull(computerStatus);
        ArgumentNullException.ThrowIfNull(preference);
        ArgumentNullException.ThrowIfNull(securityCenter);

        var (statusRead, status) = Part(computerStatus);
        var (preferenceRead, prefs) = Part(preference);
        var protection = status is null ? DefenderProtectionState.Unknown : MapProtection(status);
        var products = MapProducts(securityCenter);

        return new DefenderStatusSnapshot
        {
            CollectedAt = collectedAt,
            ComputerStatusRead = statusRead,
            PreferenceRead = preferenceRead,
            Detail = MapDetail(computerStatus, statusRead, preference, preferenceRead),
            Protection = protection,
            Preferences = prefs is null ? DefenderPreferenceFlags.Unknown : MapPreferences(prefs),
            Exclusions = prefs is null ? DefenderExclusions.Unknown : MapExclusions(prefs),
            RegisteredAntivirus = products,
            DefenderIsActiveAntivirus = IsDefenderActive(statusRead, protection, products),
        };
    }

    internal static DefenderReadState ToReadState(WmiReadStatus status) => status switch
    {
        WmiReadStatus.Ok => DefenderReadState.Available,
        WmiReadStatus.NotFound => DefenderReadState.NotInstalled,
        WmiReadStatus.ServiceNotRunning => DefenderReadState.ServiceNotRunning,
        WmiReadStatus.AccessDenied => DefenderReadState.AccessDenied,
        WmiReadStatus.Unavailable => DefenderReadState.WmiUnavailable,
        WmiReadStatus.TimedOut => DefenderReadState.TimedOut,
        _ => DefenderReadState.Failed,
    };

    /// <summary>The read state and the single instance (Defender's classes are singletons).</summary>
    private static (DefenderReadState State, IReadOnlyDictionary<string, object?>? Instance) Part(WmiReadResult result)
    {
        if (result.Status != WmiReadStatus.Ok)
        {
            return (ToReadState(result.Status), null);
        }

        return result.Instances.Count == 0 ? (DefenderReadState.Failed, null) : (DefenderReadState.Available, result.Instances[0]);
    }

    private static DefenderProtectionState MapProtection(IReadOnlyDictionary<string, object?> v)
    {
        var modeText = Text(v, "AMRunningMode");
        return new DefenderProtectionState
        {
            AntimalwareServiceEnabled = Bool(v, "AMServiceEnabled"),
            AntivirusEnabled = Bool(v, "AntivirusEnabled"),
            AntispywareEnabled = Bool(v, "AntispywareEnabled"),
            RealTimeProtectionEnabled = Bool(v, "RealTimeProtectionEnabled"),
            OnAccessProtectionEnabled = Bool(v, "OnAccessProtectionEnabled"),
            BehaviorMonitorEnabled = Bool(v, "BehaviorMonitorEnabled"),
            IoavProtectionEnabled = Bool(v, "IoavProtectionEnabled"),
            TamperProtected = Bool(v, "IsTamperProtected"),
            RunningModeText = modeText,
            RunningMode = ParseRunningMode(modeText),
            ProductVersion = Text(v, "AMProductVersion"),
        };
    }

    private static DefenderPreferenceFlags MapPreferences(IReadOnlyDictionary<string, object?> v) => new()
    {
        RealtimeMonitoringDisabled = Bool(v, "DisableRealtimeMonitoring"),
        BehaviorMonitoringDisabled = Bool(v, "DisableBehaviorMonitoring"),
        IoavProtectionDisabled = Bool(v, "DisableIOAVProtection"),
    };

    private static DefenderExclusions MapExclusions(IReadOnlyDictionary<string, object?> v) => new()
    {
        Paths = Exclusions(v, "ExclusionPath"),
        Extensions = Exclusions(v, "ExclusionExtension"),
        Processes = Exclusions(v, "ExclusionProcess"),
        IpAddresses = Exclusions(v, "ExclusionIpAddress"),
    };

    internal static DefenderRunningMode ParseRunningMode(string? text)
    {
        var normalized = text?.Trim().ToUpperInvariant();
        return normalized switch
        {
            "NORMAL" => DefenderRunningMode.Normal,
            "PASSIVE" or "PASSIVE MODE" => DefenderRunningMode.Passive,
            "SXS PASSIVE" or "SXS PASSIVE MODE" => DefenderRunningMode.SideBySidePassive,
            "EDR BLOCK" or "EDR BLOCK MODE" => DefenderRunningMode.EdrBlock,
            _ => DefenderRunningMode.Unknown,
        };
    }

    private static DefenderExclusionList Exclusions(IReadOnlyDictionary<string, object?> v, string name)
    {
        if (!v.TryGetValue(name, out var value))
        {
            return DefenderExclusionList.Unknown; // this Defender version has no such list
        }

        string?[]? items = value switch
        {
            null => [],                       // WMI returns null for an empty list
            string[] array => array,
            string single => [single],
            _ => null,
        };

        if (items is null)
        {
            return DefenderExclusionList.Unknown;
        }

        return IsHiddenPlaceholder(items) ? DefenderExclusionList.Hidden : DefenderExclusionList.Known(items);
    }

    private static bool IsHiddenPlaceholder(string?[] items)
    {
        var nonBlank = items.Where(i => !string.IsNullOrWhiteSpace(i)).ToArray();
        return nonBlank.Length == 1 && nonBlank[0]!.TrimStart().StartsWith("N/A", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<RegisteredAntivirus>? MapProducts(WmiReadResult result)
    {
        if (result.Status != WmiReadStatus.Ok)
        {
            return null;
        }

        var products = new List<RegisteredAntivirus>();
        foreach (var v in result.Instances.Take(MaxRegisteredProducts))
        {
            bool isDefender = Text(v, "instanceGuid") is { } guid && Guid.TryParse(guid, out var parsed) && parsed == DefenderSecurityCenterGuid;
            bool? enabled = Unsigned(v, "productState") is { } state ? (state & 0xF000) == 0x1000 : null; // WSC_SECURITY_PRODUCT_STATE_ON
            products.Add(new RegisteredAntivirus(Text(v, "displayName") ?? "(unnamed)", isDefender, enabled));
        }

        return products.AsReadOnly();
    }

    /// <summary>
    /// Defender's own running mode decides when known; otherwise Security Center's view of Defender, or of another enabled product.
    /// </summary>
    private static bool? IsDefenderActive(DefenderReadState statusRead, DefenderProtectionState protection, IReadOnlyList<RegisteredAntivirus>? products)
    {
        if (statusRead is DefenderReadState.NotInstalled or DefenderReadState.ServiceNotRunning)
        {
            return false;
        }

        if (statusRead == DefenderReadState.Available)
        {
            switch (protection.RunningMode)
            {
                case DefenderRunningMode.Passive or DefenderRunningMode.SideBySidePassive or DefenderRunningMode.EdrBlock:
                    return false;
                case DefenderRunningMode.Normal when protection.AntivirusEnabled is { } enabled:
                    return enabled;
            }
        }

        if (products is null)
        {
            return null;
        }

        var defender = products.FirstOrDefault(p => p.IsDefender);
        if (defender?.Enabled is { } defenderEnabled)
        {
            return defenderEnabled;
        }

        return products.Any(p => !p.IsDefender && p.Enabled == true) ? false : null;
    }

    private static string? MapDetail(WmiReadResult status, DefenderReadState statusRead, WmiReadResult preference, DefenderReadState preferenceRead)
    {
        var parts = new List<string>(2);
        if (statusRead != DefenderReadState.Available)
        {
            parts.Add($"{ComputerStatusClass}: {statusRead}{Suffix(status)}");
        }

        if (preferenceRead != DefenderReadState.Available)
        {
            parts.Add($"{PreferenceClass}: {preferenceRead}{Suffix(preference)}");
        }

        return parts.Count == 0 ? null : SafeText.SingleLine(string.Join("; ", parts), DefenderStatusSnapshot.MaxDetailLength);

        static string Suffix(WmiReadResult r) => r.Status == WmiReadStatus.Ok ? " (no instance)" : r.Detail is null ? string.Empty : $" ({r.Detail})";
    }

    private static bool? Bool(IReadOnlyDictionary<string, object?> v, string name) =>
        v.TryGetValue(name, out var value) && value is bool b ? b : null;

    private static string? Text(IReadOnlyDictionary<string, object?> v, string name) =>
        v.TryGetValue(name, out var value) && value is string s && !string.IsNullOrWhiteSpace(s) ? SafeText.SingleLine(s.Trim(), MaxShortText) : null;

    private static uint? Unsigned(IReadOnlyDictionary<string, object?> v, string name) =>
        v.TryGetValue(name, out var value) ? value switch
        {
            uint u => u,
            int i when i >= 0 => (uint)i,
            _ => null,
        } : null;
}
