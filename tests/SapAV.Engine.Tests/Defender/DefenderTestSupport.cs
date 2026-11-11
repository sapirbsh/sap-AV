using System.Collections.Concurrent;
using SapAV.Engine.Defender;

namespace SapAV.Engine.Tests.Defender;

/// <summary>A fake <see cref="IWmiReader"/>: per-class canned results (or handlers), and a record of every query.</summary>
internal sealed class FakeWmiReader : IWmiReader
{
    private readonly Dictionary<string, Func<WmiClassQuery, CancellationToken, Task<WmiReadResult>>> _handlers = new(StringComparer.OrdinalIgnoreCase);

    public ConcurrentQueue<WmiClassQuery> Queries { get; } = new();

    public FakeWmiReader Returns(string className, WmiReadResult result)
    {
        _handlers[className] = (_, _) => Task.FromResult(result);
        return this;
    }

    public FakeWmiReader Handles(string className, Func<WmiClassQuery, CancellationToken, Task<WmiReadResult>> handler)
    {
        _handlers[className] = handler;
        return this;
    }

    public Task<WmiReadResult> ReadAsync(WmiClassQuery query, CancellationToken cancellationToken)
    {
        Queries.Enqueue(query);
        return _handlers.TryGetValue(query.ClassName, out var handler)
            ? handler(query, cancellationToken)
            : Task.FromResult(WmiReadResult.Failure(WmiReadStatus.NotFound, "no such class in the fake"));
    }
}

/// <summary>Synthetic WMI property bags shaped like Defender's and Security Center's classes. No real Defender data.</summary>
internal static class DefenderWmiData
{
    public const string AdminPlaceholder = "N/A: Must be an administrator to view exclusions";
    public const string ThirdPartyGuid = "{11111111-2222-3333-4444-555555555555}";

    public static WmiReadResult One(Dictionary<string, object?> values) => WmiReadResult.Ok([values]);

    public static Dictionary<string, object?> HealthyStatus() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["AMServiceEnabled"] = true,
        ["AntivirusEnabled"] = true,
        ["AntispywareEnabled"] = true,
        ["RealTimeProtectionEnabled"] = true,
        ["OnAccessProtectionEnabled"] = true,
        ["BehaviorMonitorEnabled"] = true,
        ["IoavProtectionEnabled"] = true,
        ["IsTamperProtected"] = true,
        ["AMRunningMode"] = "Normal",
        ["AMProductVersion"] = "4.18.25010.11",
    };

    public static Dictionary<string, object?> Preference(string[]? paths = null, string[]? extensions = null, string[]? processes = null) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["ExclusionPath"] = paths,
            ["ExclusionExtension"] = extensions,
            ["ExclusionProcess"] = processes,
            ["ExclusionIpAddress"] = null,
            ["DisableRealtimeMonitoring"] = false,
            ["DisableBehaviorMonitoring"] = false,
            ["DisableIOAVProtection"] = false,
        };

    public static Dictionary<string, object?> Product(string name, string guid, uint state) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["displayName"] = name,
        ["instanceGuid"] = guid,
        ["productState"] = state,
    };

    /// <summary>productState with the real-time scanner on (0x1000) or off (0x0000).</summary>
    public static uint State(bool on) => on ? 0x061100u : 0x060100u;

    public static Dictionary<string, object?> DefenderProduct(bool on) =>
        Product("Windows Defender", DefenderStatusMapper.DefenderSecurityCenterGuid.ToString("B"), State(on));

    public static WmiReadResult NoSecurityCenter => WmiReadResult.Failure(WmiReadStatus.NotFound, "0x8004100E");
}
