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

/// <summary>A fake <see cref="IDefenderEnvironment"/> returning a given value, counting calls.</summary>
internal sealed class FakeDefenderEnvironment(DefenderEnvironmentInfo info) : IDefenderEnvironment
{
    private int _calls;

    public int Calls => Volatile.Read(ref _calls);

    public DefenderEnvironmentInfo Read()
    {
        Interlocked.Increment(ref _calls);
        return info;
    }
}

/// <summary>
/// A fake HKLM for <see cref="WindowsDefenderEnvironment"/>: keys (path -> values), and paths that throw access denied.
/// </summary>
internal sealed class FakeRegistryView : SapAV.Engine.Persistence.IRegistryView
{
    private readonly Dictionary<string, Dictionary<string, object>> _keys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _denied = new(StringComparer.OrdinalIgnoreCase);

    public FakeRegistryView Key(string path, params (string Name, object Value)[] values)
    {
        _keys[path] = values.ToDictionary(v => v.Name, v => v.Value, StringComparer.OrdinalIgnoreCase);
        return this;
    }

    public FakeRegistryView Denied(string path)
    {
        _denied.Add(path);
        return this;
    }

    public SapAV.Engine.Persistence.IRegistryKeyReader? Open(SapAV.Engine.Persistence.RegistryRoot root, string path)
    {
        if (_denied.Contains(path))
        {
            throw new System.Security.SecurityException("Requested registry access is not allowed.");
        }

        return _keys.TryGetValue(path, out var values) ? new Reader(values) : null;
    }

    private sealed class Reader(Dictionary<string, object> values) : SapAV.Engine.Persistence.IRegistryKeyReader
    {
        public IReadOnlyList<string> SubKeyNames() => [];

        public IReadOnlyList<string> ValueNames() => values.Keys.ToArray();

        public SapAV.Engine.Persistence.RegistryData? Value(string name) =>
            values.TryGetValue(name, out var v) ? new SapAV.Engine.Persistence.RegistryData(
                v is string ? Microsoft.Win32.RegistryValueKind.String : Microsoft.Win32.RegistryValueKind.DWord, v) : null;

        public SapAV.Engine.Persistence.IRegistryKeyReader? OpenSubKey(string name) => null;

        public void Dispose()
        {
        }
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
