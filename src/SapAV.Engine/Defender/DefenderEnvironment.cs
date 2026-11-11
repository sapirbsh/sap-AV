using SapAV.Engine.Persistence;

namespace SapAV.Engine.Defender;

/// <summary>
/// Exclusion lists read from the registry (read-only fallback when WMI hides them). Each list is null when it couldn't be read
/// completely (a key was access-denied or failed); an existing-but-empty or missing key is an empty list.
/// </summary>
public sealed record DefenderRegistryExclusions(
    IReadOnlyList<string>? Paths,
    IReadOnlyList<string>? Extensions,
    IReadOnlyList<string>? Processes,
    IReadOnlyList<string>? IpAddresses)
{
    public static DefenderRegistryExclusions Unreadable { get; } = new(null, null, null, null);
}

/// <summary>Facts about the machine and the collector that aren't WMI: SKU, account, registry fallback.</summary>
/// <param name="IsClientSku">True on Windows 10/11 client SKUs (Defender is part of the OS), false on Server, null when unknown.</param>
/// <param name="RunningAsSystem">Whether the collector runs as LocalSystem.</param>
/// <param name="RegistryExclusions">The registry fallback for the exclusion lists.</param>
public sealed record DefenderEnvironmentInfo(bool? IsClientSku, bool? RunningAsSystem, DefenderRegistryExclusions RegistryExclusions)
{
    public static DefenderEnvironmentInfo Unknown { get; } = new(null, null, DefenderRegistryExclusions.Unreadable);
}

/// <summary>Reads <see cref="DefenderEnvironmentInfo"/>. Read-only; never throws. Faked in tests.</summary>
public interface IDefenderEnvironment
{
    DefenderEnvironmentInfo Read();
}

/// <summary>
/// The real <see cref="IDefenderEnvironment"/>: <c>ProductOptions\ProductType</c>, the process token, and the exclusion keys
/// <c>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes,IpAddresses}</c> plus their Group Policy
/// twins under <c>HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions</c> (value names are the entries). Opened
/// read-only (KEY_READ); the local key is readable by SYSTEM and Administrators only, so a normal user gets null lists.
/// </summary>
public sealed class WindowsDefenderEnvironment : IDefenderEnvironment
{
    internal const string ProductOptionsKey = @"SYSTEM\CurrentControlSet\Control\ProductOptions";
    internal const string LocalExclusionsKey = @"SOFTWARE\Microsoft\Windows Defender\Exclusions";
    internal const string PolicyExclusionsKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions";

    /// <summary>At most this many value names are read per key (a padded key is truncated later anyway).</summary>
    internal const int MaxNamesPerKey = 100_000;

    private readonly IRegistryView _registry;
    private readonly Func<bool> _isSystem;

    public WindowsDefenderEnvironment()
        : this(new WindowsRegistryView(), Sandbox.AppContainerName.IsLocalSystem)
    {
    }

    internal WindowsDefenderEnvironment(IRegistryView registry, Func<bool> isSystem)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _isSystem = isSystem ?? throw new ArgumentNullException(nameof(isSystem));
    }

    public DefenderEnvironmentInfo Read() => new(ReadIsClientSku(), ReadIsSystem(), new DefenderRegistryExclusions(
        ReadList("Paths"), ReadList("Extensions"), ReadList("Processes"), ReadList("IpAddresses")));

    private bool? ReadIsSystem()
    {
        try
        {
            return _isSystem();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    private bool? ReadIsClientSku()
    {
        try
        {
            using var key = _registry.Open(RegistryRoot.LocalMachine, ProductOptionsKey);
            return key?.Value("ProductType")?.AsString()?.Trim().ToUpperInvariant() switch
            {
                "WINNT" => true,
                "SERVERNT" or "LANMANNT" => false,
                _ => null,
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    private IReadOnlyList<string>? ReadList(string list)
    {
        var local = ValueNames(LocalExclusionsKey + "\\" + list);
        var policy = ValueNames(PolicyExclusionsKey + "\\" + list);
        if (local is null || policy is null)
        {
            return null; // a partial list must not look complete
        }

        return local.Concat(policy).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>The key's value names; empty when the key doesn't exist; null when it can't be read.</summary>
    private IReadOnlyList<string>? ValueNames(string path)
    {
        try
        {
            using var key = _registry.Open(RegistryRoot.LocalMachine, path);
            return key is null ? [] : key.ValueNames().Where(n => n.Length > 0).Take(MaxNamesPerKey).ToArray();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }
}
