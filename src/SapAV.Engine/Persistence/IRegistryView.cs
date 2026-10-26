using Microsoft.Win32;

namespace SapAV.Engine.Persistence;

/// <summary>The registry roots the collectors read.</summary>
internal enum RegistryRoot
{
    /// <summary><c>HKEY_LOCAL_MACHINE</c> (64-bit view; WOW6432Node is read explicitly).</summary>
    LocalMachine,

    /// <summary><c>HKEY_USERS</c> (loaded user hives only).</summary>
    Users,
}

/// <summary>A registry value as stored: environment names are <b>not</b> expanded (the engine's environment is never used).</summary>
internal readonly record struct RegistryData(RegistryValueKind Kind, object? Data)
{
    /// <summary>The text of a REG_SZ / REG_EXPAND_SZ (or the first REG_MULTI_SZ string); null for other kinds.</summary>
    public string? AsString() => Data switch
    {
        string s => s,
        string[] { Length: > 0 } multi => multi[0],
        _ => null,
    };

    /// <summary>A REG_DWORD / REG_QWORD, or a REG_SZ holding a decimal or <c>0x</c> hex number.</summary>
    public long? AsNumber() => Data switch
    {
        int i => (uint)i,
        long l => l,
        string s when s.Trim().StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && long.TryParse(s.Trim()[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) => hex,
        string s when long.TryParse(s.Trim(), out var dec) => dec,
        _ => null,
    };

    public byte[]? AsBinary() => Data as byte[];
}

/// <summary>
/// Read-only registry access for the persistence collectors (ROADMAP C2), so tests can point them at a throwaway HKCU
/// key or a fake. Opening a missing key returns null; access problems throw <see cref="UnauthorizedAccessException"/> or
/// <see cref="System.Security.SecurityException"/> (the collectors turn them into issues).
/// </summary>
internal interface IRegistryView
{
    IRegistryKeyReader? Open(RegistryRoot root, string path);
}

/// <summary>An open, read-only key.</summary>
internal interface IRegistryKeyReader : IDisposable
{
    IReadOnlyList<string> SubKeyNames();

    IReadOnlyList<string> ValueNames();

    /// <summary>The value (unexpanded), or null when it doesn't exist. <c>""</c> is the default value.</summary>
    RegistryData? Value(string name);

    IRegistryKeyReader? OpenSubKey(string name);
}

/// <summary>
/// The real registry, read-only (KEY_READ), 64-bit view. Tests root it at a throwaway HKCU key instead of HKLM / HKU.
/// Registry symbolic links are followed by the OS (as for any reader); that can only change which key is read, never
/// write anything.
/// </summary>
internal sealed class WindowsRegistryView : IRegistryView
{
    private readonly RegistryKey _machine;
    private readonly RegistryKey _users;

    public WindowsRegistryView()
        : this(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64),
            RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
    {
    }

    /// <summary>Test seam: other roots for HKLM and HKU (e.g. subkeys of a throwaway HKCU key).</summary>
    internal WindowsRegistryView(RegistryKey machine, RegistryKey users)
    {
        _machine = machine;
        _users = users;
    }

    public IRegistryKeyReader? Open(RegistryRoot root, string path)
    {
        var baseKey = root == RegistryRoot.LocalMachine ? _machine : _users;
        var key = path.Length == 0 ? baseKey.OpenSubKey(string.Empty, writable: false) : baseKey.OpenSubKey(path, writable: false);
        return key is null ? null : new Reader(key);
    }

    private sealed class Reader(RegistryKey key) : IRegistryKeyReader
    {
        public IReadOnlyList<string> SubKeyNames() => key.GetSubKeyNames();

        public IReadOnlyList<string> ValueNames() => key.GetValueNames();

        public RegistryData? Value(string name)
        {
            var data = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return data is null ? null : new RegistryData(key.GetValueKind(name), data);
        }

        public IRegistryKeyReader? OpenSubKey(string name) =>
            key.OpenSubKey(name, writable: false) is { } sub ? new Reader(sub) : null;

        public void Dispose() => key.Dispose();
    }
}
