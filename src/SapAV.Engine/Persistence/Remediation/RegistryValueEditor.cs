using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Persistence.Remediation;

/// <summary>A registry value exactly as stored: its type (REG_SZ = 1, REG_EXPAND_SZ = 2, ...) and raw bytes.</summary>
internal sealed record RawRegistryValue(int Type, byte[] Data)
{
    public const int RegSz = 1;

    /// <summary>Most bytes of one backed-up value (Run values are short; anything bigger isn't an autostart command).</summary>
    public const int MaxBytes = 64 * 1024;

    public bool SameAs(RawRegistryValue? other) => other is not null && other.Type == Type && Data.AsSpan().SequenceEqual(other.Data);

    /// <summary>A REG_SZ holding <paramref name="text"/> (UTF-16LE with its terminating NUL).</summary>
    public static RawRegistryValue String(string text) => new(RegSz, [.. System.Text.Encoding.Unicode.GetBytes(text), 0, 0]);

    /// <summary>
    /// The ways a reader may have read this value as text: up to the first NUL, and (REG_SZ / REG_EXPAND_SZ) the whole data
    /// without one terminating NUL, as <see cref="Microsoft.Win32.RegistryKey.GetValue(string)"/> does. Empty for other types.
    /// </summary>
    public IReadOnlyList<string> Texts()
    {
        if (Type is not (1 or 2 or 7))
        {
            return [];
        }

        string all = new(System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(Data.AsSpan(0, Data.Length & ~1)));
        int nul = all.IndexOf('\0');
        string first = nul < 0 ? all : all[..nul];
        if (Type == 7)
        {
            return [first];
        }

        string whole = all.EndsWith('\0') ? all[..^1] : all;
        return whole == first ? [first] : [first, whole];
    }
}

internal enum RegistryEditStatus
{
    Ok,

    /// <summary>The key (or a key on its path, or the hive) doesn't exist.</summary>
    KeyMissing,

    ValueMissing,

    /// <summary>A key on the path is a registry symbolic link: refused, never followed.</summary>
    Redirected,

    AccessDenied,

    /// <summary>The value isn't what the caller expected (it changed since it was read): nothing was written or deleted.</summary>
    Changed,

    /// <summary>The value is over <see cref="RawRegistryValue.MaxBytes"/>.</summary>
    TooLarge,

    Failed,
}

/// <summary>
/// D5: registry writes for Block &amp; remove, as SYSTEM, on HKLM and HKU (or test roots). Every key is opened component by
/// component with <c>REG_OPTION_OPEN_LINK</c>, and a component that is a registry symbolic link is refused, so a user-made link
/// in their own hive can't redirect a SYSTEM write into another key. Values are read and written raw (type + bytes, nothing
/// expanded). The compare-and-change methods check the current value under the same open key right before changing it.
/// Fake it in tests that aren't about the registry itself.
/// </summary>
internal interface IRegistryValueEditor
{
    RegistryEditStatus ValueNames(RegistryRoot root, string path, out IReadOnlyList<string> names);

    RegistryEditStatus Read(RegistryRoot root, string path, string name, out RawRegistryValue? value);

    /// <summary>Deletes the value only if it still equals <paramref name="expected"/>.</summary>
    RegistryEditStatus DeleteIf(RegistryRoot root, string path, string name, RawRegistryValue expected);

    /// <summary>Writes <paramref name="value"/> only if the value now equals <paramref name="expected"/> (null: only if it doesn't exist).</summary>
    RegistryEditStatus WriteIf(RegistryRoot root, string path, string name, RawRegistryValue? expected, RawRegistryValue value);

    /// <summary>The key's security descriptor (owner, group, DACL; self-relative), for an AccessCheck with a client's token.</summary>
    RegistryEditStatus Security(RegistryRoot root, string path, out byte[]? descriptor);
}

/// <summary>The real editor (see <see cref="IRegistryValueEditor"/>). The key itself is never created: a missing key is reported.</summary>
internal sealed class NoFollowRegistryEditor : IRegistryValueEditor
{
    private const uint RegOptionOpenLink = 0x8;
    private const uint KeyQueryValue = 0x0001;
    private const uint KeySetValue = 0x0002;
    private const uint KeyEnumerateSubKeys = 0x0008;
    private const uint KeyWow64_64Key = 0x0100;
    private const int RegLink = 6;
    private const int ErrorSuccess = 0;
    private const int ErrorFileNotFound = 2;
    private const int ErrorAccessDenied = 5;
    private const int ErrorMoreData = 234;
    private const int ErrorNoMoreItems = 259;
    private const int ErrorKeyDeleted = 1018;
    private const int ErrorInsufficientBuffer = 122;
    private const uint ReadControl = 0x00020000;
    private const uint SecurityInformation = 0x1 | 0x2 | 0x4; // owner, group, DACL

    private readonly RegistryKey _machine;
    private readonly RegistryKey _users;

    public NoFollowRegistryEditor()
        : this(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
    {
    }

    /// <summary>Test seam: other roots for HKLM and HKU (the same keys a test's <see cref="WindowsRegistryView"/> reads).</summary>
    internal NoFollowRegistryEditor(RegistryKey machine, RegistryKey users)
    {
        _machine = machine;
        _users = users;
    }

    public RegistryEditStatus ValueNames(RegistryRoot root, string path, out IReadOnlyList<string> names)
    {
        names = [];
        var status = OpenKey(root, path, KeyQueryValue, out var key);
        using (key)
        {
            if (status != RegistryEditStatus.Ok)
            {
                return status;
            }

            var list = new List<string>();
            var buffer = new char[16384];
            for (uint index = 0; list.Count < 65536; index++)
            {
                uint length = (uint)buffer.Length;
                int error = RegEnumValueW(key!, index, buffer, ref length, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (error == ErrorNoMoreItems)
                {
                    break;
                }

                if (error != ErrorSuccess)
                {
                    return Map(error);
                }

                list.Add(new string(buffer, 0, (int)length));
            }

            names = list;
            return RegistryEditStatus.Ok;
        }
    }

    public RegistryEditStatus Read(RegistryRoot root, string path, string name, out RawRegistryValue? value)
    {
        value = null;
        var status = OpenKey(root, path, KeyQueryValue, out var key);
        using (key)
        {
            return status != RegistryEditStatus.Ok ? status : Query(key!, name, out value);
        }
    }

    public RegistryEditStatus DeleteIf(RegistryRoot root, string path, string name, RawRegistryValue expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        var status = OpenKey(root, path, KeyQueryValue | KeySetValue, out var key);
        using (key)
        {
            if (status != RegistryEditStatus.Ok)
            {
                return status;
            }

            status = Query(key!, name, out var current);
            if (status != RegistryEditStatus.Ok)
            {
                return status == RegistryEditStatus.ValueMissing ? RegistryEditStatus.Changed : status;
            }

            return !expected.SameAs(current) ? RegistryEditStatus.Changed : Map(RegDeleteValueW(key!, name));
        }
    }

    public RegistryEditStatus WriteIf(RegistryRoot root, string path, string name, RawRegistryValue? expected, RawRegistryValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Data.Length > RawRegistryValue.MaxBytes)
        {
            return RegistryEditStatus.TooLarge;
        }

        var status = OpenKey(root, path, KeyQueryValue | KeySetValue, out var key);
        using (key)
        {
            if (status != RegistryEditStatus.Ok)
            {
                return status;
            }

            status = Query(key!, name, out var current);
            bool matches = expected is null ? status == RegistryEditStatus.ValueMissing : status == RegistryEditStatus.Ok && expected.SameAs(current);
            if (!matches)
            {
                return status is RegistryEditStatus.Ok or RegistryEditStatus.ValueMissing or RegistryEditStatus.TooLarge ? RegistryEditStatus.Changed : status;
            }

            return Map(RegSetValueExW(key!, name, 0, (uint)value.Type, value.Data, (uint)value.Data.Length));
        }
    }

    public RegistryEditStatus Security(RegistryRoot root, string path, out byte[]? descriptor)
    {
        descriptor = null;
        var status = OpenKey(root, path, ReadControl, out var key);
        using (key)
        {
            if (status != RegistryEditStatus.Ok)
            {
                return status;
            }

            uint size = 0;
            int error = RegGetKeySecurity(key!, SecurityInformation, null, ref size);
            if (error != ErrorInsufficientBuffer || size is 0 or > 64 * 1024)
            {
                return Map(error);
            }

            var buffer = new byte[size];
            error = RegGetKeySecurity(key!, SecurityInformation, buffer, ref size);
            if (error != ErrorSuccess)
            {
                return Map(error);
            }

            descriptor = buffer[..(int)size];
            return RegistryEditStatus.Ok;
        }
    }

    /// <summary>Opens each component with REG_OPTION_OPEN_LINK; a component that is a link (a REG_LINK SymbolicLinkValue) is refused.</summary>
    private RegistryEditStatus OpenKey(RegistryRoot root, string path, uint access, out SafeRegistryHandle? key)
    {
        key = null;
        var parts = path.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(p => p.Length > 255))
        {
            return RegistryEditStatus.KeyMissing;
        }

        var baseKey = root == RegistryRoot.LocalMachine ? _machine : _users;
        SafeRegistryHandle? current = null;
        for (int i = 0; i < parts.Length; i++)
        {
            bool last = i == parts.Length - 1;
            uint desired = (last ? access : KeyEnumerateSubKeys) | KeyQueryValue | KeyWow64_64Key;
            int error = RegOpenKeyExW(current ?? baseKey.Handle, parts[i], RegOptionOpenLink, desired, out var next);
            current?.Dispose();
            if (error != ErrorSuccess)
            {
                next.Dispose();
                return Map(error) == RegistryEditStatus.ValueMissing ? RegistryEditStatus.KeyMissing : Map(error);
            }

            current = next;
            if (IsLink(current))
            {
                current.Dispose();
                return RegistryEditStatus.Redirected;
            }
        }

        key = current;
        return RegistryEditStatus.Ok;
    }

    private static bool IsLink(SafeRegistryHandle key)
    {
        uint size = 0;
        int error = RegQueryValueExW(key, "SymbolicLinkValue", IntPtr.Zero, out uint type, null, ref size);
        return (error is ErrorSuccess or ErrorMoreData) && type == RegLink;
    }

    private static RegistryEditStatus Query(SafeRegistryHandle key, string name, out RawRegistryValue? value)
    {
        value = null;
        uint size = 0;
        int error = RegQueryValueExW(key, name, IntPtr.Zero, out uint type, null, ref size);
        if (error != ErrorSuccess && error != ErrorMoreData)
        {
            return Map(error);
        }

        if (size > RawRegistryValue.MaxBytes)
        {
            return RegistryEditStatus.TooLarge;
        }

        var data = new byte[size];
        error = RegQueryValueExW(key, name, IntPtr.Zero, out type, data, ref size);
        if (error != ErrorSuccess)
        {
            return error == ErrorMoreData ? RegistryEditStatus.Changed : Map(error); // it grew between the two calls
        }

        value = new RawRegistryValue((int)type, data[..(int)size]);
        return RegistryEditStatus.Ok;
    }

    private static RegistryEditStatus Map(int error) => error switch
    {
        ErrorSuccess => RegistryEditStatus.Ok,
        ErrorFileNotFound => RegistryEditStatus.ValueMissing,
        ErrorKeyDeleted => RegistryEditStatus.KeyMissing,
        ErrorAccessDenied => RegistryEditStatus.AccessDenied,
        _ => RegistryEditStatus.Failed,
    };

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegOpenKeyExW(SafeRegistryHandle key, string subKey, uint options, uint desired, out SafeRegistryHandle result);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegQueryValueExW(SafeRegistryHandle key, string name, IntPtr reserved, out uint type, byte[]? data, ref uint size);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegSetValueExW(SafeRegistryHandle key, string name, uint reserved, uint type, byte[] data, uint size);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegDeleteValueW(SafeRegistryHandle key, string name);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int RegGetKeySecurity(SafeRegistryHandle key, uint information, byte[]? descriptor, ref uint size);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegEnumValueW(
        SafeRegistryHandle key, uint index, [Out] char[] name, ref uint nameLength, IntPtr reserved, IntPtr type, IntPtr data, IntPtr dataLength);
}
