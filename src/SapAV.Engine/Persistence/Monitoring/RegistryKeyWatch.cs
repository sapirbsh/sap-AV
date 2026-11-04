using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>D4: starts registry change watches; fake it in tests (most tests signal changes by hand).</summary>
internal interface IRegistryWatchFactory
{
    /// <summary>
    /// Watches <paramref name="path"/> below <paramref name="root"/>; <paramref name="changed"/> runs on a thread-pool thread
    /// after each change (it must be quick and must not throw). Never throws for a missing key: it is watched through its
    /// nearest existing ancestor until it appears.
    /// </summary>
    IDisposable Watch(RegistryRoot root, string path, bool subtree, Action changed);
}

/// <summary>The real watches (<see cref="RegistryKeyWatch"/>) on HKLM and HKU, or on test roots below HKCU.</summary>
internal sealed class WindowsRegistryWatchFactory : IRegistryWatchFactory
{
    private readonly RegistryKey _machine;
    private readonly RegistryKey _users;

    public WindowsRegistryWatchFactory()
        : this(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
    {
    }

    /// <summary>Test seam: other roots for HKLM and HKU (the same keys a test's <see cref="WindowsRegistryView"/> reads).</summary>
    internal WindowsRegistryWatchFactory(RegistryKey machine, RegistryKey users)
    {
        _machine = machine;
        _users = users;
    }

    public IDisposable Watch(RegistryRoot root, string path, bool subtree, Action changed) =>
        new RegistryKeyWatch(root == RegistryRoot.LocalMachine ? _machine.Handle : _users.Handle, path, subtree, changed,
            minDepth: path.Length == 0 ? 0 : 1);
}

/// <summary>
/// D4: one registry key watched with <c>RegNotifyChangeKeyValue</c> (asynchronous, an event per watch, re-armed after each
/// notification; <c>REG_NOTIFY_THREAD_AGNOSTIC</c>, so the registration doesn't end with the thread that made it). The wait
/// is a thread-pool registered wait, so many watches cost no thread each.
/// </summary>
/// <remarks>
/// <para><b>Least access, no links.</b> The key is opened with <c>KEY_NOTIFY</c> only, never for reading, and with
/// <c>REG_OPTION_OPEN_LINK</c>: a registry symbolic link at the watched key is watched as itself, never followed (the
/// collector, which reads it, still follows it as any reader does; such an entry is seen at the next safety rescan).</para>
/// <para><b>A key that doesn't exist</b> (e.g. a user's <c>Policies\Explorer\Run</c>) is watched through its nearest existing
/// ancestor, for subkey names only and not its subtree (no noise from the rest of the tree), never above
/// <paramref name="minDepth"/> components (the SID for a user hive). Its notification re-arms on the full path, so the key is
/// watched as soon as it exists; a key that is deleted falls back the same way. A hive that is unloaded leaves nothing to
/// watch until the next plan.</para>
/// <para><b>Lifetime.</b> <see cref="Dispose"/> unregisters the wait (waiting for a running callback), then closes the key and
/// the event; a notification after that does nothing.</para>
/// </remarks>
internal sealed class RegistryKeyWatch : IDisposable
{
    private const uint KeyNotify = 0x0010;
    private const uint KeyWow64_64Key = 0x0100;
    private const uint OpenLink = 0x0008; // REG_OPTION_OPEN_LINK
    private const uint ChangeName = 0x1;
    private const uint ChangeLastSet = 0x4;
    private const uint ThreadAgnostic = 0x10000000;
    private const int MaxDepth = 32;

    private readonly SafeRegistryHandle _base;
    private readonly string[] _components;
    private readonly bool _subtree;
    private readonly Action _changed;
    private readonly int _minDepth;
    private readonly AutoResetEvent _signal = new(false);
    private readonly Lock _lock = new();
    private SafeRegistryHandle? _key;
    private int _depth;
    private RegisteredWaitHandle? _wait;
    private bool _disposed;

    public RegistryKeyWatch(SafeRegistryHandle baseKey, string path, bool subtree, Action changed, int minDepth)
    {
        _base = baseKey ?? throw new ArgumentNullException(nameof(baseKey));
        _changed = changed ?? throw new ArgumentNullException(nameof(changed));
        _components = path.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (_components.Length > MaxDepth)
        {
            throw new ArgumentException("The key path is too deep.", nameof(path));
        }

        _subtree = subtree;
        _minDepth = Math.Min(minDepth, _components.Length);
        lock (_lock)
        {
            Arm();
        }
    }

    /// <summary>The key is watched itself (not an ancestor standing in for it).</summary>
    public bool WatchingKey
    {
        get
        {
            lock (_lock)
            {
                return _key is not null && _depth == _components.Length;
            }
        }
    }

    /// <summary>Anything is watched (false: not even the minimum ancestor exists, e.g. the hive was unloaded).</summary>
    public bool Active
    {
        get
        {
            lock (_lock)
            {
                return _key is not null;
            }
        }
    }

    private void OnSignaled(object? state, bool timedOut)
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _wait?.Unregister(null);
            _wait = null;
            if (_depth < _components.Length)
            {
                CloseKey(); // an ancestor fired: try the full path again
            }

            Arm();
        }

        try
        {
            _changed();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            System.Diagnostics.Debug.WriteLine($"Registry watch callback failed: {ex}"); // the watch goes on
        }
    }

    /// <summary>Opens the deepest existing key (from the full path down to the minimum depth) and asks for its next change.</summary>
    private void Arm()
    {
        int failures = 0;
        for (int round = 0; round <= MaxDepth + 1 && !_disposed; round++)
        {
            if (_key is null && !OpenDeepest())
            {
                return;
            }

            bool atKey = _depth == _components.Length;
            uint filter = (atKey ? ChangeName | ChangeLastSet : ChangeName) | ThreadAgnostic;
            int error = RegNotifyChangeKeyValue(_key!, atKey && _subtree, filter, _signal.SafeWaitHandle, true);
            if (error != 0)
            {
                CloseKey(); // deleted (ERROR_KEY_DELETED) or unusable: open again from the path, once
                if (++failures > 1)
                {
                    return;
                }

                continue;
            }

            // An ancestor: a child created after the deepest-key open but before the notification was armed raised nothing, so
            // look once more now that it is armed; if the next component exists, go deeper (a whole chain created at once).
            if (!atKey && Exists(_depth + 1))
            {
                CloseKey();
                _signal.Reset(); // closing the armed key may have signalled it
                continue;
            }

            _wait = ThreadPool.UnsafeRegisterWaitForSingleObject(_signal, OnSignaled, null, Timeout.Infinite, executeOnlyOnce: true);
            return;
        }
    }

    private bool Exists(int depth)
    {
        if (RegOpenKeyExW(_base, string.Join('\\', _components, 0, depth), OpenLink, KeyNotify | KeyWow64_64Key, out var key) == 0 && !key.IsInvalid)
        {
            key.Dispose();
            return true;
        }

        key?.Dispose();
        return false;
    }

    private bool OpenDeepest()
    {
        for (int depth = _components.Length; depth >= _minDepth; depth--)
        {
            string sub = string.Join('\\', _components, 0, depth);
            if (RegOpenKeyExW(_base, sub, OpenLink, KeyNotify | KeyWow64_64Key, out var key) == 0 && !key.IsInvalid)
            {
                _key = key;
                _depth = depth;
                return true;
            }

            key?.Dispose();
        }

        return false;
    }

    private void CloseKey()
    {
        _key?.Dispose();
        _key = null;
    }

    public void Dispose()
    {
        RegisteredWaitHandle? wait;
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            wait = _wait;
            _wait = null;
        }

        if (wait is not null)
        {
            using var done = new ManualResetEvent(false);
            if (wait.Unregister(done))
            {
                done.WaitOne(TimeSpan.FromSeconds(5)); // a callback already running finishes first (it sees _disposed)
            }
        }

        lock (_lock)
        {
            CloseKey();
        }

        _signal.Dispose();
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegOpenKeyExW(SafeRegistryHandle key, string subKey, uint options, uint desired, out SafeRegistryHandle result);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int RegNotifyChangeKeyValue(
        SafeRegistryHandle key, [MarshalAs(UnmanagedType.Bool)] bool watchSubtree, uint filter, SafeWaitHandle @event, [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
}
