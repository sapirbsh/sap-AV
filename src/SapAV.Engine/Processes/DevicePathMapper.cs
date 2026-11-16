namespace SapAV.Engine.Processes;

/// <summary>
/// Turns an NT device path from an ETW event (<c>\Device\HarddiskVolume3\Windows\System32\cmd.exe</c>) into a Win32 path
/// (<c>C:\Windows\System32\cmd.exe</c>) using the drive-letter targets from <c>QueryDosDeviceW</c>. The table is cached and
/// re-read at most every <see cref="RefreshInterval"/> when a path doesn't match (a USB drive was plugged in). Thread-safe.
/// </summary>
public sealed class DevicePathMapper
{
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    private readonly Func<IReadOnlyList<(string Drive, string Device)>> _readTable;
    private readonly Func<long> _ticks;
    private volatile IReadOnlyList<(string Drive, string Device)> _table = [];
    private long _readAt = long.MinValue;

    public DevicePathMapper()
        : this(ReadDosDevices, () => Environment.TickCount64)
    {
    }

    internal DevicePathMapper(Func<IReadOnlyList<(string Drive, string Device)>> readTable, Func<long> ticks)
    {
        _readTable = readTable ?? throw new ArgumentNullException(nameof(readTable));
        _ticks = ticks ?? throw new ArgumentNullException(nameof(ticks));
    }

    /// <summary>The Win32 form of <paramref name="path"/>; a path that isn't a device path is returned unchanged, an unknown device as null.</summary>
    public string? ToWin32(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        if (TryMap(_table, path) is { } mapped)
        {
            return mapped;
        }

        long now = _ticks();
        long last = Interlocked.Read(ref _readAt);
        if (last != long.MinValue && now - last < (long)RefreshInterval.TotalMilliseconds)
        {
            return null;
        }

        Interlocked.Exchange(ref _readAt, now);
        try
        {
            _table = _readTable();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }

        return TryMap(_table, path);
    }

    private static string? TryMap(IReadOnlyList<(string Drive, string Device)> table, string path)
    {
        foreach (var (drive, device) in table)
        {
            if (path.Length > device.Length && path[device.Length] == '\\'
                && path.StartsWith(device, StringComparison.OrdinalIgnoreCase))
            {
                return drive + path[device.Length..];
            }
        }

        return null;
    }

    private static IReadOnlyList<(string Drive, string Device)> ReadDosDevices()
    {
        var table = new List<(string, string)>();
        var buffer = new char[1024];
        for (char letter = 'A'; letter <= 'Z'; letter++)
        {
            string drive = letter + ":";
            uint length = ProcessNative.QueryDosDeviceW(drive, buffer, (uint)buffer.Length);
            if (length == 0)
            {
                continue;
            }

            // The result is a NUL-separated list; the first entry is the current target.
            int end = Array.IndexOf(buffer, '\0', 0, (int)Math.Min(length, (uint)buffer.Length));
            string device = new(buffer, 0, end < 0 ? (int)length : end);
            if (device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                table.Add((drive, device));
            }
        }

        return table;
    }
}
