using System.Runtime.InteropServices;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>A drive letter as Windows reports it (C6).</summary>
/// <param name="Root">The drive root, e.g. <c>C:\</c>.</param>
/// <param name="DriveType">GetDriveTypeW: 2 removable, 3 fixed, 4 remote, 5 CD-ROM, 6 RAM disk, 0/1 unknown / no root.</param>
/// <param name="VolumeName">The volume GUID path (<c>\\?\Volume{...}\</c>), or null when the letter isn't a volume mount point (SUBST).</param>
/// <param name="UsedBytes">Total minus free bytes, or null if unknown.</param>
internal sealed record DriveInfoEntry(string Root, int DriveType, string? VolumeName, long? UsedBytes);

/// <summary>Lists the drive letters (fake it in tests).</summary>
internal interface IVolumeSource
{
    IReadOnlyList<DriveInfoEntry> List();
}

/// <summary>
/// The real drive list: <c>GetLogicalDrives</c>, then per letter <c>GetDriveTypeW</c>, and for fixed drives
/// <c>GetVolumeNameForVolumeMountPointW</c> and <c>GetDiskFreeSpaceExW</c>. Only metadata calls on local roots; nothing
/// is opened on removable, network or optical drives.
/// </summary>
internal sealed class WindowsVolumeSource : IVolumeSource
{
    public IReadOnlyList<DriveInfoEntry> List()
    {
        var drives = new List<DriveInfoEntry>();
        uint mask = GetLogicalDrives();
        for (int i = 0; i < 26; i++)
        {
            if ((mask & (1u << i)) == 0)
            {
                continue;
            }

            string root = $"{(char)('A' + i)}:\\";
            int type = Pipe.Native.PipeNative.DriveType(root);
            drives.Add(type == FullScanVolumes.DriveFixed ? new DriveInfoEntry(root, type, VolumeName(root), Used(root)) : new DriveInfoEntry(root, type, null, null));
        }

        return drives;
    }

    private static string? VolumeName(string root)
    {
        var buffer = new char[64];
        return GetVolumeNameForVolumeMountPointW(root, buffer, (uint)buffer.Length) ? new string(buffer).TrimEnd('\0') : null;
    }

    private static long? Used(string root) =>
        GetDiskFreeSpaceExW(root, out _, out ulong total, out ulong free) && total >= free ? (long)Math.Min(total - free, long.MaxValue) : null;

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetLogicalDrives();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string mountPoint, [Out] char[] volumeName, uint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceExW(string directory, out ulong freeForCaller, out ulong total, out ulong totalFree);
}

/// <summary>
/// Which drives a Full Scan walks (C6): <b>local fixed volumes only</b> (DRIVE_FIXED: not removable, network, optical or
/// RAM disks), each volume once.
/// <list type="bullet">
/// <item>A letter that isn't a volume mount point (a SUBST alias of a folder, which reports its target's drive type) is
/// skipped: its files are walked through the real volume.</item>
/// <item>A volume mounted under two letters is walked once (by its volume GUID).</item>
/// <item><b>VHD / VHDX-mounted drives are included</b>: they are local fixed volumes, and leaving them out would give
/// malware an easy place to hide (mount a disk image, drop the payload there). Their cost is bounded like any drive's
/// (the depth and entry caps).</item>
/// <item>USB hard disks that report themselves fixed are included too (Windows can't tell them apart here).</item>
/// </list>
/// </summary>
internal static class FullScanVolumes
{
    public const int DriveFixed = 3;

    /// <summary>The drives to walk, in letter order, plus notes about the ones left out.</summary>
    public static IReadOnlyList<DriveInfoEntry> Select(IReadOnlyList<DriveInfoEntry> drives, List<string> notes)
    {
        ArgumentNullException.ThrowIfNull(drives);
        var chosen = new List<DriveInfoEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int other = 0;
        foreach (var drive in drives.OrderBy(d => d.Root, StringComparer.OrdinalIgnoreCase))
        {
            if (drive.DriveType != DriveFixed)
            {
                other++;
            }
            else if (drive.VolumeName is null)
            {
                notes.Add($"{drive.Root} is not a volume (a SUBST alias?); its files are scanned through their real drive.");
            }
            else if (!seen.Add(drive.VolumeName))
            {
                notes.Add($"{drive.Root} is another letter of a volume already scanned; not scanned twice.");
            }
            else
            {
                chosen.Add(drive);
            }
        }

        if (other > 0)
        {
            notes.Add($"{other} removable, network, optical or other drive(s) are not part of a Full Scan.");
        }

        return chosen;
    }
}
