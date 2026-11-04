using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Cache;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Persistence.Monitoring;

/// <summary>
/// D4 review H2: the change stamp of autostart target files for one pass. Attributes only, through <see cref="SafeTree"/>:
/// component by component, no junction / symlink / mount point followed, never a UNC path or network drive, no cloud recall,
/// no content read. Each folder is opened once per pass (at most <see cref="MaxFolders"/>). Not thread-safe.
/// </summary>
internal sealed class TargetStampReader : IDisposable
{
    public const int MaxFolders = 256;

    private const uint FolderAccess = N.FileTraverse | N.FileReadAttributes;

    private readonly Dictionary<string, SafeFileHandle?> _folders = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>"id:size:write:change:usn", "missing" (not found), or "unknown" (a link on the way, denied, remote, no file ID...).</summary>
    public string Stamp(string path)
    {
        int separator = path.LastIndexOf('\\');
        if (separator <= 2 || separator == path.Length - 1)
        {
            return "unknown";
        }

        string parent = path[..separator];
        var folder = Folder(parent.EndsWith(':') ? parent + @"\" : parent, out bool missing);
        if (folder is null)
        {
            return missing ? "missing" : "unknown";
        }

        using var file = SafeTree.OpenChild(folder, path[(separator + 1)..], N.FileReadAttributes, SafeTree.ShareAll,
            N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out var failure, out _);
        if (file is null)
        {
            return failure == SafeTreeFailure.NotFound ? "missing" : "unknown";
        }

        try
        {
            return FileStamp.CaptureForChangeDetection(file) is { } s
                ? $"{s.Volume:x}:{s.FileId:x}:{s.Size}:{s.LastWriteTime}:{s.ChangeTime}:{s.Usn?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-"}"
                : "unknown";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return "unknown";
        }
    }

    private SafeFileHandle? Folder(string path, out bool missing)
    {
        missing = false;
        if (_folders.TryGetValue(path, out var known))
        {
            missing = known is null && _missing.Contains(path);
            return known;
        }

        if (_folders.Count >= MaxFolders)
        {
            Dispose();
        }

        var handle = SafeTree.Open(path, FolderAccess, SafeTree.ShareAll, N.FileDirectoryFile, out var failure, out _);
        if (handle is null && failure == SafeTreeFailure.NotFound)
        {
            _missing.Add(path);
            missing = true;
        }

        return _folders[path] = handle;
    }

    private readonly HashSet<string> _missing = new(StringComparer.OrdinalIgnoreCase);

    public void Dispose()
    {
        foreach (var handle in _folders.Values)
        {
            handle?.Dispose();
        }

        _folders.Clear();
        _missing.Clear();
    }
}
