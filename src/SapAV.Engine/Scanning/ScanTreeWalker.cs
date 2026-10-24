using SapAV.Core.Hashing;
using SapAV.Engine.Scanning.Native;

namespace SapAV.Engine.Scanning;

/// <summary>What the walker found.</summary>
internal enum ScanTreeEntryKind
{
    /// <summary>A file to scan (a root that doesn't exist is also emitted as a file, so it is reported NotScanned, not lost).</summary>
    File,

    /// <summary>A file or folder inside an excluded folder (not descended into).</summary>
    Excluded,

    /// <summary>A junction, symlink, mount point or other name surrogate (not followed).</summary>
    SkippedLink,

    /// <summary>A folder that couldn't be listed (access denied, gone, ...).</summary>
    Unreadable,
}

/// <param name="Length">The file size from the directory listing (0 if unknown); for the progress total only.</param>
/// <param name="Detail">Why, for Unreadable entries.</param>
internal readonly record struct ScanTreeEntry(string Path, ScanTreeEntryKind Kind, long Length = 0, string? Detail = null);

/// <summary>
/// The simple recursive walk for "scan these files/folders" (B3; C1 adds ScanPathPolicy and the scan modes). Iterative,
/// depth first. Name-surrogate reparse points (junctions, symlinks, mount points) are never followed, so a link can't
/// pull a scan out of the requested tree or into a loop; other reparse points (OneDrive / cloud files, dedup) are
/// regular content and are walked and scanned (the opener skips offline placeholders without recalling them). A
/// reparse point whose tag can't be read is treated as a link. Runs on the job's enumerator thread; nothing here reads
/// file content.
/// </summary>
internal sealed class ScanTreeWalker(FolderSet excluded, Func<string, uint?>? reparseTag = null)
{
    private static readonly EnumerationOptions ListOptions = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
    };

    private readonly Func<string, uint?> _reparseTag = reparseTag ?? ScanNative.TryGetReparseTag;

    /// <summary>Walks every root in order, calling <paramref name="emit"/> for each entry (it may block for back-pressure or pause).</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public void Walk(IEnumerable<string> roots, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access = null)
    {
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WalkRoot(root, emit, cancellationToken, access);
        }
    }

    private void WalkRoot(string requested, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access)
    {
        // B3 review H1: walk in the exact \\?\ form. A plain path would drop trailing dots/spaces, so a folder "x." could
        // not be listed (its files never scanned) and "evil.exe." would be read as "evil.exe".
        if (ExactPath.ToExtended(requested) is not { } root)
        {
            emit(new(requested, ScanTreeEntryKind.File)); // not a usable path: the opener reports why
            return;
        }

        string shown = ExactPath.ForOpening(root);
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            emit(new(shown, ScanTreeEntryKind.File)); // missing or unreadable: the opener reports why
            return;
        }

        if (excluded.Contains(root))
        {
            emit(new(shown, ScanTreeEntryKind.Excluded));
            return;
        }

        if (!attributes.HasFlag(FileAttributes.Directory))
        {
            emit(IsLink(root, attributes) ? new(shown, ScanTreeEntryKind.SkippedLink) : new(shown, ScanTreeEntryKind.File, SafeLength(root)));
            return;
        }

        if (IsLink(root, attributes))
        {
            emit(new(shown, ScanTreeEntryKind.SkippedLink));
            return;
        }

        WalkTree(root, emit, cancellationToken, access);
    }

    private void WalkTree(string root, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var directory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (access is not null && !access.CanList(directory))
            {
                // B4: the requester can't list this folder, so the job doesn't either (and never descends below it).
                emit(new(ExactPath.ForOpening(directory), ScanTreeEntryKind.Unreadable, Detail: "AccessDenied (requester)"));
                continue;
            }

            var subdirectories = new List<string>();
            try
            {
                foreach (var entry in new DirectoryInfo(directory).EnumerateFileSystemInfos("*", ListOptions))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Classify(entry, subdirectories, emit);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                emit(new(ExactPath.ForOpening(directory), ScanTreeEntryKind.Unreadable, Detail: ex.GetType().Name));
            }

            // Push in reverse so subfolders are visited in listing order.
            for (int i = subdirectories.Count - 1; i >= 0; i--)
            {
                pending.Push(subdirectories[i]);
            }
        }
    }

    private void Classify(FileSystemInfo entry, List<string> subdirectories, Action<ScanTreeEntry> emit)
    {
        string path = entry.FullName; // extended form (inherited from the root): exact names
        string shown = ExactPath.ForOpening(path);
        var attributes = entry.Attributes;
        if (IsLink(path, attributes))
        {
            emit(new(shown, ScanTreeEntryKind.SkippedLink));
        }
        else if (excluded.Contains(path))
        {
            emit(new(shown, ScanTreeEntryKind.Excluded));
        }
        else if (attributes.HasFlag(FileAttributes.Directory))
        {
            subdirectories.Add(path);
        }
        else
        {
            emit(new(shown, ScanTreeEntryKind.File, entry is FileInfo file ? file.Length : 0));
        }
    }

    internal bool IsLink(string path, FileAttributes attributes) =>
        attributes.HasFlag(FileAttributes.ReparsePoint) && (_reparseTag(path) is not { } tag || ScanNative.IsNameSurrogate(tag));

    private static long SafeLength(string path)
    {
        try
        {
            return new FileInfo(path).Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }
}
