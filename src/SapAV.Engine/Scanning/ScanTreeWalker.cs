using Microsoft.Win32.SafeHandles;
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
/// <param name="Folder">
/// For a File found in a listing: the listed folder (one reference owned by this entry; the consumer releases it) and
/// <paramref name="Name"/>, so the file is opened relative to that folder handle (review B H2). Null for a root given as a file.
/// </param>
/// <param name="Name">The file name inside <paramref name="Folder"/>.</param>
internal readonly record struct ScanTreeEntry(
    string Path, ScanTreeEntryKind Kind, long Length = 0, string? Detail = null, SharedFolder? Folder = null, string? Name = null);

/// <summary>
/// The recursive walk for "scan these files/folders" (B3), depth first, <b>bound to handles</b> (review B4 H3 / M2,
/// ROADMAP B3 M1). Each root is opened component by component with <see cref="SafeTree"/> (no reparse point followed
/// anywhere on the way, a name surrogate refused); each folder is opened once, relative to its parent's handle, checked
/// (the requester's access, <see cref="IScanAccessCheck.CanList"/>, on that handle's descriptor) and listed from that
/// same handle. A folder swapped for a junction after its parent was listed is opened as the junction itself and refused,
/// so the walk can't leave the requested tree or list a folder the check didn't cover. Name surrogates (junctions,
/// symlinks, mount points) are never followed; other reparse points (OneDrive / cloud files, dedup) are regular content
/// (the opener skips offline placeholders without recalling them). Depth is capped at <see cref="MaxDepth"/>. Each file is
/// emitted with a reference to the listed folder's handle (<see cref="SharedFolder"/>), so the scan opens it relative to
/// that handle (review B H2) and a parent renamed or replaced after the listing can't redirect the open.
/// Runs on the job's enumerator thread; nothing here reads file content.
/// </summary>
internal sealed class ScanTreeWalker(ExclusionSet excluded, Func<string, uint?>? reparseTag = null, IRemoteFileProbe? remote = null)
{
    /// <summary>Test convenience: <paramref name="excluded"/> always excluded (nothing verified).</summary>
    public ScanTreeWalker(FolderSet excluded, Func<string, uint?>? reparseTag = null)
        : this(ExclusionSet.Always(excluded), reparseTag)
    {
    }

    /// <summary>Deepest folder nesting walked (review B3 C6 M2); deeper folders are reported Unreadable.</summary>
    public const int MaxDepth = 256;

    /// <summary>Walks every root in order, calling <paramref name="emit"/> for each entry (it may block for back-pressure or pause).</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public void Walk(
        IEnumerable<string> roots, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access = null, bool allowRemote = false,
        ScanWalkFilter? filter = null)
    {
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WalkRoot(root, emit, cancellationToken, access, allowRemote, filter);
        }
    }

    private void WalkRoot(
        string requested, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access, bool allowRemote, ScanWalkFilter? filter)
    {
        // B3 review H1: walk in the exact \\?\ form, so "x." and "evil.exe." keep their names.
        if (ExactPath.ToExtended(requested) is not { } root)
        {
            emit(new(requested, ScanTreeEntryKind.File)); // not a usable path: the opener reports why
            return;
        }

        string shown = ExactPath.ForOpening(root);
        if (excluded.Contains(root))
        {
            emit(new(shown, ScanTreeEntryKind.Excluded));
            return;
        }

        var handle = SafeTree.Open(root, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out var failure, out _, allowRemote);
        if (handle is null)
        {
            // A link (on the way or the root itself) is skipped; anything else goes to the opener, which reports why.
            emit(failure == SafeTreeFailure.Redirected ? new(shown, ScanTreeEntryKind.SkippedLink) : new(shown, ScanTreeEntryKind.File));
            return;
        }

        if (!SafeTree.IsDirectory(handle))
        {
            // Review C1 L2: a restricted job learns the size (it goes into BytesTotal) only for a file the requester can read.
            long length = access is null || access.CanRead(handle) ? SafeLength(handle) : 0;
            handle.Dispose();
            emit(new(shown, ScanTreeEntryKind.File, length));
            return;
        }

        WalkTree(root, handle, emit, cancellationToken, access, allowRemote, filter);
    }

    private sealed class Frame(string path, SharedFolder folder, List<string> subdirectories) : IDisposable
    {
        public string Path { get; } = path;

        public SafeFileHandle Handle => folder.Handle;

        public List<string> Subdirectories { get; } = subdirectories;

        public int Next { get; set; }

        /// <summary>Drops the walker's reference; queued files keep the folder open until they are scanned.</summary>
        public void Dispose() => folder.Release();
    }

    /// <summary>Depth first; one handle per level is open (the chain from the root to the current folder).</summary>
    private void WalkTree(
        string root, SafeFileHandle rootHandle, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access, bool allowRemote,
        ScanWalkFilter? filter)
    {
        var stack = new Stack<Frame>();
        try
        {
            if (Visit(root, rootHandle, emit, access, allowRemote, filter) is { } first)
            {
                stack.Push(first);
            }

            while (stack.TryPeek(out var top))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (filter is { LimitReached: true })
                {
                    return; // C6: the entry cap; the frames are released below
                }

                if (top.Next == top.Subdirectories.Count)
                {
                    stack.Pop().Dispose();
                    continue;
                }

                string name = top.Subdirectories[top.Next++];
                string path = SafeTree.Child(top.Path, name);
                if (filter is not null && stack.Count > filter.MaxDepth)
                {
                    filter.FoldersTooDeep++; // C4: a deliberate depth limit, counted, not a warning per folder
                    continue;
                }

                if (stack.Count >= MaxDepth)
                {
                    emit(new(ExactPath.ForOpening(path), ScanTreeEntryKind.Unreadable, Detail: "TooDeep"));
                    continue;
                }

                var child = SafeTree.OpenChild(top.Handle, name, SafeTree.DirectoryAccess, SafeTree.ShareAll, Quarantine.Native.QuarantineNative.FileDirectoryFile,
                    out var failure, out _);
                if (child is null)
                {
                    // Redirected: it became a junction / symlink since the listing (or a reparse was refused): never followed.
                    emit(failure == SafeTreeFailure.Redirected
                        ? new(ExactPath.ForOpening(path), ScanTreeEntryKind.SkippedLink)
                        : new(ExactPath.ForOpening(path), ScanTreeEntryKind.Unreadable, Detail: failure.ToString()));
                    continue;
                }

                if (Visit(path, child, emit, access, allowRemote, filter) is { } frame)
                {
                    stack.Push(frame);
                }
            }
        }
        finally
        {
            while (stack.TryPop(out var frame))
            {
                frame.Dispose();
            }
        }
    }

    /// <summary>Checks and lists one folder from its handle; emits its files. Null (handle disposed) if it can't be listed.</summary>
    private Frame? Visit(
        string directory, SafeFileHandle handle, Action<ScanTreeEntry> emit, IScanAccessCheck? access, bool allowRemote, ScanWalkFilter? filter)
    {
        string shown = ExactPath.ForOpening(directory);
        if (access is not null && !access.CanList(handle))
        {
            // B4: the requester can't list this folder, so the job doesn't either (and never descends below it).
            handle.Dispose();
            emit(new(shown, ScanTreeEntryKind.Unreadable, Detail: "AccessDenied (requester)"));
            return null;
        }

        if (!allowRemote && (remote ?? RemoteFileProbe.Instance).Classify(handle) != FileLocation.Local)
        {
            // A2 W-A / B3 M1: a folder on a remote file system is never listed (see RemoteFileProbe for what this can't prevent).
            handle.Dispose();
            emit(new(shown, ScanTreeEntryKind.Unreadable, Detail: "RemoteFolder"));
            return null;
        }

        List<SafeTreeEntry> entries;
        try
        {
            entries = SafeTree.List(handle);
        }
        catch (IOException ex)
        {
            handle.Dispose();
            emit(new(shown, ScanTreeEntryKind.Unreadable, Detail: (ex.InnerException as System.ComponentModel.Win32Exception)?.NativeErrorCode.ToString() ?? "IOException"));
            return null;
        }

        if (filter is not null)
        {
            if (filter.LimitReached || filter.EntriesSeen + entries.Count > filter.MaxEntries)
            {
                filter.LimitReached = true; // C6 / B3 M2: nothing more is listed or emitted by this job's walks
                handle.Dispose();
                return null;
            }

            filter.EntriesSeen += entries.Count;
        }

        var subdirectories = new List<string>();
        var folder = new SharedFolder(handle);
        try
        {
            foreach (var entry in entries)
            {
                Classify(directory, folder, entry, subdirectories, emit, filter);
            }
        }
        catch
        {
            folder.Release();
            throw;
        }

        return new Frame(directory, folder, subdirectories);
    }

    private void Classify(
        string directory, SharedFolder folder, SafeTreeEntry entry, List<string> subdirectories, Action<ScanTreeEntry> emit, ScanWalkFilter? filter)
    {
        string path = SafeTree.Child(directory, entry.Name); // extended form: exact names
        string shown = ExactPath.ForOpening(path);
        if (IsLink(path, entry.Attributes, entry.ReparseTag))
        {
            emit(new(shown, ScanTreeEntryKind.SkippedLink));
        }
        else if (excluded.Contains(path))
        {
            emit(new(shown, ScanTreeEntryKind.Excluded));
        }
        else if (entry.IsDirectory)
        {
            if (filter is { SkipPlaceholderFolders: true } && entry.IsPlaceholder)
            {
                filter.FoldersOffline++; // B3 M2: never make SYSTEM ask a sync provider to populate a folder
                return;
            }

            if (filter?.SkipFolder is { } skip && skip(path))
            {
                filter.FoldersSkipped++;
                return;
            }

            subdirectories.Add(entry.Name);
        }
        else if (filter?.SkipFile is { } skipFile && skipFile(path))
        {
            filter.FilesSkipped++;
        }
        else if (filter?.IncludeFile is { } include && !include(entry))
        {
            filter.FilesFiltered++;
        }
        else
        {
            // Review B H2: the file is opened relative to this listed folder's handle, never by path again.
            var file = new ScanTreeEntry(shown, ScanTreeEntryKind.File, entry.Length, Folder: folder.AddRef(), Name: entry.Name);
            try
            {
                emit(file);
            }
            catch
            {
                file.Folder!.Release(); // not handed over (cancelled, or the consumer failed)
                throw;
            }
        }
    }

    /// <summary>A reparse point that is a name surrogate, or whose tag is unknown (test seam: <c>reparseTag</c> by path).</summary>
    internal bool IsLink(string path, FileAttributes attributes) => IsLink(path, attributes, null);

    private bool IsLink(string path, FileAttributes attributes, uint? listedTag)
    {
        if (!attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return false;
        }

        uint? tag = reparseTag is not null ? reparseTag(path) : listedTag ?? ScanNative.TryGetReparseTag(path);
        return tag is not { } t || ScanNative.IsNameSurrogate(t);
    }

    private static long SafeLength(SafeFileHandle handle)
    {
        try
        {
            return RandomAccess.GetLength(handle);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }
}

/// <summary>
/// C4: what a scan check walks (Quick Scan's folder phases, Full Scan's drives): a depth limit, which listed files are
/// emitted and which subfolders are not descended into. The walk itself is unchanged (handle-bound, no link followed,
/// exclusions applied first). The counters are for the phase summary; one filter belongs to one job's walks on one thread.
/// </summary>
internal sealed class ScanWalkFilter
{
    /// <summary>Deepest folder nesting below a root that is listed (the root is depth 0); deeper folders are counted, not walked.</summary>
    public int MaxDepth { get; init; } = ScanTreeWalker.MaxDepth;

    /// <summary>
    /// C6 / review B3 M2: most directory entries listed by the walks using this filter (all roots together). Once a listing
    /// would go past it, <see cref="LimitReached"/> is set and the walks stop: an endless or gigantic tree (a hostile
    /// cloud provider, a crafted volume) can't keep a job going forever.
    /// </summary>
    public long MaxEntries { get; init; } = long.MaxValue;

    /// <summary>
    /// C6 / review B3 M2: don't descend into cloud-files placeholder folders whose content isn't local (RECALL_ON_OPEN /
    /// RECALL_ON_DATA_ACCESS / Offline): listing one as SYSTEM would ask the user's sync provider to populate it. Counted
    /// in <see cref="FoldersOffline"/>. Default on.
    /// </summary>
    public bool SkipPlaceholderFolders { get; init; } = true;

    /// <summary>Emits a listed file only when this says yes (null = every file). Sees the listing only: name, size, times.</summary>
    public Func<SafeTreeEntry, bool>? IncludeFile { get; init; }

    /// <summary>A file (exact <c>\?\</c> path) that is skipped and counted in <see cref="FilesSkipped"/> (e.g. pagefile.sys at a volume root).</summary>
    public Func<string, bool>? SkipFile { get; init; }

    /// <summary>A subfolder (exact <c>\?\</c> path) that is not descended into (null = none).</summary>
    public Func<string, bool>? SkipFolder { get; init; }

    public long FilesFiltered { get; set; }

    public long FilesSkipped { get; set; }

    public long FoldersSkipped { get; set; }

    public long FoldersTooDeep { get; set; }

    public long FoldersOffline { get; set; }

    public long EntriesSeen { get; set; }

    public bool LimitReached { get; set; }
}
