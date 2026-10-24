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
internal readonly record struct ScanTreeEntry(string Path, ScanTreeEntryKind Kind, long Length = 0, string? Detail = null);

/// <summary>
/// The recursive walk for "scan these files/folders" (B3), depth first, <b>bound to handles</b> (review B4 H3 / M2,
/// ROADMAP B3 M1). Each root is opened component by component with <see cref="SafeTree"/> (no reparse point followed
/// anywhere on the way, a name surrogate refused); each folder is opened once, relative to its parent's handle, checked
/// (the requester's access, <see cref="IScanAccessCheck.CanList"/>, on that handle's descriptor) and listed from that
/// same handle. A folder swapped for a junction after its parent was listed is opened as the junction itself and refused,
/// so the walk can't leave the requested tree or list a folder the check didn't cover. Name surrogates (junctions,
/// symlinks, mount points) are never followed; other reparse points (OneDrive / cloud files, dedup) are regular content
/// (the opener skips offline placeholders without recalling them). Depth is capped at <see cref="MaxDepth"/>.
/// Runs on the job's enumerator thread; nothing here reads file content.
/// </summary>
internal sealed class ScanTreeWalker(FolderSet excluded, Func<string, uint?>? reparseTag = null)
{
    /// <summary>Deepest folder nesting walked (review B3 C6 M2); deeper folders are reported Unreadable.</summary>
    public const int MaxDepth = 256;

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

        var handle = SafeTree.Open(root, SafeTree.DirectoryAccess, SafeTree.ShareAll, 0, out var failure, out _);
        if (handle is null)
        {
            // A link (on the way or the root itself) is skipped; anything else goes to the opener, which reports why.
            emit(failure == SafeTreeFailure.Redirected ? new(shown, ScanTreeEntryKind.SkippedLink) : new(shown, ScanTreeEntryKind.File));
            return;
        }

        if (!SafeTree.IsDirectory(handle))
        {
            long length = SafeLength(handle);
            handle.Dispose();
            emit(new(shown, ScanTreeEntryKind.File, length));
            return;
        }

        WalkTree(root, handle, emit, cancellationToken, access);
    }

    private sealed class Frame(string path, SafeFileHandle handle, List<string> subdirectories) : IDisposable
    {
        public string Path { get; } = path;

        public SafeFileHandle Handle { get; } = handle;

        public List<string> Subdirectories { get; } = subdirectories;

        public int Next { get; set; }

        public void Dispose() => Handle.Dispose();
    }

    /// <summary>Depth first; one handle per level is open (the chain from the root to the current folder).</summary>
    private void WalkTree(string root, SafeFileHandle rootHandle, Action<ScanTreeEntry> emit, CancellationToken cancellationToken, IScanAccessCheck? access)
    {
        var stack = new Stack<Frame>();
        try
        {
            if (Visit(root, rootHandle, emit, access) is { } first)
            {
                stack.Push(first);
            }

            while (stack.TryPeek(out var top))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (top.Next == top.Subdirectories.Count)
                {
                    stack.Pop().Dispose();
                    continue;
                }

                string name = top.Subdirectories[top.Next++];
                string path = SafeTree.Child(top.Path, name);
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

                if (Visit(path, child, emit, access) is { } frame)
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
    private Frame? Visit(string directory, SafeFileHandle handle, Action<ScanTreeEntry> emit, IScanAccessCheck? access)
    {
        string shown = ExactPath.ForOpening(directory);
        if (access is not null && !access.CanList(handle))
        {
            // B4: the requester can't list this folder, so the job doesn't either (and never descends below it).
            handle.Dispose();
            emit(new(shown, ScanTreeEntryKind.Unreadable, Detail: "AccessDenied (requester)"));
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

        var subdirectories = new List<string>();
        try
        {
            foreach (var entry in entries)
            {
                Classify(directory, entry, subdirectories, emit);
            }
        }
        catch
        {
            handle.Dispose();
            throw;
        }

        return new Frame(directory, handle, subdirectories);
    }

    private void Classify(string directory, SafeTreeEntry entry, List<string> subdirectories, Action<ScanTreeEntry> emit)
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
            subdirectories.Add(entry.Name);
        }
        else
        {
            emit(new(shown, ScanTreeEntryKind.File, entry.Length));
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
