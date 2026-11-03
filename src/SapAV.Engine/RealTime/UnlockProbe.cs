using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.RealTime;

/// <summary>What <see cref="UnlockProbe.Probe"/> found.</summary>
internal enum ProbeOutcome
{
    /// <summary>No writer has the file open: it can be scanned now.</summary>
    Unlocked,

    /// <summary>A writer still has it open (sharing violation): still being written, wait.</summary>
    Locked,

    /// <summary>It is gone (deleted or renamed before it was looked at: normal for temporary files).</summary>
    Gone,

    /// <summary>It, or a folder on the way, is a junction / symlink / other name surrogate: never followed.</summary>
    Link,

    Directory,

    /// <summary>Another antivirus refused the open (ERROR_VIRUS_INFECTED / DELETED): it got there first. Not an error.</summary>
    BlockedByAntivirus,

    AccessDenied,

    Error,
}

/// <param name="Length">The file size from the probe's handle (Unlocked only).</param>
internal readonly record struct ProbeResult(ProbeOutcome Outcome, long Length = 0, int Win32Error = 0);

/// <summary>
/// "Wait until unlocked" (ROADMAP D1, carried over from the A2 review), <b>its own probe</b>, separate from the scan open.
/// The hasher shares Read | Write, and the scan open falls back to a shared open when a writer has the file, so neither
/// tells whether a download is finished. This probe opens the file for read with <b>writers denied</b> (share Read |
/// Delete: FileShare.Read for writers; delete stays shared so a downloader's pending rename never looks like a write), which
/// fails with a sharing violation while any process has it open for writing. On NTFS it also fails while a writable mapped
/// view exists (ROADMAP C5 L6 note), so a writer holding a writable section is waited for too. The open is relative to the
/// parent folder's handle, never follows a reparse point and never recalls cloud content; nothing is read.
/// </summary>
internal static class UnlockProbe
{
    private const uint ShareNoWriters = N.ShareRead | N.ShareDelete;

    public static ProbeResult Probe(SafeFileHandle parent, string name)
    {
        ArgumentNullException.ThrowIfNull(parent);
        using var handle = SafeTree.OpenChild(parent, name, N.GenericRead, ShareNoWriters, SafeTree.OpenNoRecall, out var failure, out int error);
        if (handle is null)
        {
            return new(Classify(failure, error), Win32Error: error);
        }

        if (SafeTree.IsDirectory(handle))
        {
            return new(ProbeOutcome.Directory);
        }

        try
        {
            return new(ProbeOutcome.Unlocked, RandomAccess.GetLength(handle));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(ProbeOutcome.Error, Win32Error: ex.HResult & 0xFFFF);
        }
    }

    /// <summary>The outcome for a failed open (pure; tested directly).</summary>
    internal static ProbeOutcome Classify(SafeTreeFailure failure, int win32Error) => win32Error switch
    {
        SafeScanOpen.ErrorVirusInfected or SafeScanOpen.ErrorVirusDeleted => ProbeOutcome.BlockedByAntivirus,
        _ => failure switch
        {
            SafeTreeFailure.Locked => ProbeOutcome.Locked,
            SafeTreeFailure.NotFound => ProbeOutcome.Gone,
            SafeTreeFailure.Redirected => ProbeOutcome.Link,
            SafeTreeFailure.AccessDenied => ProbeOutcome.AccessDenied,
            _ => ProbeOutcome.Error,
        },
    };
}

/// <summary>Opening a folder below a watched root <b>relative to the root's handle</b>, one component at a time (no link followed).</summary>
internal static class RelativeOpen
{
    /// <summary>
    /// Opens the folder <paramref name="relativeFolder"/> (empty = the root itself) below <paramref name="root"/> with
    /// <see cref="SafeTree.DirectoryAccess"/>. Every component is opened with <see cref="SafeTree.OpenChild"/>, so a junction
    /// or symlink anywhere on the way is refused (Redirected), not followed. Null with the failure otherwise.
    /// </summary>
    public static SafeFileHandle? OpenFolder(SafeFileHandle root, string relativeFolder, out SafeTreeFailure failure, out int win32Error)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (!IsValidRelative(relativeFolder, allowEmpty: true))
        {
            failure = SafeTreeFailure.Unsupported;
            win32Error = 0;
            return null;
        }

        // The empty name relative to the root opens the root object itself again (a handle the caller owns).
        var current = SafeTree.OpenChild(root, string.Empty, SafeTree.DirectoryAccess, SafeTree.ShareAll, N.FileDirectoryFile, out failure, out win32Error);
        if (current is null || relativeFolder.Length == 0)
        {
            return current;
        }

        foreach (var part in relativeFolder.Split('\\'))
        {
            var next = SafeTree.OpenChild(current, part, SafeTree.DirectoryAccess, SafeTree.ShareAll, N.FileDirectoryFile, out failure, out win32Error);
            current.Dispose();
            if (next is null)
            {
                return null;
            }

            current = next;
        }

        return current;
    }

    /// <summary>
    /// A relative name from a watcher event (or a rescan): components separated by <c>\</c>, none empty, <c>.</c> or <c>..</c>,
    /// no <c>/</c>, <c>:</c> or NUL. Kernel names never look otherwise; anything else is refused rather than interpreted.
    /// </summary>
    public static bool IsValidRelative(string relative, bool allowEmpty = false)
    {
        if (relative.Length == 0)
        {
            return allowEmpty;
        }

        if (relative.Length > short.MaxValue || relative.AsSpan().IndexOfAny('/', ':', '\0') >= 0)
        {
            return false;
        }

        foreach (var part in relative.Split('\\'))
        {
            if (part.Length == 0 || part is "." or "..")
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Splits <c>a\b\file.exe</c> into (<c>a\b</c>, <c>file.exe</c>).</summary>
    public static (string Folder, string Name) Split(string relative)
    {
        int slash = relative.LastIndexOf('\\');
        return slash < 0 ? (string.Empty, relative) : (relative[..slash], relative[(slash + 1)..]);
    }
}
