using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Scanning;

/// <summary>
/// A folder handle the walker listed, shared with the files it queued from that listing (review B H2): each queued file
/// is opened <b>relative to this handle</b>, so renaming or replacing a parent folder (or swapping it for a junction)
/// between the listing and the open can't send the engine anywhere else. Reference counted: the walker holds one
/// reference while it uses the folder, each queued file one more; the handle closes with the last release.
/// </summary>
internal sealed class SharedFolder
{
    private readonly SafeFileHandle _handle;
    private int _references = 1;

    /// <param name="handle">Owned from here on (closed by the last <see cref="Release"/>).</param>
    public SharedFolder(SafeFileHandle handle) => _handle = handle ?? throw new ArgumentNullException(nameof(handle));

    /// <summary>The folder handle; valid while the caller holds a reference.</summary>
    public SafeFileHandle Handle => _handle;

    /// <summary>References still held (tests).</summary>
    internal int References => Volatile.Read(ref _references);

    /// <summary>Takes one more reference (for a queued file) and returns this.</summary>
    /// <exception cref="ObjectDisposedException">The last reference was already released.</exception>
    public SharedFolder AddRef()
    {
        int current;
        do
        {
            current = Volatile.Read(ref _references);
            ObjectDisposedException.ThrowIf(current == 0, this);
        }
        while (Interlocked.CompareExchange(ref _references, current + 1, current) != current);

        return this;
    }

    /// <summary>Releases one reference; the last one closes the handle.</summary>
    public void Release()
    {
        int left = Interlocked.Decrement(ref _references);
        if (left == 0)
        {
            _handle.Dispose();
        }
        else if (left < 0)
        {
            throw new InvalidOperationException("SharedFolder released more often than referenced.");
        }
    }
}
