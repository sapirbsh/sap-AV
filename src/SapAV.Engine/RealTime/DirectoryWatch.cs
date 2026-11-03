using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.RealTime;

/// <summary>What happened to a name in a watched folder (only what real-time monitoring acts on).</summary>
internal enum FileChangeKind
{
    Added,
    Modified,

    /// <summary>The new name of a rename (moved in, or renamed in place, e.g. a finished download).</summary>
    RenamedTo,

    /// <summary>A named stream of the file was added or written (the name is the file's; see <see cref="FileChange.Stream"/>).</summary>
    StreamChanged,
}

/// <summary>One change, with the extended information when the file system gives it (NTFS: ReadDirectoryChangesExW).</summary>
/// <param name="Name">Relative to the watched folder (<c>sub\file.exe</c>), exactly as the file system reported it.</param>
/// <param name="Attributes">The object's attributes at the time of the change; null when unknown.</param>
/// <param name="Size">End of file at the time of the change; null when unknown.</param>
/// <param name="ReparseTag">The reparse tag when <paramref name="Attributes"/> has ReparsePoint.</param>
/// <param name="Stream">For <see cref="FileChangeKind.StreamChanged"/>: the stream name (e.g. <c>Zone.Identifier</c>).</param>
internal readonly record struct FileChange(
    FileChangeKind Kind, string Name, FileAttributes? Attributes = null, long? Size = null, uint ReparseTag = 0, string? Stream = null)
{
    public bool IsDirectory => Attributes is { } a && a.HasFlag(FileAttributes.Directory);

    /// <summary>A junction, symlink or other name surrogate (known from the event; never followed).</summary>
    public bool IsLink => Attributes is { } a && a.HasFlag(FileAttributes.ReparsePoint) && Scanning.Native.ScanNative.IsNameSurrogate(ReparseTag);

    /// <summary>The Mark-of-the-Web stream was written: a download (queued first).</summary>
    public bool IsMarkOfTheWeb => Kind == FileChangeKind.StreamChanged && string.Equals(Stream, "Zone.Identifier", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Receives a watch's notifications (on an I/O completion thread: must be quick and never block).</summary>
internal interface IDirectoryWatchSink
{
    void OnChanges(WatchedRoot root, IReadOnlyList<FileChange> changes);

    /// <summary>Notifications were lost (the buffer overflowed): the folder needs a rescan.</summary>
    void OnOverflow(WatchedRoot root);

    /// <summary>The watch stopped (the folder was deleted, access was lost, ...).</summary>
    void OnFailed(WatchedRoot root, int win32Error);
}

/// <summary>Starts watching a root's directory object; fake it in tests (most tests push events by hand).</summary>
internal interface IDirectoryWatchFactory
{
    /// <exception cref="Win32Exception">The watch could not be started.</exception>
    IDisposable Start(WatchedRoot root, IDirectoryWatchSink sink, int bufferBytes);
}

/// <summary>
/// A watched folder, <b>bound to a handle</b>: opened once through <see cref="SafeTree"/> (component by component, no reparse
/// point followed, name surrogates refused, local only), and every event under it is resolved relative to this handle,
/// never by path. If the folder is later renamed and replaced with a junction, events still lead into the original folder
/// object, so a link can't redirect SYSTEM; revalidation notices the swap and stops the watch.
/// </summary>
internal sealed class WatchedRoot : IDisposable
{
    private long _lastBatchTicks;
    private int _closed;

    public WatchedRoot(int id, WatchedFolder folder, string exactPath, SafeFileHandle handle, ulong volume, string fileId, DateTimeOffset openedAt)
    {
        Id = id;
        Folder = folder;
        ExactPath = exactPath;
        Handle = handle;
        Volume = volume;
        FileId = fileId;
        _lastBatchTicks = openedAt.UtcTicks;
    }

    public int Id { get; }

    public WatchedFolder Folder { get; }

    /// <summary>The <c>\\?\</c> form of the folder (exact names).</summary>
    public string ExactPath { get; }

    /// <summary>The folder's handle (list + traverse); events are opened relative to it.</summary>
    public SafeFileHandle Handle { get; }

    public ulong Volume { get; }

    public string FileId { get; }

    /// <summary>The live watch (owned).</summary>
    public IDisposable? Watch { get; set; }

    public bool Closed => Volatile.Read(ref _closed) != 0;

    /// <summary>The watch reported a failure (the folder was deleted, access lost): revalidation replaces or stops it.</summary>
    public bool Failed
    {
        get => Volatile.Read(ref _failed) != 0;
        set => Volatile.Write(ref _failed, value ? 1 : 0);
    }

    private int _failed;

    /// <summary>When the last notification batch arrived (or the watch started): an overflow lost events after it.</summary>
    public DateTimeOffset LastBatchAt => new(Interlocked.Read(ref _lastBatchTicks), TimeSpan.Zero);

    public void MarkBatch(DateTimeOffset at) => Interlocked.Exchange(ref _lastBatchTicks, at.UtcTicks);

    /// <summary>The exact path of a name relative to this folder.</summary>
    public string PathOf(string relative) => relative.Length == 0 ? ExactPath : SafeTree.Child(ExactPath, relative);

    /// <summary>The name relative to this folder of an exact path below it, or null.</summary>
    public string? RelativeOf(string path)
    {
        if (Core.Hashing.ExactPath.ToExtended(path) is not { } exact)
        {
            return null;
        }

        string prefix = ExactPath.EndsWith('\\') ? ExactPath : ExactPath + "\\";
        return exact.Length > prefix.Length && exact.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? exact[prefix.Length..] : null;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        Watch?.Dispose();
        Handle.Dispose();
    }
}

/// <summary>The real watches: <see cref="NativeDirectoryWatch"/>.</summary>
internal sealed class NativeDirectoryWatchFactory : IDirectoryWatchFactory
{
    public static NativeDirectoryWatchFactory Instance { get; } = new();

    public IDisposable Start(WatchedRoot root, IDirectoryWatchSink sink, int bufferBytes) => new NativeDirectoryWatch(root, sink, bufferBytes);
}

/// <summary>
/// A recursive watch on one folder object with <c>ReadDirectoryChangesExW</c> (extended information: attributes, size and
/// reparse tag come with each event, so folders, links and over-size files are known without an open), falling back to
/// <c>ReadDirectoryChangesW</c> where the file system doesn't support it. Unlike <see cref="FileSystemWatcher"/>, which opens
/// its folder <b>by path</b> (following junctions and symlinks, so SYSTEM could be sent to another folder or a server), this
/// watches the handle <see cref="SafeTree"/> opened: it is reopened by the empty name relative to that handle (the same object, no path lookup)
/// for overlapped I/O on the thread pool. The buffer (<see cref="RealTimeOptions.WatcherBufferBytes"/>, 64 KiB by default
/// against FileSystemWatcher's 8 KiB) is pinned for the watch's life; an empty completion or ERROR_NOTIFY_ENUM_DIR means
/// notifications were lost, reported as an overflow.
/// </summary>
internal sealed unsafe class NativeDirectoryWatch : IDisposable
{
    private const uint FileListDirectory = 0x0001;
    private const uint ShareAll = 0x7;

    // FILE_NOTIFY_CHANGE_FILE_NAME | DIR_NAME | SIZE | LAST_WRITE | CREATION; the stream bits (NT-level) report named streams.
    private const uint BasicFilter = 0x1 | 0x2 | 0x8 | 0x10 | 0x40;
    private const uint StreamFilter = 0x200 /* STREAM_NAME */ | 0x800 /* STREAM_WRITE */;

    private const int ReadDirectoryNotifyExtendedInformation = 2;
    private const uint ErrorOperationAborted = 995;
    private const uint ErrorNotifyEnumDir = 1022;

    private readonly WatchedRoot _root;
    private readonly IDirectoryWatchSink _sink;
    private readonly SafeFileHandle _handle;
    private readonly byte[] _buffer;
    private readonly object _gate = new();
    private readonly ThreadPoolBoundHandle? _bound;
    private readonly PreAllocatedOverlapped? _overlapped;
    private bool _extended = true;
    private uint _filter = BasicFilter | StreamFilter;
    private bool _pending;
    private bool _disposed;

    public NativeDirectoryWatch(WatchedRoot root, IDirectoryWatchSink sink, int bufferBytes)
    {
        _root = root ?? throw new ArgumentNullException(nameof(root));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _buffer = GC.AllocateArray<byte>(bufferBytes, pinned: true);
        _handle = OpenOverlapped(root.Handle);

        try
        {
            _bound = ThreadPoolBoundHandle.BindHandle(_handle);
            _overlapped = PreAllocatedOverlapped.UnsafeCreate(OnCompleted, this, null);
            StartFirst();
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// The same folder object again, for overlapped I/O: the empty name relative to the root's handle (no path lookup, so
    /// nothing can be redirected), with FILE_OPEN_REPARSE_POINT and OBJ_DONT_REPARSE, and checked to be that same object.
    /// </summary>
    /// <exception cref="Win32Exception">It could not be opened, or it isn't the root's object.</exception>
    private static SafeFileHandle OpenOverlapped(SafeFileHandle root)
    {
        var handle = Quarantine.Native.QuarantineNative.OpenRelative(root, string.Empty, FileListDirectory, ShareAll, Quarantine.Native.QuarantineNative.FileOpen,
            Quarantine.Native.QuarantineNative.FileDirectoryFile | Quarantine.Native.QuarantineNative.FileOpenReparsePoint, out int error,
            Quarantine.Native.QuarantineNative.ObjCaseInsensitive | Quarantine.Native.QuarantineNative.ObjDontReparse, synchronous: false);
        if (handle is null)
        {
            throw new Win32Exception(error);
        }

        if (!NativeFile.TryGetFileId(handle, out ulong volume, out string id) || !NativeFile.TryGetFileId(root, out ulong rootVolume, out string rootId)
            || volume != rootVolume || !string.Equals(id, rootId, StringComparison.Ordinal))
        {
            handle.Dispose();
            throw new Win32Exception(6 /* ERROR_INVALID_HANDLE */, "The watch handle is not the watched folder.");
        }

        return handle;
    }

    /// <summary>Whether the extended (attributes + size) form is in use.</summary>
    internal bool Extended => _extended;

    /// <summary>The first request decides the form: extended with streams, extended without, then the classic call.</summary>
    private void StartFirst()
    {
        (bool Extended, uint Filter)[] forms = [(true, BasicFilter | StreamFilter), (true, BasicFilter), (false, BasicFilter)];
        int error = 0;
        foreach (var (extended, filter) in forms)
        {
            _extended = extended;
            _filter = filter;
            error = Issue();
            if (error == 0)
            {
                return;
            }

            if (error is not (87 or 1 or 50)) // ERROR_INVALID_PARAMETER / INVALID_FUNCTION / NOT_SUPPORTED: try the next form
            {
                break;
            }
        }

        throw new Win32Exception(error);
    }

    /// <returns>0 if a request is pending (or the watch is disposed), else the Win32 error.</returns>
    private int Issue()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return 0;
            }

            NativeOverlapped* overlapped = _bound!.AllocateNativeOverlapped(_overlapped!);
            bool ok;
            fixed (byte* buffer = _buffer)
            {
                ok = _extended
                    ? ReadDirectoryChangesExW(_handle, buffer, (uint)_buffer.Length, true, _filter, null, overlapped, IntPtr.Zero, ReadDirectoryNotifyExtendedInformation)
                    : ReadDirectoryChangesW(_handle, buffer, (uint)_buffer.Length, true, _filter, null, overlapped, IntPtr.Zero);
            }

            if (ok)
            {
                _pending = true;
                return 0;
            }

            int error = Marshal.GetLastPInvokeError();
            _bound.FreeNativeOverlapped(overlapped);
            return error;
        }
    }

    private static void OnCompleted(uint errorCode, uint numBytes, NativeOverlapped* overlapped)
    {
        var self = (NativeDirectoryWatch)ThreadPoolBoundHandle.GetNativeOverlappedState(overlapped)!;
        self.Completed(errorCode, numBytes, overlapped);
    }

    private void Completed(uint errorCode, uint numBytes, NativeOverlapped* overlapped)
    {
        List<FileChange>? changes = null;
        lock (_gate)
        {
            _bound!.FreeNativeOverlapped(overlapped);
            _pending = false;
            if (_disposed || errorCode == ErrorOperationAborted)
            {
                Monitor.PulseAll(_gate);
                return;
            }

            if (errorCode == 0 && numBytes > 0)
            {
                changes = TryParse(_buffer.AsSpan(0, (int)Math.Min(numBytes, (uint)_buffer.Length)), _extended);
            }
        }

        try
        {
            if (errorCode != 0 && errorCode != ErrorNotifyEnumDir)
            {
                _sink.OnFailed(_root, (int)errorCode);
                return; // not re-issued: revalidation decides what happens to the folder
            }

            // Parsed first, then the next request goes out before the sink runs, so the window without a request stays short.
            int error = Issue();
            if (changes is null)
            {
                _sink.OnOverflow(_root);
            }
            else if (changes.Count > 0)
            {
                _sink.OnChanges(_root, changes);
            }

            if (error != 0)
            {
                _sink.OnFailed(_root, error);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The sink must not throw; if it does, the watch goes on (the next request is already out).
            System.Diagnostics.Debug.WriteLine($"Real-time sink failed: {ex}");
        }
    }

    /// <summary>
    /// Parses FILE_NOTIFY_EXTENDED_INFORMATION (or FILE_NOTIFY_INFORMATION) records, bounds-checked: a record that doesn't
    /// fit ends the parse. Only Added / Modified / RenamedTo / stream changes are kept.
    /// </summary>
    /// <summary>Review D1 L1: <see cref="Parse"/> on the I/O thread, guarded: a parse failure is treated as lost events (a rescan), never a crash.</summary>
    private static List<FileChange>? TryParse(ReadOnlySpan<byte> data, bool extended)
    {
        try
        {
            return Parse(data, extended);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException)
        {
            return null;
        }
    }

    internal static List<FileChange> Parse(ReadOnlySpan<byte> data, bool extended)
    {
        // Extended: NextEntryOffset 0, Action 4, times 8-39, AllocatedLength 40, FileSize 48, FileAttributes 56,
        // ReparsePointTag 60, FileId 64, ParentFileId 72, FileNameLength 80, FileName 84. Classic: 0, 4, FileNameLength 8, FileName 12.
        int header = extended ? 84 : 12;
        var changes = new List<FileChange>();
        int offset = 0;
        while (offset >= 0 && (long)offset + header <= data.Length)
        {
            var record = data[offset..];
            int next = BitConverter.ToInt32(record);
            int action = BitConverter.ToInt32(record[4..]);
            int nameBytes = BitConverter.ToInt32(record[(header - 4)..]);
            if (nameBytes < 0 || (nameBytes & 1) != 0 || (long)header + nameBytes > record.Length) // review D1 L1: no int overflow
            {
                break;
            }

            string name = new(MemoryMarshal.Cast<byte, char>(record.Slice(header, nameBytes)));
            FileAttributes? attributes = extended ? (FileAttributes)BitConverter.ToUInt32(record[56..]) : null;
            long? size = extended ? BitConverter.ToInt64(record[48..]) : null;
            uint tag = extended ? BitConverter.ToUInt32(record[60..]) : 0;
            if (ToChange(action, name, attributes, size, tag) is { } change)
            {
                changes.Add(change);
            }

            if (next <= 0)
            {
                break;
            }

            if ((long)offset + next > data.Length)
            {
                break;
            }

            offset += next;
        }

        return changes;
    }

    private static FileChange? ToChange(int action, string name, FileAttributes? attributes, long? size, uint tag)
    {
        string? stream = null;
        int colon = name.IndexOf(':', name.LastIndexOf('\\') + 1);
        if (colon >= 0)
        {
            stream = name[(colon + 1)..];
            int type = stream.IndexOf(':');
            stream = type >= 0 ? stream[..type] : stream; // "Zone.Identifier:$DATA"
            name = name[..colon];
        }

        FileChangeKind? kind = action switch
        {
            1 /* ADDED */ => FileChangeKind.Added,
            3 /* MODIFIED */ => FileChangeKind.Modified,
            5 /* RENAMED_NEW_NAME */ => FileChangeKind.RenamedTo,
            6 /* ADDED_STREAM */ or 8 /* MODIFIED_STREAM */ => FileChangeKind.StreamChanged,
            _ => null,
        };
        if (kind is null || name.Length == 0)
        {
            return null;
        }

        if (stream is not null)
        {
            kind = FileChangeKind.StreamChanged; // a stream of the file, whatever the action said
        }

        return new FileChange(kind.Value, name, attributes, size, tag, stream);
    }

    public void Dispose()
    {
        bool pending;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            pending = _pending;
        }

        if (pending && !_handle.IsInvalid)
        {
            CancelIoEx(_handle, null);
        }

        bool idle;
        lock (_gate)
        {
            var deadline = Environment.TickCount64 + 5000;
            while (_pending && Environment.TickCount64 < deadline)
            {
                Monitor.Wait(_gate, 100);
            }

            idle = !_pending;
        }

        if (idle)
        {
            _overlapped?.Dispose();
            _bound?.Dispose();
        }

        // If a request is somehow still pending, the pinned buffer and the overlapped are left to the process (never freed
        // under the kernel); closing the handle completes the request.
        _handle.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadDirectoryChangesW(
        SafeFileHandle directory, byte* buffer, uint bufferLength, [MarshalAs(UnmanagedType.Bool)] bool watchSubtree, uint notifyFilter,
        uint* bytesReturned, NativeOverlapped* overlapped, IntPtr completionRoutine);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadDirectoryChangesExW(
        SafeFileHandle directory, byte* buffer, uint bufferLength, [MarshalAs(UnmanagedType.Bool)] bool watchSubtree, uint notifyFilter,
        uint* bytesReturned, NativeOverlapped* overlapped, IntPtr completionRoutine, int informationClass);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(SafeFileHandle file, NativeOverlapped* overlapped);
}
