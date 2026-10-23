using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;

namespace SapAV.Core.Motw;

/// <summary>Reads a file's Mark-of-the-Web. Implemented by <see cref="MarkOfTheWebReader"/>; fake it in tests (A7).</summary>
public interface IMarkOfTheWebReader
{
    /// <summary>Reads the <c>Zone.Identifier</c> stream of the file at <paramref name="path"/>. Never throws for I/O.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="path"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    MarkOfTheWebResult Read(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads the <c>Zone.Identifier</c> stream of the file behind an already open handle, opened <b>relative to that
    /// handle</b> (the single-handle scan pipeline). The handle is validated first and is not closed.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="handle"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    MarkOfTheWebResult Read(SafeFileHandle handle, CancellationToken cancellationToken = default);
}

/// <summary>Reads the <c>Zone.Identifier</c> stream without resolving the path a second time. Thread-safe and stateless.</summary>
/// <remarks>
/// <list type="number">
/// <item>A path must name a file, not a stream: a <c>:</c> in the file name (e.g. <c>a.txt:evil</c>) is InvalidPath.</item>
/// <item>The <b>base file</b> is opened through the hardened path (<see cref="SecureFile"/>: device paths never opened,
/// <c>GetFileType</c> must be disk, directories rejected). Offline files and cloud placeholders are allowed: the
/// stream is metadata and is opened with no-recall, so nothing is downloaded.</item>
/// <item>The stream is opened with <c>NtCreateFile</c> <b>relative to the base file handle</b>
/// (<c>RootDirectory</c> = the file, name <c>:Zone.Identifier</c>), read-only, no recall, anonymous SQOS. The path
/// is never looked up again, so a path swapped after the base open (rename, junction flip, link to a pipe)
/// can't redirect the read. The stream handle must also be a disk file.</item>
/// <item>At most <see cref="MarkOfTheWeb.MaxStreamBytes"/> bytes are read; a missing stream (or a file system
/// without streams) is Absent.</item>
/// </list>
/// </remarks>
public sealed class MarkOfTheWebReader : IMarkOfTheWebReader
{
    public const string StreamName = "Zone.Identifier";

    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorInvalidName = 123;

    public MarkOfTheWebResult Read(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        cancellationToken.ThrowIfCancellationRequested();

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return MarkOfTheWebResult.NotRead(HashFailureReason.InvalidPath, ex.Message);
        }

        if (Path.GetFileName(fullPath).Contains(':'))
        {
            return MarkOfTheWebResult.NotRead(HashFailureReason.InvalidPath,
                "The path names an alternate data stream, not a file.");
        }

        using var file = SecureFile.OpenRegularFile(path, out var failure, out _, allowOffline: true);
        if (file is null)
        {
            return MarkOfTheWebResult.NotRead(failure.Reason, failure.Message);
        }

        return ReadValidated(file, cancellationToken);
    }

    public MarkOfTheWebResult Read(SafeFileHandle handle, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        cancellationToken.ThrowIfCancellationRequested();

        if (!SecureFile.Validate(handle, out var failure, out _, allowOffline: true))
        {
            return MarkOfTheWebResult.NotRead(failure.Reason, failure.Message);
        }

        return ReadValidated(handle, cancellationToken);
    }

    private static MarkOfTheWebResult ReadValidated(SafeFileHandle file, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var stream = NativeFile.OpenStreamRelative(file, ":" + StreamName, out int error);
        return FromOpenedStream(stream, error);
    }

    /// <summary>
    /// The result for an already opened <c>Zone.Identifier</c> stream (<paramref name="stream"/>), or for the Win32
    /// error of a failed open (<paramref name="openError"/>, when <paramref name="stream"/> is null). Shared by this
    /// reader and the sandboxed scan worker (B5), which gets the stream handle from the broker. Never throws for I/O;
    /// the stream is not closed.
    /// </summary>
    internal static MarkOfTheWebResult FromOpenedStream(SafeFileHandle? stream, int openError)
    {
        if (stream is null || stream.IsInvalid)
        {
            return openError switch
            {
                ErrorFileNotFound or ErrorPathNotFound => MarkOfTheWebResult.Absent(),
                ErrorNotSupported or ErrorInvalidParameter or ErrorInvalidName =>
                    MarkOfTheWebResult.Absent("The file system has no alternate data streams."),
                _ => MarkOfTheWebResult.NotRead(Sha256Hasher.MapWin32Error(openError), $"Could not open the Zone.Identifier stream (Win32 error {openError})."),
            };
        }

        try
        {
            if (NativeFile.GetFileType(stream) != NativeFile.FileTypeDisk)
            {
                return MarkOfTheWebResult.NotRead(HashFailureReason.NotRegularFile, "The Zone.Identifier stream is not a disk file.");
            }

            return MarkOfTheWebResult.Present(MarkOfTheWeb.Parse(ReadCapped(stream)));
        }
        catch (Exception ex) when (Sha256Hasher.TryClassify(ex, out var reason))
        {
            return MarkOfTheWebResult.NotRead(reason, ex.Message);
        }
    }

    private static byte[] ReadCapped(SafeFileHandle handle)
    {
        long length = Math.Min(RandomAccess.GetLength(handle), MarkOfTheWeb.MaxStreamBytes);
        var buffer = new byte[length];
        int total = 0;
        while (total < buffer.Length)
        {
            int read = RandomAccess.Read(handle, buffer.AsSpan(total), total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total == buffer.Length ? buffer : buffer[..total];
    }
}
