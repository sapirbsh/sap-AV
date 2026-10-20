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
}

/// <summary>
/// Reads <c>path:Zone.Identifier</c> without trusting the path twice. Thread-safe and stateless.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>The path must name a file, not a stream: a <c>:</c> in the file name (e.g. <c>a.txt:evil</c>) is InvalidPath.</item>
/// <item>The <b>base file</b> is opened first through the hardened path (<see cref="SecureFile"/>: device paths
/// never opened, <c>GetFileType</c> must be disk, directories rejected). Offline files and cloud placeholders
/// are allowed: their stream is metadata and is opened with no-recall, so nothing is downloaded.</item>
/// <item>Then the stream is opened the same hardened way, and its handle must report the <b>same file identity</b>
/// (volume serial + 128-bit file ID) as the base handle, which stays open meanwhile. A path swapped between
/// the two opens (e.g. replaced by a link to another file, a pipe or a device) is detected and nothing from
/// it is used. If the file system can't report identities, the stream isn't read (NotRead).</item>
/// <item>At most <see cref="MarkOfTheWeb.MaxStreamBytes"/> bytes are read; a missing stream is Absent.</item>
/// </list>
/// </remarks>
public sealed class MarkOfTheWebReader : IMarkOfTheWebReader
{
    public const string StreamName = "Zone.Identifier";

    /// <summary>Test seam: runs after the base file is open and before the stream is opened.</summary>
    internal Action? BetweenOpensHook { get; init; }

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

        if (!NativeFile.TryGetFileId(file, out var fileId))
        {
            return MarkOfTheWebResult.NotRead(HashFailureReason.IoError, "The file system did not report a file identity.");
        }

        BetweenOpensHook?.Invoke();
        cancellationToken.ThrowIfCancellationRequested();

        using var stream = SecureFile.OpenRegularFile(fullPath + ":" + StreamName, out var streamFailure, out _, allowOffline: true);
        if (stream is null)
        {
            return streamFailure.Reason switch
            {
                HashFailureReason.NotFound => MarkOfTheWebResult.Absent(),
                HashFailureReason.InvalidPath => MarkOfTheWebResult.Absent("The file system has no alternate data streams."),
                _ => MarkOfTheWebResult.NotRead(streamFailure.Reason, streamFailure.Message),
            };
        }

        if (!NativeFile.TryGetFileId(stream, out var streamId) || streamId != fileId)
        {
            return MarkOfTheWebResult.NotRead(HashFailureReason.ChangedDuringHashing,
                "The file was replaced between opening it and opening its Zone.Identifier stream.");
        }

        try
        {
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
