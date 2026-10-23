using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;

namespace SapAV.Core.Motw;

/// <summary>
/// The Mark-of-the-Web reader of the sandboxed scan worker (B5). The worker can't open the <c>Zone.Identifier</c>
/// stream itself (its token has no access to user files, by design), so the broker opens the stream relative to the
/// file handle and passes a read-only duplicate, or the Win32 error of that open. One instance per scan.
/// </summary>
/// <remarks>
/// <see cref="Read(SafeFileHandle, CancellationToken)"/> validates the file handle like <see cref="MarkOfTheWebReader"/>
/// and then parses the provided stream (it never opens anything). <see cref="Read(string, CancellationToken)"/> is not
/// supported here: the worker never opens a file by path.
/// </remarks>
public sealed class BrokeredMarkOfTheWebReader : IMarkOfTheWebReader
{
    private readonly SafeFileHandle? _stream;
    private readonly int _openError;

    /// <param name="stream">The <c>Zone.Identifier</c> stream handle (not owned), or null if the broker couldn't open it.</param>
    /// <param name="openError">The broker's Win32 error when <paramref name="stream"/> is null (2 = no stream).</param>
    public BrokeredMarkOfTheWebReader(SafeFileHandle? stream, int openError)
    {
        _stream = stream;
        _openError = openError;
    }

    public MarkOfTheWebResult Read(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        cancellationToken.ThrowIfCancellationRequested();
        return MarkOfTheWebResult.NotRead(HashFailureReason.InvalidPath, "The sandboxed reader reads only the stream the broker opened.");
    }

    public MarkOfTheWebResult Read(SafeFileHandle handle, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        cancellationToken.ThrowIfCancellationRequested();

        if (!SecureFile.Validate(handle, out var failure, out _, allowOffline: true))
        {
            return MarkOfTheWebResult.NotRead(failure.Reason, failure.Message);
        }

        return MarkOfTheWebReader.FromOpenedStream(_stream, _openError);
    }
}
