using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Hashing;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.BrowserHijack;

/// <summary>The raw bytes and metadata of the hosts file (E6).</summary>
/// <param name="Content">At most the requested cap; empty unless <paramref name="State"/> is Available.</param>
/// <param name="Truncated">The file is longer than <paramref name="Content"/>.</param>
internal sealed record HostsFileRead(
    HijackReadState State, string? Detail, byte[] Content, bool Truncated, long? Length, DateTimeOffset? LastWriteTime, string? OwnerSid)
{
    public static HostsFileRead Failed(HijackReadState state, string? detail) => new(state, detail, [], false, null, null, null);
}

/// <summary>Reads the hosts file (fake in tests). Read-only; never throws for I/O.</summary>
internal interface IHostsFileReader
{
    HostsFileRead Read(string path, int maxBytes);
}

/// <summary>
/// The real <see cref="IHostsFileReader"/>: the hardened open (<see cref="SafeTree"/>: component by component, no reparse point
/// followed, name surrogates and remote paths refused, no recall of a cloud file, never waiting on an oplock), read access only,
/// a regular disk file only (<see cref="SecureFile.Validate"/>), then at most <c>maxBytes</c> read from that handle. Owner and
/// last-write time come from the same handle.
/// </summary>
internal sealed class SafeHostsFileReader : IHostsFileReader
{
    private const uint Options = N.FileNonDirectoryFile | SafeTree.OpenNoRecall | N.FileCompleteIfOplocked;

    public HostsFileRead Read(string path, int maxBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);
        using var handle = SafeTree.Open(path, N.GenericRead, SafeTree.ShareAll, Options, out var failure, out int error);
        if (handle is null)
        {
            return HostsFileRead.Failed(Map(failure), $"The hosts file can't be opened ({failure}, Win32 error {error}).");
        }

        try
        {
            if (!SecureFile.Validate(handle, out var invalid, out _))
            {
                return HostsFileRead.Failed(HijackReadState.Failed, Core.Text.SafeText.SingleLine(invalid.Message ?? "Not a regular file.", 256));
            }

            long length = RandomAccess.GetLength(handle);
            var lastWrite = new DateTimeOffset(File.GetLastWriteTimeUtc(handle), TimeSpan.Zero);
            var content = ReadCapped(handle, maxBytes, out bool truncated);
            return new HostsFileRead(HijackReadState.Available, null, content, truncated || length > maxBytes, length, lastWrite, Owner(handle));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return HostsFileRead.Failed(ex is UnauthorizedAccessException ? HijackReadState.AccessDenied : HijackReadState.Failed,
                $"The hosts file can't be read ({ex.GetType().Name}).");
        }
    }

    /// <summary>Reads up to <paramref name="maxBytes"/> (one more byte tells whether the file grew past the cap since its length was read).</summary>
    private static byte[] ReadCapped(SafeFileHandle handle, int maxBytes, out bool truncated)
    {
        var buffer = new byte[maxBytes + 1];
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

        truncated = total > maxBytes;
        return buffer.AsSpan(0, Math.Min(total, maxBytes)).ToArray();
    }

    private static string? Owner(SafeFileHandle handle)
    {
        var descriptor = Pipe.Native.PipeNative.TryReadFileSecurity(handle);
        if (descriptor is null)
        {
            return null;
        }

        try
        {
            return new RawSecurityDescriptor(descriptor, 0).Owner?.Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static HijackReadState Map(SafeTreeFailure failure) => failure switch
    {
        SafeTreeFailure.NotFound => HijackReadState.NotFound,
        SafeTreeFailure.AccessDenied => HijackReadState.AccessDenied,
        SafeTreeFailure.Redirected => HijackReadState.Redirected,
        SafeTreeFailure.Remote => HijackReadState.Remote,
        SafeTreeFailure.Locked => HijackReadState.Locked,
        _ => HijackReadState.Failed,
    };
}
