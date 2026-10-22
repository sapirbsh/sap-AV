using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Quarantine;

namespace SapAV.Engine.Quarantine;

/// <summary>
/// Byte copying for the quarantine: hashing a handle, writing the neutralised copy, verifying it, and writing the
/// plaintext back on restore. Content is only copied and XOR-ed here, never parsed.
/// </summary>
internal static class StoredContent
{
    private const int BufferSize = 256 * 1024;

    /// <summary>SHA-256 (lowercase hex) of <paramref name="handle"/> from offset 0, and the number of bytes read.</summary>
    public static (string Sha256, long Length) Hash(SafeFileHandle handle, CancellationToken cancellationToken = default)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long offset = 0;
            int read;
            while ((read = RandomAccess.Read(handle, buffer.AsSpan(0, BufferSize), offset)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                sha.AppendData(buffer, 0, read);
                offset += read;
            }

            return (Convert.ToHexStringLower(sha.GetHashAndReset()), offset);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Writes header + XOR-ed content of <paramref name="source"/> to a new file <paramref name="partialPath"/>
    /// (CreateNew, flushed to disk) and returns the SHA-256 of the plaintext that was copied and its length.
    /// </summary>
    public static (string Sha256, long Length) WriteNeutralised(SafeFileHandle source, string partialPath, byte[] key)
    {
        using var output = new FileStream(partialPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.None);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long length = RandomAccess.GetLength(source);
        Span<byte> header = stackalloc byte[QuarantineContentTransform.HeaderLength];
        QuarantineContentTransform.WriteHeader(header, length);
        output.Write(header);

        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long offset = 0;
            int read;
            while ((read = RandomAccess.Read(source, buffer.AsSpan(0, BufferSize), offset)) > 0)
            {
                sha.AppendData(buffer, 0, read);
                QuarantineContentTransform.Apply(key, buffer.AsSpan(0, read), offset);
                output.Write(buffer, 0, read);
                offset += read;
            }

            if (offset != length)
            {
                throw new IOException($"The source length changed while copying ({length} -> {offset} bytes).");
            }

            output.Flush(flushToDisk: true);
            return (Convert.ToHexStringLower(sha.GetHashAndReset()), offset);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>True if the stored file at <paramref name="dataPath"/> decodes to exactly the expected content.</summary>
    public static bool Verify(string dataPath, byte[] key, long expectedLength, string expectedSha256)
    {
        try
        {
            using var handle = File.OpenHandle(dataPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var (sha, length) = DecodeTo(handle, key, null);
            return length == expectedLength && sha == expectedSha256;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return false;
        }
    }

    /// <summary>
    /// Decodes the stored file <paramref name="stored"/> and, if <paramref name="target"/> is set, writes the plaintext
    /// to it from offset 0. Returns the plaintext SHA-256 and length.
    /// </summary>
    /// <exception cref="InvalidDataException">The header is missing or the length doesn't match it.</exception>
    public static (string Sha256, long Length) DecodeTo(SafeFileHandle stored, byte[] key, SafeFileHandle? target)
    {
        Span<byte> header = stackalloc byte[QuarantineContentTransform.HeaderLength];
        if (RandomAccess.Read(stored, header, 0) != header.Length
            || !QuarantineContentTransform.TryReadHeader(header, out long declared)
            || RandomAccess.GetLength(stored) != declared + QuarantineContentTransform.HeaderLength)
        {
            throw new InvalidDataException("The stored file has no valid quarantine header.");
        }

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            long offset = 0;
            int read;
            while ((read = RandomAccess.Read(stored, buffer.AsSpan(0, BufferSize), offset + QuarantineContentTransform.HeaderLength)) > 0)
            {
                QuarantineContentTransform.Apply(key, buffer.AsSpan(0, read), offset);
                sha.AppendData(buffer, 0, read);
                if (target is not null)
                {
                    RandomAccess.Write(target, buffer.AsSpan(0, read), offset);
                }

                offset += read;
            }

            return (Convert.ToHexStringLower(sha.GetHashAndReset()), offset);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}
