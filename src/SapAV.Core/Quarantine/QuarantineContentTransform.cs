using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace SapAV.Core.Quarantine;

/// <summary>
/// Neutralises quarantined content so the stored file can't run, be double-clicked into something useful, or be
/// re-detected by an antivirus or indexer: a 16-byte header, then the original bytes XOR-ed with a per-item random
/// <see cref="KeyLength"/>-byte key (byte <c>i</c> of the content is XOR-ed with <c>key[i % KeyLength]</c>).
/// </summary>
/// <remarks>
/// <para>
/// This is <b>neutralisation, not encryption</b>: the key is kept in the item's metadata (in the ACL'd store, under
/// the metadata HMAC). The goals are that no byte sequence of the original (MZ header, script text, YARA atoms)
/// appears in the stored file, and that the file starts with <see cref="Magic"/> instead of anything a loader or
/// shell recognises. XOR is its own inverse, so <see cref="Apply"/> both neutralises and restores.
/// </para>
/// <para>
/// Header layout (16 bytes): <see cref="Magic"/> (8 ASCII bytes <c>SAPAVQ01</c>), then the original length as a
/// little-endian <see cref="long"/>.
/// </para>
/// </remarks>
public static class QuarantineContentTransform
{
    /// <summary>The algorithm name recorded in metadata.</summary>
    public const string Algorithm = "xor-4096-v1";

    /// <summary>Key size in bytes.</summary>
    public const int KeyLength = 4096;

    /// <summary>Size of the header in front of the transformed content.</summary>
    public const int HeaderLength = 16;

    /// <summary>The first 8 bytes of every stored file.</summary>
    public static ReadOnlySpan<byte> Magic => "SAPAVQ01"u8;

    /// <summary>A new random key (cryptographic RNG).</summary>
    public static byte[] CreateKey() => RandomNumberGenerator.GetBytes(KeyLength);

    /// <summary>
    /// XORs <paramref name="data"/> in place with the key stream at content offset <paramref name="contentOffset"/>
    /// (the position of <c>data[0]</c> in the original file, not counting the header). Calling it twice restores
    /// the input, so chunks can be processed in any order.
    /// </summary>
    /// <exception cref="ArgumentException">The key is not <see cref="KeyLength"/> bytes.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="contentOffset"/> is negative.</exception>
    public static void Apply(ReadOnlySpan<byte> key, Span<byte> data, long contentOffset)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException($"The key must be {KeyLength} bytes.", nameof(key));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(contentOffset);
        int keyPos = (int)(contentOffset % KeyLength);
        while (!data.IsEmpty)
        {
            int n = Math.Min(data.Length, KeyLength - keyPos);
            XorInPlace(data[..n], key.Slice(keyPos, n));
            data = data[n..];
            keyPos = 0;
        }
    }

    /// <summary>Writes the header for content of <paramref name="length"/> bytes.</summary>
    /// <exception cref="ArgumentException"><paramref name="header"/> is shorter than <see cref="HeaderLength"/>.</exception>
    public static void WriteHeader(Span<byte> header, long length)
    {
        if (header.Length < HeaderLength)
        {
            throw new ArgumentException($"The header needs {HeaderLength} bytes.", nameof(header));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(length);
        Magic.CopyTo(header);
        BinaryPrimitives.WriteInt64LittleEndian(header[8..], length);
    }

    /// <summary>True if <paramref name="header"/> starts with a valid header; <paramref name="length"/> is the content length.</summary>
    public static bool TryReadHeader(ReadOnlySpan<byte> header, out long length)
    {
        length = 0;
        if (header.Length < HeaderLength || !header[..8].SequenceEqual(Magic))
        {
            return false;
        }

        length = BinaryPrimitives.ReadInt64LittleEndian(header[8..]);
        return length >= 0;
    }

    private static void XorInPlace(Span<byte> data, ReadOnlySpan<byte> key)
    {
        int i = 0;
        if (Vector.IsHardwareAccelerated)
        {
            int width = Vector<byte>.Count;
            for (; i + width <= data.Length; i += width)
            {
                var v = new Vector<byte>(data.Slice(i, width)) ^ new Vector<byte>(key.Slice(i, width));
                v.CopyTo(data.Slice(i, width));
            }
        }

        for (; i < data.Length; i++)
        {
            data[i] ^= key[i];
        }
    }
}
