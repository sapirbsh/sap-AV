using System.Buffers.Binary;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Minimal PE header reader for signature tests: finds the Authenticode certificate table and the first
/// section's raw data, so a test can flip a byte that is covered by the signature hash, or strip the
/// signature to get an unsigned PE. Only used on copies of benign signed Microsoft files.
/// </summary>
internal static class PeImage
{
    private const int SecurityDirectoryIndex = 4;

    /// <summary>The certificate table (file offset and size), or null if the file isn't a PE or has none.</summary>
    public static (int Offset, int Size)? SecurityDirectory(byte[] image)
    {
        if (DataDirectoryOffset(image, SecurityDirectoryIndex) is not { } entry)
        {
            return null;
        }

        int offset = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(entry));
        int size = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(entry + 4));
        return offset > 0 && size > 0 && (long)offset + size <= image.Length ? (offset, size) : null;
    }

    /// <summary>True if <paramref name="path"/> is a PE file with an embedded Authenticode signature.</summary>
    public static bool HasEmbeddedSignature(string path)
    {
        try
        {
            return SecurityDirectory(File.ReadAllBytes(path)) is not null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Offset of a byte in the middle of the first section's raw data: inside the Authenticode hash, away
    /// from the headers, the checksum field and the certificate table.
    /// </summary>
    public static int BodyByteOffset(byte[] image)
    {
        int peHeader = PeHeaderOffset(image) ?? throw new InvalidDataException("Not a PE file.");
        int sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(peHeader + 20));
        int firstSection = peHeader + 24 + sizeOfOptionalHeader;
        int sizeOfRawData = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(firstSection + 16));
        int pointerToRawData = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(firstSection + 20));
        if (sizeOfRawData <= 0 || pointerToRawData <= 0 || pointerToRawData + sizeOfRawData > image.Length)
        {
            throw new InvalidDataException("First section has no raw data.");
        }

        return pointerToRawData + (sizeOfRawData / 2);
    }

    /// <summary>A copy with the certificate table removed and its directory entry zeroed: an unsigned PE.</summary>
    public static byte[] StripSignature(byte[] image)
    {
        var (offset, _) = SecurityDirectory(image) ?? throw new InvalidDataException("No embedded signature.");
        int entry = DataDirectoryOffset(image, SecurityDirectoryIndex)!.Value;
        var stripped = image.AsSpan(0, offset).ToArray();
        BinaryPrimitives.WriteInt64LittleEndian(stripped.AsSpan(entry), 0);
        return stripped;
    }

    private static int? PeHeaderOffset(byte[] image)
    {
        if (image.Length < 0x40 || image[0] != 'M' || image[1] != 'Z')
        {
            return null;
        }

        int peHeader = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        return peHeader > 0 && peHeader + 24 < image.Length
               && BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(peHeader)) == 0x00004550 // "PE\0\0"
            ? peHeader
            : null;
    }

    private static int? DataDirectoryOffset(byte[] image, int index)
    {
        if (PeHeaderOffset(image) is not { } peHeader)
        {
            return null;
        }

        int optionalHeader = peHeader + 24;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optionalHeader));
        (int countOffset, int directories) = magic switch
        {
            0x10B => (92, 96),   // PE32
            0x20B => (108, 112), // PE32+
            _ => (-1, -1),
        };

        if (countOffset < 0 || BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(optionalHeader + countOffset)) <= index)
        {
            return null;
        }

        int entry = optionalHeader + directories + (index * 8);
        return entry + 8 <= image.Length ? entry : null;
    }
}
