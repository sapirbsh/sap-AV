using System.Buffers.Binary;

namespace SapAV.Core.Heuristics;

/// <summary>
/// Minimal, bounds-checked PE header reader: enough to tell whether a file is a PE image and where its
/// section data ends (everything after that is the overlay). Never throws on malformed input.
/// </summary>
internal sealed record PeHeaders(bool IsDll, int SectionCount, IReadOnlyList<(long Offset, long Size)> SectionData, long ImageEnd)
{
    /// <summary>Bytes to read from the start of a file so the headers and section table are normally covered.</summary>
    public const int HeaderReadSize = 4096;

    private const int MaxSections = 96; // the PE loader's limit

    /// <summary>Parses the headers in <paramref name="head"/> (the first bytes of a file of <paramref name="fileLength"/> bytes).</summary>
    public static PeHeaders? TryParse(ReadOnlySpan<byte> head, long fileLength)
    {
        if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z')
        {
            return null;
        }

        int pe = BinaryPrimitives.ReadInt32LittleEndian(head[0x3C..]);
        if (pe < 0x40 || pe > head.Length - 24 || BinaryPrimitives.ReadUInt32LittleEndian(head[pe..]) != 0x00004550) // "PE\0\0"
        {
            return null;
        }

        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(head[(pe + 6)..]);
        int optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(head[(pe + 20)..]);
        bool isDll = (BinaryPrimitives.ReadUInt16LittleEndian(head[(pe + 22)..]) & 0x2000) != 0;
        if (sectionCount > MaxSections)
        {
            return null;
        }

        long table = (long)pe + 24 + optionalHeaderSize;
        var sections = new List<(long, long)>();
        long imageEnd = Math.Min(table + (40L * sectionCount), fileLength); // at least the headers
        for (int i = 0; i < sectionCount; i++)
        {
            long entry = table + (40L * i);
            if (entry + 40 > head.Length)
            {
                break; // section table beyond what was read: use what we have
            }

            long size = BinaryPrimitives.ReadUInt32LittleEndian(head[(int)(entry + 16)..]);
            long offset = BinaryPrimitives.ReadUInt32LittleEndian(head[(int)(entry + 20)..]);
            if (size == 0 || offset >= fileLength)
            {
                continue;
            }

            size = Math.Min(size, fileLength - offset);
            sections.Add((offset, size));
            imageEnd = Math.Max(imageEnd, offset + size);
        }

        return new PeHeaders(isDll, sectionCount, sections.AsReadOnly(), imageEnd);
    }
}

/// <summary>Shannon entropy in bits per byte (0 = one repeated value, 8 = uniformly random).</summary>
public sealed class ShannonEntropy
{
    private readonly long[] _counts = new long[256];

    public long Total { get; private set; }

    public void Add(ReadOnlySpan<byte> data)
    {
        foreach (byte b in data)
        {
            _counts[b]++;
        }

        Total += data.Length;
    }

    /// <summary>Entropy of everything added so far (0 for no data).</summary>
    public double Value
    {
        get
        {
            if (Total == 0)
            {
                return 0;
            }

            double entropy = 0;
            foreach (long count in _counts)
            {
                if (count > 0)
                {
                    double p = (double)count / Total;
                    entropy -= p * Math.Log2(p);
                }
            }

            return entropy;
        }
    }

    public static double Of(ReadOnlySpan<byte> data)
    {
        var e = new ShannonEntropy();
        e.Add(data);
        return e.Value;
    }
}
