using System.Buffers.Binary;

namespace SapAV.Core.Heuristics;

/// <summary>What <see cref="PeHeaders.Probe"/> found at the start of a file.</summary>
/// <param name="IsMz">The file starts with "MZ" (an executable image as far as Windows is concerned, whatever else is wrong).</param>
/// <param name="Pe">The parsed headers, or null when there are none to parse.</param>
/// <param name="Malformed">Why the headers are malformed (engine text), or null: MZ without a reachable PE header, more sections
/// than the loader accepts, a section table past the headers read (A5 follow-up M2: each of these used to make the file "not a PE",
/// so the unsigned / entropy / folder rules were skipped).</param>
internal sealed record PeProbe(bool IsMz, PeHeaders? Pe, string? Malformed);

/// <summary>
/// Minimal, bounds-checked PE header reader: enough to tell whether a file is a PE image and where its
/// section data ends (everything after that is the overlay). Never throws on malformed input.
/// </summary>
internal sealed record PeHeaders(bool IsDll, int SectionCount, IReadOnlyList<(long Offset, long Size)> SectionData, long ImageEnd)
{
    /// <summary>Bytes read first; <see cref="HeaderBytesNeeded"/> says whether more are needed.</summary>
    public const int HeaderReadSize = 4096;

    /// <summary>Most header bytes ever read (A5 follow-up M2): <c>SizeOfHeaders</c> or the section table end, capped here.</summary>
    public const int MaxHeaderReadSize = 64 * 1024;

    /// <summary>The PE loader's section limit: more is a malformed-header signal, but the table is still read (up to 65535).</summary>
    public const int LoaderMaxSections = 96;

    /// <summary>
    /// How many bytes from the start of the file the headers need (<c>SizeOfHeaders</c>, the PE header, the section table), capped at
    /// <see cref="MaxHeaderReadSize"/> and the file length. <paramref name="head"/> is the first <see cref="HeaderReadSize"/> bytes.
    /// </summary>
    /// <remarks>
    /// All offsets are 32-bit header values held in <see cref="long"/>, so no sum overflows; a span is only indexed after the
    /// bound check, and the result never drops below <c>head.Length</c> (never throws, whatever the header says). Call it again
    /// with the larger head: the first call may only know where the PE header is, the second also sees the section table.
    /// </remarks>
    public static int HeaderBytesNeeded(ReadOnlySpan<byte> head, long fileLength)
    {
        if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z')
        {
            return head.Length;
        }

        long cap = Math.Clamp(fileLength, 0, MaxHeaderReadSize);
        long pe = BinaryPrimitives.ReadUInt32LittleEndian(head[0x3C..]);
        long needed = pe + 24 + 64; // the PE header and the start of the optional header (SizeOfHeaders is at +60)
        if (pe >= 0x40 && needed <= head.Length && BinaryPrimitives.ReadUInt32LittleEndian(head[(int)pe..]) == 0x00004550)
        {
            int sections = BinaryPrimitives.ReadUInt16LittleEndian(head[(int)(pe + 6)..]);
            int optional = BinaryPrimitives.ReadUInt16LittleEndian(head[(int)(pe + 20)..]);
            long sizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(head[(int)(pe + 24 + 60)..]);
            needed = Math.Max(sizeOfHeaders, pe + 24 + optional + (40L * sections));
        }

        // Not Math.Clamp: it throws when min > max, and a caller may hand in a head longer than fileLength claims.
        return (int)Math.Max(head.Length, Math.Min(needed, cap));
    }

    /// <summary>Probes the headers in <paramref name="head"/> (the first bytes of a file of <paramref name="fileLength"/> bytes).</summary>
    public static PeProbe Probe(ReadOnlySpan<byte> head, long fileLength)
    {
        if (head.Length < 2 || head[0] != (byte)'M' || head[1] != (byte)'Z')
        {
            return new PeProbe(false, null, null);
        }

        if (head.Length < 0x40)
        {
            return new PeProbe(true, null, "an MZ header too short to hold a PE header offset");
        }

        long pe = BinaryPrimitives.ReadUInt32LittleEndian(head[0x3C..]);
        if (pe < 0x40 || pe > head.Length - 24)
        {
            return new PeProbe(true, null, pe >= MaxHeaderReadSize - 24 && pe < fileLength
                ? "the PE header starts past the first 64 KiB"
                : "an MZ header without a reachable PE header");
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(head[(int)pe..]) != 0x00004550) // "PE\0\0"
        {
            return new PeProbe(true, null, "an MZ header without a PE signature");
        }

        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(head[(int)(pe + 6)..]); // at most 65535
        int optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(head[(int)(pe + 20)..]);
        bool isDll = (BinaryPrimitives.ReadUInt16LittleEndian(head[(int)(pe + 22)..]) & 0x2000) != 0;
        string? malformed = sectionCount > LoaderMaxSections ? $"{sectionCount} sections (the loader accepts {LoaderMaxSections})" : null;

        long table = pe + 24 + optionalHeaderSize;
        var sections = new List<(long, long)>();
        long imageEnd = Math.Min(table + (40L * sectionCount), fileLength); // at least the headers
        for (int i = 0; i < sectionCount; i++)
        {
            long entry = table + (40L * i);
            if (entry + 40 > head.Length)
            {
                malformed ??= "a section table past the headers read";
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

        return new PeProbe(true, new PeHeaders(isDll, sectionCount, sections.AsReadOnly(), imageEnd), malformed);
    }

    /// <summary>The parsed headers, or null (see <see cref="Probe"/>).</summary>
    public static PeHeaders? TryParse(ReadOnlySpan<byte> head, long fileLength) => Probe(head, fileLength).Pe;
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
