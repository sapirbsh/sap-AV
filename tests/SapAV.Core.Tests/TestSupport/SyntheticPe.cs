using System.Buffers.Binary;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Signatures;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Builds files that only look like PE images to a header parser: a DOS header, PE headers and one section
/// filled with bytes the test chooses (zeros, random). They contain no code and can't run.
/// </summary>
internal static class SyntheticPe
{
    private const int PeOffset = 0x40;
    private const int OptionalHeaderSize = 0xF0;
    private const int SectionDataOffset = 0x400;

    public static byte[] Build(byte[] sectionData, int overlayLength = 0, byte overlayByte = 0)
    {
        var image = new byte[SectionDataOffset + sectionData.Length + overlayLength];
        var s = image.AsSpan();
        s[0] = (byte)'M';
        s[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(s[0x3C..], PeOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(s[PeOffset..], 0x00004550);           // "PE\0\0"
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 4)..], 0x8664);         // x64
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 6)..], 1);              // one section
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 20)..], OptionalHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 22)..], 0x0022);        // executable image
        BinaryPrimitives.WriteUInt16LittleEndian(s[(PeOffset + 24)..], 0x020B);        // PE32+ magic
        int section = PeOffset + 24 + OptionalHeaderSize;
        ".data"u8.CopyTo(s[section..]);
        BinaryPrimitives.WriteInt32LittleEndian(s[(section + 16)..], sectionData.Length);
        BinaryPrimitives.WriteInt32LittleEndian(s[(section + 20)..], SectionDataOffset);
        sectionData.CopyTo(s[SectionDataOffset..]);
        s[(SectionDataOffset + sectionData.Length)..].Fill(overlayByte);
        return image;
    }

    /// <summary>
    /// A path under a user's Temp folder for in-memory analysis (<c>FileHeuristics.Analyze(ReadOnlyMemory&lt;byte&gt;, ...)</c>):
    /// it is never opened, it only feeds the name and folder rules, so the risky-folder rule (Temp) applies to executables.
    /// </summary>
    public static string FakeTempPath(string name) => @"C:\Users\test\AppData\Local\Temp\sapav-tests\" + name;

    /// <summary>
    /// The synthetic PE files the on-disk tests write to %TEMP% (the real handle/I/O path). The
    /// <see cref="Requires.SyntheticPeOnDisk"/> probe writes and reads exactly these, so a real antivirus that blocks
    /// one of them turns those tests into a Skip instead of a failure. Each has a content finding it must produce.
    /// </summary>
    public static IReadOnlyList<OnDiskSample> OnDiskSamples { get; } =
    [
        // Section data read through the handle: entropy.
        new("packed.exe", () => Build(Random(64 * 1024)), Sha256Hasher.DefaultMaxSizeBytes, HeuristicKind.HighEntropyExecutable),

        // Over a small size limit: header + sampled overlay reads through the handle (padding).
        new("padded.exe", () => Build(Random(8192), overlayLength: 1024 * 1024), 64 * 1024, HeuristicKind.PaddedOversizedExecutable),
    ];

    public static OnDiskSample OnDisk(string name) => OnDiskSamples.Single(s => s.Name == name);

    public sealed record OnDiskSample(string Name, Func<byte[]> Build, long MaxSizeBytes, HeuristicKind ContentFinding)
    {
        private readonly Lazy<byte[]> _bytes = new(Build);

        public byte[] Bytes => _bytes.Value;

        public FileHeuristics Heuristics() => new(MaxSizeBytes);
    }

    public static byte[] Random(int count, int seed = 7)
    {
        var bytes = new byte[count];
        new System.Random(seed).NextBytes(bytes);
        return bytes;
    }

    /// <summary>A trusted (OtherTrusted) signature result with a made-up signer, for heuristic contexts.</summary>
    public static SignatureCheckResult TrustedSignature() =>
        SignatureCheckResult.Trusted(SignatureStatus.OtherTrusted, SignatureKind.Embedded,
            new SignatureSigner([new SignatureCertificate("CN=Contoso", "CN=Contoso CA", new string('A', 40), new string('A', 64))], null));

    public static SignatureCheckResult Unsigned() => SignatureCheckResult.NotSigned();

    public static SignatureCheckResult Tampered() =>
        SignatureCheckResult.Invalid(SignatureFailureReason.HashMismatch, SignatureKind.Embedded, unchecked((int)0x80096010));
}
