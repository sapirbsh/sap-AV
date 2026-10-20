using System.Buffers.Binary;
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
