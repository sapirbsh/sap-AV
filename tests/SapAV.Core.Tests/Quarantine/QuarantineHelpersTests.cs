using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Models;
using SapAV.Core.Quarantine;

namespace SapAV.Core.Tests.Quarantine;

public sealed class QuarantineHelpersTests
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Transform_IsReversible_InAnyChunking_AndHidesTheContent()
    {
        var key = QuarantineContentTransform.CreateKey();
        var original = new byte[3 * QuarantineContentTransform.KeyLength + 123];
        Encoding.ASCII.GetBytes("MZ This program cannot be run in DOS mode").CopyTo(original, 0);

        var whole = (byte[])original.Clone();
        QuarantineContentTransform.Apply(key, whole, 0);
        var chunked = (byte[])original.Clone();
        for (int offset = 0; offset < chunked.Length; offset += 1000)
        {
            int n = Math.Min(1000, chunked.Length - offset);
            QuarantineContentTransform.Apply(key, chunked.AsSpan(offset, n), offset);
        }

        Assert.Equal(whole, chunked);
        Assert.Equal(-1, whole.AsSpan().IndexOf("This program"u8));
        QuarantineContentTransform.Apply(key, whole, 0);
        Assert.Equal(original, whole);
    }

    [Fact]
    public void Transform_KeysAreRandom_AndHeaderRoundTrips()
    {
        Assert.NotEqual(QuarantineContentTransform.CreateKey(), QuarantineContentTransform.CreateKey());
        Assert.Throws<ArgumentException>(() => QuarantineContentTransform.Apply(new byte[16], new byte[4], 0));

        var header = new byte[QuarantineContentTransform.HeaderLength];
        QuarantineContentTransform.WriteHeader(header, 12345);
        Assert.True(QuarantineContentTransform.TryReadHeader(header, out long length));
        Assert.Equal(12345, length);
        header[0] = (byte)'M';
        Assert.False(QuarantineContentTransform.TryReadHeader(header, out _));
    }

    [Fact]
    public void Codec_RoundTrips()
    {
        var metadata = Sample();
        var decoded = QuarantineMetadataCodec.Decode(QuarantineMetadataCodec.Encode(metadata, Key), metadata.Id, Key);

        Assert.Equal(metadata.OriginalPath, decoded.OriginalPath);
        Assert.Equal(metadata.TransformKey, decoded.TransformKey);
        Assert.Equal(metadata.ZoneIdentifier, decoded.ZoneIdentifier);
        Assert.Equal(metadata.LastWriteTimeUtc, decoded.LastWriteTimeUtc);
        Assert.Equal(metadata.Reasons, decoded.Reasons);
    }

    [Fact]
    public void Codec_RefusesAnyChangedByte_OtherId_OrOtherKey()
    {
        var metadata = Sample();
        var file = QuarantineMetadataCodec.Encode(metadata, Key);
        string text = Encoding.UTF8.GetString(file);
        int at = text.IndexOf("\"payload\":\"", StringComparison.Ordinal) + 20;
        var flipped = Encoding.UTF8.GetBytes(text[..at] + (text[at] == 'A' ? 'B' : 'A') + text[(at + 1)..]);

        Assert.Equal(QuarantineMetadataError.Tampered,
            Assert.Throws<QuarantineMetadataException>(() => QuarantineMetadataCodec.Decode(flipped, metadata.Id, Key)).Error);
        Assert.Equal(QuarantineMetadataError.Tampered,
            Assert.Throws<QuarantineMetadataException>(() => QuarantineMetadataCodec.Decode(file, QuarantineItemId.New(), Key)).Error);
        Assert.Equal(QuarantineMetadataError.Tampered,
            Assert.Throws<QuarantineMetadataException>(() => QuarantineMetadataCodec.Decode(file, metadata.Id, RandomNumberGenerator.GetBytes(32))).Error);
        Assert.Equal(QuarantineMetadataError.Malformed,
            Assert.Throws<QuarantineMetadataException>(() => QuarantineMetadataCodec.Decode("{}"u8, metadata.Id, Key)).Error);
    }

    [Fact]
    public void Codec_RefusesInvalidMetadata_OnWrite()
    {
        Assert.Throws<InvalidDataException>(() => QuarantineMetadataCodec.Encode(Sample() with { OriginalPath = @"\\server\share\x.exe" }, Key));
        Assert.Throws<InvalidDataException>(() => QuarantineMetadataCodec.Encode(Sample() with { Verdict = Verdict.Clean }, Key));
        Assert.Throws<InvalidDataException>(() => QuarantineMetadataCodec.Encode(Sample() with { State = QuarantineState.Restoring }, Key)); // no temp name
        Assert.Throws<ArgumentException>(() => QuarantineMetadataCodec.Encode(Sample(), new byte[8]));
    }

    [Theory]
    [InlineData(@"C:\Users\u\Downloads\a.exe", true)]
    [InlineData(@"C:\a.exe", true)]
    [InlineData(@"C:\dir\name with trailing dot.", true)]
    [InlineData(@"\\server\share\a.exe", false)]
    [InlineData(@"\\?\C:\a.exe", false)]
    [InlineData(@"C:\dir\..\Windows\a.exe", false)]
    [InlineData(@"C:\dir\a.exe:stream", false)]
    [InlineData(@"C:\dir\\a.exe", false)]
    [InlineData(@"relative\a.exe", false)]
    public void OriginalPath_Validation(string path, bool valid) =>
        Assert.Equal(valid, QuarantinePath.TryValidateOriginalPath(path, out _));

    [Theory]
    [InlineData("report.pdf.exe", 0, "report.pdf.exe")]
    [InlineData("report.pdf.exe", 2, "report.pdf (restored 2).exe")]
    [InlineData("README", 1, "README (restored 1)")]
    [InlineData(".hidden", 1, ".hidden (restored 1)")]
    public void RestoredName_InsertsSuffixBeforeExtension(string name, int n, string expected) =>
        Assert.Equal(expected, QuarantinePath.RestoredName(name, n));

    private static QuarantineMetadata Sample() => new()
    {
        Id = QuarantineItemId.New(),
        State = QuarantineState.Quarantined,
        MoveKind = QuarantineMoveKind.SameVolume,
        OriginalPath = @"C:\Users\u\Downloads\invoice.pdf.exe",
        ScannedPath = @"C:\Users\u\Downloads\invoice.pdf.exe",
        SizeBytes = 68,
        Sha256 = new string('a', 64),
        SourceVolumeSerial = 0x1234,
        SourceFileId = QuarantineItemId.New(),
        Attributes = (int)FileAttributes.Archive,
        CreationTimeUtc = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
        LastWriteTimeUtc = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero).AddTicks(7),
        LastAccessTimeUtc = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
        SecurityDescriptor = "O:BAG:SYD:(A;;FA;;;SY)",
        ZoneIdentifier = "[ZoneTransfer]\r\nZoneId=3\r\n"u8.ToArray(),
        Verdict = Verdict.Malicious,
        Reasons = ["YARA rule X matched"],
        TechniqueIds = ["T1204.002"],
        Trigger = ScanTrigger.RealTime,
        ScanTimestamp = DateTimeOffset.UnixEpoch,
        QuarantinedAtUtc = DateTimeOffset.UnixEpoch,
        TransformAlgorithm = QuarantineContentTransform.Algorithm,
        TransformKey = QuarantineContentTransform.CreateKey(),
    };
}
