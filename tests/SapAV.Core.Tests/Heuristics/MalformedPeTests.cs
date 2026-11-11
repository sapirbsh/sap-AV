using System.Buffers.Binary;
using SapAV.Core.Heuristics;
using SapAV.Core.Scanning;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Heuristics;

/// <summary>
/// A5 follow-up M2 (malformed-PE detection), M3 (entropy read budget), M7 (trusted self-extractor names) and L1 (bidi isolates).
/// Every image is a synthetic header layout built in memory and analysed in memory: no code, nothing written to disk.
/// </summary>
public sealed class MalformedPeTests
{
    private const string AppData = @"C:\Users\alice\AppData\Roaming\";

    private static readonly FileHeuristics Heuristics = new();

    private static HeuristicContext Unsigned => new(SyntheticPe.Unsigned());

    private static HeuristicContext Trusted => new(SyntheticPe.TrustedSignature());

    private static HeuristicKind[] Kinds(HeuristicResult r) => r.Findings.Select(f => f.Kind).ToArray();

    private static HeuristicResult Analyze(byte[] content, string name, HeuristicContext context, FileHeuristics? heuristics = null)
    {
        string path = name.Contains('\\') ? name : SyntheticPe.FakeTempPath(name);
        var result = (heuristics ?? Heuristics).Analyze(content, path, context);
        Assert.True(result.ContentInspected, result.ContentError);
        return result;
    }

    /// <summary>
    /// A header-only image of <paramref name="length"/> bytes: "MZ", e_lfanew, "PE\0\0", the file header and the optional header's
    /// magic and SizeOfHeaders, then one table entry per <paramref name="sections"/> item (parts past the array are left out).
    /// <paramref name="declaredSections"/> overrides the section count in the header.
    /// </summary>
    private static byte[] Image(int length, (int Offset, int Size)[] sections, int peOffset = 0x40, int optionalSize = 0xF0,
        uint sizeOfHeaders = 0x400, int? declaredSections = null, bool peSignature = true)
    {
        var image = new byte[length];
        var s = image.AsSpan();
        s[0] = (byte)'M';
        s[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(s[0x3C..], peOffset);
        if (peOffset + 24 + 64 <= length)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(s[peOffset..], peSignature ? 0x00004550u : 0u);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(peOffset + 4)..], 0x8664);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(peOffset + 6)..], (ushort)(declaredSections ?? sections.Length));
            BinaryPrimitives.WriteUInt16LittleEndian(s[(peOffset + 20)..], (ushort)optionalSize);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(peOffset + 22)..], 0x0022);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(peOffset + 24)..], 0x020B);
            BinaryPrimitives.WriteUInt32LittleEndian(s[(peOffset + 24 + 60)..], sizeOfHeaders);
        }

        int table = peOffset + 24 + optionalSize;
        for (int i = 0; i < sections.Length && table + (40 * i) + 40 <= length; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(s[(table + (40 * i) + 16)..], sections[i].Size);
            BinaryPrimitives.WriteInt32LittleEndian(s[(table + (40 * i) + 20)..], sections[i].Offset);
        }

        return image;
    }

    private static void FillRandom(byte[] image, int offset, int count) => SyntheticPe.Random(count).CopyTo(image, offset);

    // ---- M2: headers that used to make the file "not a PE" ----

    [Fact]
    public void MoreThan96Sections_IsMalformed_AndTheOtherRulesStillRun()
    {
        var image = Image(0x8000 + 0x10000, [.. Enumerable.Repeat((0x8000, 0x10000), 120)], sizeOfHeaders: 0x8000);
        FillRandom(image, 0x8000, 0x10000);

        var result = Analyze(image, "tool.exe", Unsigned);

        var malformed = Assert.Single(result.Findings, f => f.Kind == HeuristicKind.MalformedExecutable);
        Assert.Equal(FileHeuristics.MalformedScore, malformed.Score);
        Assert.Contains("120 sections", malformed.Reason);
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(result)); // the 120-entry table was read, not dropped
        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(result));
    }

    [Fact]
    public void PeHeaderPast4072_ButInside64KiB_IsParsed_InTwoReads()
    {
        const int pe = 0x3000; // e_lfanew 12288: past the first 4 KiB read
        var image = Image(0x4000 + 0x10000, [(0x4000, 0x10000)], peOffset: pe, sizeOfHeaders: 0x4000);
        FillRandom(image, 0x4000, 0x10000);

        Assert.Equal(pe + 24 + 64, PeHeaders.HeaderBytesNeeded(image.AsSpan(0, PeHeaders.HeaderReadSize), image.Length)); // round 1
        Assert.Equal(0x4000, PeHeaders.HeaderBytesNeeded(image.AsSpan(0, pe + 24 + 64), image.Length));                // round 2

        var result = Analyze(image, "tool.exe", Unsigned);
        Assert.DoesNotContain(HeuristicKind.MalformedExecutable, Kinds(result));
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(result));
    }

    [Fact]
    public void SectionTablePast4KiB_IsRead_UpToSizeOfHeaders()
    {
        // A 0x1400-byte optional header puts the section table at 0x1458, past the first 4 KiB.
        var image = Image(0x2000 + 0x10000, [(0x2000, 0x10000)], optionalSize: 0x1400, sizeOfHeaders: 0x2000);
        FillRandom(image, 0x2000, 0x10000);

        var probe = PeHeaders.Probe(image.AsSpan(0, PeHeaders.HeaderReadSize), image.Length);
        Assert.Equal("a section table past the headers read", probe.Malformed); // what a 4 KiB-only reader would see

        var result = Analyze(image, "tool.exe", Unsigned);
        Assert.DoesNotContain(HeuristicKind.MalformedExecutable, Kinds(result));
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(result));
    }

    [Fact]
    public void MzWithoutPeSignature_IsMalformed_AndKeepsTheUnsignedAndRandomNameRules()
    {
        var image = Image(0x2000, [], peSignature: false);

        var result = Analyze(image, AppData + "xk3j9qz7.exe", Unsigned);

        Assert.Contains(result.Findings, f => f.Kind == HeuristicKind.MalformedExecutable && f.Reason.Contains("without a PE signature"));
        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(result));
        Assert.Contains(HeuristicKind.RandomNameAppDataExecutable, Kinds(result));
        Assert.Contains(HeuristicKind.RiskyFolderExecutable, Kinds(result));
        Assert.True(result.IsSuspicious);
        Assert.Equal(Core.Models.Verdict.Suspicious, result.Detection!.Verdict); // heuristics alone: never Malicious
    }

    [Fact]
    public void PeHeaderPast64KiB_IsMalformed_WithoutReadingThatFar()
    {
        var image = Image(0x20000, [], peOffset: 0x18000); // header fields land past the array cap of the reader

        var result = Analyze(image, "tool.dll", Unsigned);

        Assert.Contains(result.Findings, f => f.Kind == HeuristicKind.MalformedExecutable && f.Reason.Contains("past the first 64 KiB"));
        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(result));
    }

    [Fact]
    public void ImageExtension_WithoutMz_IsStillAnImage_ButNotMalformed()
    {
        byte[] text = "not an image at all, only text"u8.ToArray();

        var exe = Analyze(text, "tool.exe", Unsigned);
        Assert.Contains(HeuristicKind.UnsignedExecutable, Kinds(exe));
        Assert.DoesNotContain(HeuristicKind.MalformedExecutable, Kinds(exe));

        Assert.DoesNotContain(HeuristicKind.UnsignedExecutable, Kinds(Analyze(text, "notes.txt", Unsigned))); // control
    }

    [Fact]
    public void TrustedSignedMalformedImage_GetsNoMalformedPoints()
    {
        var image = Image(0x8000 + 0x1000, [.. Enumerable.Repeat((0x8000, 0x1000), 120)], sizeOfHeaders: 0x8000);

        Assert.Contains(HeuristicKind.MalformedExecutable, Kinds(Analyze(image, "tool.exe", Unsigned))); // control
        Assert.Empty(Analyze(image, "tool.exe", Trusted).Findings);
    }

    [Fact]
    public void HostileHeaderValues_NeverThrow_AndStayInsideTheCap()
    {
        foreach (uint lfanew in new uint[] { 0, 0x3F, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFC, 0xFFFF })
        {
            foreach (int length in new[] { 0x40, 0x1000, 0x20000 })
            {
                var image = Image(length, [], sizeOfHeaders: uint.MaxValue, declaredSections: ushort.MaxValue);
                BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x3C), lfanew);
                var head = image.AsSpan(0, Math.Min(length, PeHeaders.HeaderReadSize));

                int needed = PeHeaders.HeaderBytesNeeded(head, length);
                Assert.InRange(needed, head.Length, PeHeaders.MaxHeaderReadSize);
                Assert.True(PeHeaders.Probe(head, length).IsMz);
                Assert.Equal(head.Length, PeHeaders.HeaderBytesNeeded(head, fileLength: 0)); // a head longer than the file: no throw
                Analyze(image, "tool.exe", Unsigned);
            }
        }

        // A valid PE header claiming 65535 sections and SizeOfHeaders 4 GiB: the read stops at 64 KiB.
        var huge = Image(0x20000, [], sizeOfHeaders: uint.MaxValue, declaredSections: ushort.MaxValue);
        Assert.Equal(PeHeaders.MaxHeaderReadSize, PeHeaders.HeaderBytesNeeded(huge.AsSpan(0, PeHeaders.HeaderReadSize), huge.Length));
        Assert.Contains(HeuristicKind.MalformedExecutable, Kinds(Analyze(huge, "tool.exe", Unsigned)));
    }

    // ---- M3: entropy reads ----

    [Fact]
    public void MergeRanges_JoinsOverlappingTouchingAndDuplicateRanges()
    {
        var merged = FileHeuristics.MergeRanges([(100, 50), (0, 10), (100, 50), (120, 100), (10, 5), (400, 0), (300, 1)]);

        Assert.Equal([(0L, 15L), (100L, 120L), (300L, 1L)], merged);
    }

    [Fact]
    public void ThousandsOfDuplicateSections_AreReadOnce()
    {
        const int data = 0x10000;
        var image = Image(data + 0x10000, [.. Enumerable.Repeat((data, 0x10000), 1500)], sizeOfHeaders: data);
        FillRandom(image, data, 0x10000);

        var pe = PeHeaders.TryParse(image.AsSpan(0, data), image.Length)!;
        Assert.Equal(1500, pe.SectionData.Count);
        Assert.Equal([(64L * 1024, 64L * 1024)], FileHeuristics.MergeRanges(pe.SectionData)); // 64 KiB read, not 1500 x 64 KiB
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(Analyze(image, "tool.exe", Unsigned)));
    }

    [Fact]
    public void EntropySample_StopsAtTheReadBudget()
    {
        // 64 KiB of random bytes, then 448 KiB of zeros in the same section: high entropy only if the read stops after 64 KiB.
        var image = Image(0x400 + 0x80000, [(0x400, 0x80000)]);
        FillRandom(image, 0x400, 0x10000);

        Assert.Equal(16L * 1024 * 1024, Heuristics.EntropySampleBudget);
        Assert.DoesNotContain(HeuristicKind.HighEntropyExecutable, Kinds(Analyze(image, "tool.exe", Unsigned)));
        var budgeted = new FileHeuristics { EntropySampleBudget = 0x10000 };
        Assert.Contains(HeuristicKind.HighEntropyExecutable, Kinds(Analyze(image, "tool.exe", Unsigned, budgeted)));
    }

    // ---- M7: self-extractor names ----

    [Theory]
    [InlineData(".7z.exe", true)]
    [InlineData(".zip.exe", true)]
    [InlineData(".RAR.EXE", true)]
    [InlineData(".zip.scr", false)]
    [InlineData(".pdf.exe", false)]
    public void IsArchiveDecoy_OnlyArchiveThenExe(string doubleExtension, bool expected) =>
        Assert.Equal(expected, FileNameRules.IsArchiveDecoy(doubleExtension));

    [Fact]
    public void ArchiveDoubleExtension_CountsOnlyWhenNotTrustedSigned()
    {
        byte[] content = "self-extractor stand-in"u8.ToArray();

        Assert.DoesNotContain(HeuristicKind.DoubleExtension, Kinds(Analyze(content, "setup.7z.exe", Trusted)));
        Assert.DoesNotContain(HeuristicKind.DoubleExtension, Kinds(Analyze(content, "data.zip.exe", Trusted)));
        Assert.Contains(HeuristicKind.DoubleExtension, Kinds(Analyze(content, "data.zip.exe", Unsigned)));
        Assert.Contains(HeuristicKind.DoubleExtension, Kinds(Analyze(content, "data.zip.exe", HeuristicContext.None)));
        Assert.Contains(HeuristicKind.DoubleExtension, Kinds(Analyze(content, "data.zip.scr", Trusted)));
        Assert.Contains(HeuristicKind.DoubleExtension, Kinds(Analyze(content, "invoice.pdf.exe", Trusted)));
    }

    // ---- L1: bidi controls ----

    [Theory]
    [InlineData('\u202A')]
    [InlineData('\u202B')]
    [InlineData('\u202D')]
    [InlineData('\u202E')]
    [InlineData('\u2066')]
    [InlineData('\u2067')]
    [InlineData('\u2069')]
    public void BidiOverrideAndIsolateCharacters_AreFlagged(char bidi)
    {
        string name = "invoice" + bidi + "fdp.exe";
        Assert.True(FileNameRules.HasRightToLeftOverride(name));

        var finding = Assert.Single(Analyze("x"u8.ToArray(), name, Trusted).Findings);
        Assert.Equal(HeuristicKind.RightToLeftOverride, finding.Kind);
        Assert.Contains("bidirectional override or isolate", finding.Reason);
    }

    [Fact]
    public void OrdinaryUnicodeNames_AreNotBidiMasquerading()
    {
        Assert.False(FileNameRules.HasRightToLeftOverride("\u05D7\u05E9\u05D1\u05D5\u05E0\u05D9\u05EA.pdf")); // Hebrew text, no controls
        Assert.False(FileNameRules.HasRightToLeftOverride("report\u200E.pdf"));                              // LRM is a mark, not an override
    }

    [Fact]
    public void DetectionLogicVersion_WasRaisedForTheseRules() => Assert.True(DetectionLogic.Version >= 3);
}
