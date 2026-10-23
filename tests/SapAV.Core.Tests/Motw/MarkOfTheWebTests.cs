using System.Text;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Motw;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Motw;

/// <summary>Mark-of-the-Web: parsing the Zone.Identifier stream and reading it through the hardened open path.</summary>
public sealed class MarkOfTheWebTests : IDisposable
{
    private const string Typical =
        "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/downloads\r\nHostUrl=https://cdn.example.com/setup.exe\r\n";

    private readonly TempDirectory _dir = new();
    private readonly MarkOfTheWebReader _reader = new();

    public void Dispose() => _dir.Dispose();

    private string FileWithMotw(string name, string? zoneIdentifier)
    {
        var path = _dir.WriteFile(name, [1, 2, 3]);
        if (zoneIdentifier is not null)
        {
            File.WriteAllText(path + ":Zone.Identifier", zoneIdentifier);
        }

        return path;
    }

    // --- Parsing ---

    [Fact]
    public void Parse_TypicalBrowserDownload()
    {
        var mark = MarkOfTheWeb.Parse(Encoding.ASCII.GetBytes(Typical));

        Assert.Equal(SecurityZone.Internet, mark.Zone);
        Assert.Equal(3, mark.RawZoneId);
        Assert.Equal("https://cdn.example.com/setup.exe", mark.HostUrl);
        Assert.Equal("https://example.com/downloads", mark.ReferrerUrl);
        Assert.True(mark.IsFromInternet);
    }

    [Fact]
    public void Parse_IsLenient_CaseInsensitive_Utf16Bom_OtherSectionsIgnored()
    {
        var text = "[Other]\nZoneId=0\n[zonetransfer]\n  zoneid = 4 \nhosturl=https://x.test/a\n";
        var mark = MarkOfTheWeb.Parse([0xFF, 0xFE, .. Encoding.Unicode.GetBytes(text)]);

        Assert.Equal(SecurityZone.Restricted, mark.Zone);
        Assert.Equal("https://x.test/a", mark.HostUrl);
        Assert.True(mark.IsFromInternet);
    }

    [Theory]
    [InlineData("[ZoneTransfer]\nZoneId=7\n", 7)]
    [InlineData("[ZoneTransfer]\nZoneId=abc\n", null)]
    [InlineData("ZoneId=3\n", null)] // no section header
    [InlineData("", null)]
    public void Parse_UnknownOrMissingZone_IsNotInternet(string text, int? rawZone)
    {
        var mark = MarkOfTheWeb.Parse(Encoding.ASCII.GetBytes(text));

        Assert.Null(mark.Zone);
        Assert.Equal(rawZone, mark.RawZoneId);
        Assert.False(mark.IsFromInternet);
    }

    [Theory]
    [InlineData("https://user:secret@host.test/x.exe", "https://***@host.test/x.exe")]
    [InlineData("https://host.test/a@b.exe", "https://host.test/a@b.exe")] // '@' in the path is not user info
    [InlineData("https://host.test/\u0007x\u202Eexe.pdf", "https://host.test/xexe.pdf")]
    [InlineData("\u0001\u0002", null)]
    [InlineData("https://host.test/a\u2028b\u2029.exe", "https://host.test/ab.exe")]
    [InlineData(@"https://evil.test\@good.test/x.exe", @"https://evil.test\@good.test/x.exe")] // '\' ends the authority
    [InlineData(@"https://u:p@evil.test\x.exe", @"https://***@evil.test\x.exe")]
    public void Urls_AreSanitized(string raw, string? expected)
    {
        var mark = MarkOfTheWeb.Parse(Encoding.UTF8.GetBytes($"[ZoneTransfer]\nZoneId=3\nHostUrl={raw}\n"));

        Assert.Equal(expected, mark.HostUrl);
    }

    [Theory]
    [InlineData("https://cdn.test/setup.exe?X-Amz-Signature=abc&token=s3cr3t", "https://cdn.test/setup.exe")]
    [InlineData("https://cdn.test/setup.exe#access_token=s3cr3t", "https://cdn.test/setup.exe")]
    [InlineData("https://user:pw@cdn.test/a.exe?sig=1", "https://***@cdn.test/a.exe")]
    [InlineData(@"https://evil.test\@good.test/a.exe?sig=1", @"https://evil.test\@good.test/a.exe")]
    [InlineData("https://cdn.test/a\u2028.exe", "https://cdn.test/a.exe")]
    [InlineData("?only-a-query", null)]
    [InlineData(null, null)]
    public void SanitizeUrlForLog_StripsQueryAndFragment_KeepsRedaction(string? raw, string? expected)
    {
        var once = MarkOfTheWeb.SanitizeUrlForLog(raw);

        Assert.Equal(expected, once);
        Assert.Equal(once, MarkOfTheWeb.SanitizeUrlForLog(once)); // idempotent
    }

    [Fact]
    public void Urls_AreCapped()
    {
        var mark = MarkOfTheWeb.Parse(Encoding.ASCII.GetBytes("[ZoneTransfer]\nHostUrl=https://h.test/" + new string('a', 5000)));

        Assert.Equal(MarkOfTheWeb.MaxUrlLength, mark.HostUrl!.Length);
    }

    // --- Reading from a file ---

    [Fact]
    public void Read_WrittenZoneIdentifier_RoundTrips()
    {
        var path = FileWithMotw("setup.exe", Typical);

        var result = _reader.Read(path);

        Assert.Equal(MarkOfTheWebStatus.Present, result.Status);
        Assert.Equal(SecurityZone.Internet, result.Mark!.Zone);
        Assert.Equal("https://cdn.example.com/setup.exe", result.Mark.HostUrl);
        Assert.Equal("https://example.com/downloads", result.Mark.ReferrerUrl);
    }

    [Fact]
    public void Read_ExtendedLengthPath_Works()
    {
        var path = FileWithMotw("setup.exe", Typical);

        Assert.Equal(MarkOfTheWebStatus.Present, _reader.Read(@"\\?\" + path).Status);
    }

    [Fact]
    public void Read_FileWithoutStream_IsAbsent()
    {
        var result = _reader.Read(FileWithMotw("local.exe", null));

        Assert.Equal(MarkOfTheWebStatus.Absent, result.Status);
        Assert.Null(result.Mark);
    }

    [Fact]
    public void Read_OfflineFile_StillReadsTheMark()
    {
        var path = FileWithMotw("cloud.exe", Typical);
        File.SetAttributes(path, FileAttributes.Offline);
        try
        {
            Assert.Equal(MarkOfTheWebStatus.Present, _reader.Read(path).Status);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    [Theory]
    [InlineData("a.txt:Zone.Identifier")]
    [InlineData("a.txt:evil")]
    public void Read_PathNamingAStream_IsInvalidPath(string name)
    {
        FileWithMotw("a.txt", Typical);

        var result = _reader.Read(_dir.File(name));

        Assert.Equal(HashFailureReason.InvalidPath, result.NotReadReason);
    }

    [Theory]
    [InlineData(@"\\.\NUL", HashFailureReason.NotRegularFile)]
    [InlineData("CON", HashFailureReason.NotRegularFile)]
    public void Read_Devices_AreNotRead(string path, HashFailureReason expected)
    {
        Assert.Equal(expected, _reader.Read(path).NotReadReason);
    }

    [Fact]
    public async Task Read_NamedPipe_IsNeverOpened()
    {
        await using var probe = new PipeProbe();

        var result = _reader.Read(probe.Path);

        Assert.Equal(HashFailureReason.NotRegularFile, result.NotReadReason);
        Assert.False(await probe.WasConnectedAsync());
    }

    [Fact]
    public void Read_DirectoryAndMissingFile_AreNotRead()
    {
        Assert.Equal(HashFailureReason.Directory, _reader.Read(_dir.Path).NotReadReason);
        Assert.Equal(HashFailureReason.NotFound, _reader.Read(_dir.File("missing.exe")).NotReadReason);
    }

    [Fact]
    public void ReadFromHandle_UsesTheOpenFile_EvenAfterThePathIsSwapped()
    {
        var path = FileWithMotw("swap.exe", Typical);
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        // Swap the path: the original is renamed away, a new file with a different mark takes its place.
        File.Move(path, _dir.File("moved.exe"));
        File.WriteAllBytes(path, [9]);
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\nZoneId=0\n");

        var fromHandle = _reader.Read(handle);
        Assert.Equal(SecurityZone.Internet, fromHandle.Mark!.Zone); // the stream of the file we opened
        Assert.Equal(SecurityZone.LocalMachine, _reader.Read(path).Mark!.Zone); // the path now names the new file
    }

    [Fact]
    public void ReadFromHandle_WithoutStream_IsAbsent()
    {
        using var handle = File.OpenHandle(FileWithMotw("plain.exe", null));

        Assert.Equal(MarkOfTheWebStatus.Absent, _reader.Read(handle).Status);
    }
    // --- Heuristic signal ---

    [Fact]
    public void InternetOrigin_CountsForUntrustedExecutables_Only()
    {
        var heuristics = new FileHeuristics();
        var internet = MarkOfTheWeb.Parse(Encoding.ASCII.GetBytes(Typical));
        var trustedZone = MarkOfTheWeb.Parse("[ZoneTransfer]\nZoneId=2\n"u8);
        // In memory (same rule code as the handle path), so a real antivirus can't block the synthetic PE.
        var exe = (Name: "tool.exe", Bytes: SyntheticPe.Build(new byte[8192]));
        var doc = (Name: "notes.txt", Bytes: "hello"u8.ToArray());

        // Every call must really inspect the content (a blocked read would leave only name rules and pass vacuously).
        HeuristicResult Inspect((string Name, byte[] Bytes) file, HeuristicContext context)
        {
            var r = heuristics.Analyze(file.Bytes, SyntheticPe.FakeTempPath(file.Name), context);
            Assert.True(r.ContentInspected, $"{file.Name}: content not inspected ({r.ContentError}).");
            return r;
        }

        var hit = Inspect(exe, new HeuristicContext(MarkOfTheWeb: internet));
        var finding = Assert.Single(hit.Findings, f => f.Kind == HeuristicKind.InternetOrigin);
        Assert.Contains("cdn.example.com", finding.Reason);

        var trusted = Inspect(exe, new HeuristicContext(SyntheticPe.Unsigned(), trustedZone));
        Assert.Contains(trusted.Findings, f => f.Kind == HeuristicKind.UnsignedExecutable); // control: the PE was parsed
        Assert.DoesNotContain(trusted.Findings, f => f.Kind == HeuristicKind.InternetOrigin);
        Assert.DoesNotContain(Inspect(doc, new HeuristicContext(MarkOfTheWeb: internet)).Findings, f => f.Kind == HeuristicKind.InternetOrigin);

        var signed = Inspect(exe, new HeuristicContext(SyntheticPe.TrustedSignature(), internet));
        Assert.DoesNotContain(signed.Findings, f => f.Kind == HeuristicKind.InternetOrigin);
        var tampered = Inspect(exe, new HeuristicContext(SyntheticPe.Tampered(), internet));
        Assert.Contains(tampered.Findings, f => f.Kind == HeuristicKind.InternetOrigin); // control: a broken signature isn't trusted
    }
}
