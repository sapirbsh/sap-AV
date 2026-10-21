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
    public void Urls_AreSanitized(string raw, string? expected)
    {
        var mark = MarkOfTheWeb.Parse(Encoding.UTF8.GetBytes($"[ZoneTransfer]\nZoneId=3\nHostUrl={raw}\n"));

        Assert.Equal(expected, mark.HostUrl);
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
        var exe = _dir.WriteFile("tool.exe", SyntheticPe.Build(new byte[8192]));
        var doc = _dir.WriteFile("notes.txt", "hello"u8.ToArray());

        var hit = heuristics.Analyze(exe, new HeuristicContext(MarkOfTheWeb: internet));
        var finding = Assert.Single(hit.Findings, f => f.Kind == HeuristicKind.InternetOrigin);
        Assert.Contains("cdn.example.com", finding.Reason);

        Assert.DoesNotContain(heuristics.Analyze(exe, new HeuristicContext(MarkOfTheWeb: trustedZone)).Findings, f => f.Kind == HeuristicKind.InternetOrigin);
        Assert.DoesNotContain(heuristics.Analyze(doc, new HeuristicContext(MarkOfTheWeb: internet)).Findings, f => f.Kind == HeuristicKind.InternetOrigin);
        Assert.DoesNotContain(heuristics.Analyze(exe, new HeuristicContext(SyntheticPe.TrustedSignature(), internet)).Findings,
            f => f.Kind == HeuristicKind.InternetOrigin);
    }
}
