using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Tests.Yara;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Scanning;

/// <summary>
/// H1 (section A review): the pipeline reads one file handle, so swapping the path between steps can't change what
/// a later step judges; writers are denied during the scan; and the shared fallback detects changes via the USN.
/// </summary>
public sealed class FileScannerSingleHandleTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly YaraRuleSet _rules = YaraTestRules.MarkerSet();

    public void Dispose()
    {
        _rules.Dispose();
        _dir.Dispose();
    }

    private FileScanner Scanner(ISignatureVerifier? verifier = null, Action<SafeFileHandle>? afterOpen = null) =>
        new(new Sha256Hasher(), () => HashBlocklist.Empty, verifier ?? new AuthenticodeVerifier(), new YaraScanner(_rules),
            new MarkOfTheWebReader(), new FileHeuristics())
        { AfterOpenHook = afterOpen };

    /// <summary>Swaps the path right before the signature step, then checks the signature of the handle it is given.</summary>
    private sealed class SwappingVerifier(Action swap) : ISignatureVerifier
    {
        private readonly AuthenticodeVerifier _inner = new();
        public long MaxSizeBytes => _inner.MaxSizeBytes;
        public SignatureCheckResult Verify(string path, CancellationToken cancellationToken = default) => throw new InvalidOperationException("The pipeline must not re-open the path.");

        public SignatureCheckResult Verify(SafeFileHandle handle, string displayPath, CancellationToken cancellationToken = default)
        {
            swap();
            return _inner.Verify(handle, displayPath, cancellationToken);
        }
    }

    private void SwapPathTo(string path, byte[] replacement)
    {
        File.Move(path, _dir.File("original-moved.bin")); // the scan handle shares delete, like any scanner should
        File.WriteAllBytes(path, replacement);
    }

    [Fact]
    public async Task PathSwappedBetweenSteps_LaterStepsStillJudgeTheOriginalFile()
    {
        var original = YaraTestRules.MarkerBytes();
        var path = _dir.WriteFile("tool.exe", original);

        var report = await Scanner(new SwappingVerifier(() => SwapPathTo(path, "harmless"u8.ToArray())))
            .ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.Equal(Verdict.Malicious, report.Result.Verdict); // YARA saw the original bytes, not the replacement
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(original)), report.Result.Sha256);
        Assert.Contains(report.Result.Detections, d => d.Source == DetectionSource.Yara);
    }

    [Fact]
    public async Task Report_CarriesTheIdentityOfTheScannedObject_EvenIfThePathIsSwappedDuringTheScan()
    {
        var path = _dir.WriteFile("ident.bin", YaraTestRules.MarkerBytes());

        var report = await Scanner(new SwappingVerifier(() => SwapPathTo(path, "harmless"u8.ToArray())))
            .ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.NotNull(report.Identity);
        Assert.Equal(Path.GetFullPath(path), report.Identity.FinalPath, ignoreCase: true);
        Assert.True(report.Identity.IsSameObject(Capture(_dir.File("original-moved.bin")))); // the object that was read
        Assert.False(report.Identity.IsSameObject(Capture(path)));                            // not the replacement
    }

    [Fact]
    public async Task UnopenableFile_HasNoIdentity()
    {
        var report = await Scanner().ScanAsync(new ScanItem(_dir.File("missing.bin"), ScanTrigger.CustomScan));

        Assert.Null(report.Identity);
    }

    private static FileIdentity? Capture(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return FileIdentity.TryCapture(handle);
    }

    [RequiresFact(Requires.NotepadRegularFile)]
    public async Task PathSwappedToAMicrosoftSignedFile_IsNotClean()
    {
        // The attack from the review: hash malware M, then swap the path to a Microsoft-signed file before the
        // signature step. With one handle the signature step checks M itself.
        var notepad = File.ReadAllBytes(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"));
        var path = _dir.WriteFile("update.exe", YaraTestRules.MarkerBytes());

        var report = await Scanner(new SwappingVerifier(() => SwapPathTo(path, notepad)))
            .ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.NotEqual(SignatureStatus.Microsoft, report.Result.SignatureStatus);
        Assert.Equal(Verdict.Malicious, report.Result.Verdict);
    }

    [Fact]
    public async Task DuringTheScan_NoOtherProgramCanOpenTheFileForWriting()
    {
        var path = _dir.WriteFile("doc.txt", "hello"u8.ToArray());
        Exception? writerError = null;

        var report = await Scanner(afterOpen: _ =>
        {
            try
            {
                using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            }
            catch (IOException ex)
            {
                writerError = ex;
            }
        }).ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.Equal(Verdict.Clean, report.Result.Verdict);
        Assert.IsAssignableFrom<IOException>(writerError);
        Assert.Equal(unchecked((int)0x80070020), writerError!.HResult); // ERROR_SHARING_VIOLATION

        using var afterwards = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); // released again
    }

    [RequiresFact(Requires.UsnJournal)]
    public async Task FileOpenByAWriter_IsScanned_WithTheChangeJournalCheck()
    {
        var path = _dir.WriteFile("downloading.txt", "partial"u8.ToArray());
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

        var report = await Scanner().ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.Equal(Verdict.Clean, report.Result.Verdict);
        Assert.Contains(report.Notes, n => n.Message.Contains("change-journal"));
    }

    [RequiresFact(Requires.UsnJournal)]
    public async Task SameSizeRewriteWithRestoredTimestamp_DuringASharedScan_IsNotScanned()
    {
        var path = _dir.WriteFile("swap-content.txt", "AAAAAAAAAA"u8.ToArray());
        var lastWrite = File.GetLastWriteTimeUtc(path);
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

        var report = await Scanner(afterOpen: _ =>
        {
            // Same size, timestamp put back: size + last-write checks alone can't see this.
            writer.Write("BBBBBBBBBB"u8);
            writer.Flush();
            File.SetLastWriteTimeUtc(writer.SafeFileHandle, lastWrite);
        }).ScanAsync(new ScanItem(path, ScanTrigger.CustomScan));

        Assert.Equal(ScanStatus.Error, report.Result.Status);
        Assert.Null(report.Result.Verdict);
        Assert.Contains(report.Notes, n => n.Message.Contains("changed during the scan"));
        Assert.Equal(10, new FileInfo(path).Length);
    }

    [Fact]
    public async Task HandleOverloads_GiveTheSameResultsAsThePathOverloads()
    {
        var path = _dir.WriteFile("same.exe", SyntheticPe.Build(SyntheticPe.Random(8192)));
        using var handle = File.OpenHandle(path);

        var hasher = new Sha256Hasher();
        Assert.Equal((await hasher.HashFileAsync(path)).Sha256, (await hasher.HashHandleAsync(handle)).Sha256);
        Assert.Equal(new AuthenticodeVerifier().Verify(path).Status, new AuthenticodeVerifier().Verify(handle, path).Status);
        Assert.Equal(new YaraScanner(_rules).ScanFile(path).IsScanned, new YaraScanner(_rules).ScanHandle(handle).IsScanned);
        var byPath = new FileHeuristics().Analyze(path, new HeuristicContext(SyntheticPe.Unsigned()));
        var byHandle = new FileHeuristics().Analyze(handle, path, new HeuristicContext(SyntheticPe.Unsigned()));
        Assert.True(byPath.ContentInspected && byHandle.ContentInspected, $"content not inspected: {byPath.ContentError} / {byHandle.ContentError}");
        Assert.Contains(byHandle.Findings, f => f.Kind == HeuristicKind.UnsignedExecutable); // the PE was parsed through the handle
        Assert.Equal(byPath.Findings.Select(f => (f.Kind, f.Score)), byHandle.Findings.Select(f => (f.Kind, f.Score)));
        Assert.Equal(new MarkOfTheWebReader().Read(path).Status, new MarkOfTheWebReader().Read(handle).Status);
    }
}
