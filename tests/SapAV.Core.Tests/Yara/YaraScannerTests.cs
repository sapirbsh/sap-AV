using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Yara;

/// <summary>File and buffer scanning through <see cref="YaraScanner"/>: the hardened open path, limits, changes, timeout.</summary>
public sealed class YaraScannerTests : IDisposable
{
    private static readonly TimeSpan Watchdog = TimeSpan.FromSeconds(60);
    private readonly TempDirectory _dir = new();
    private readonly YaraRuleSet _rules = YaraTestRules.MarkerSet();

    public void Dispose()
    {
        _rules.Dispose();
        _dir.Dispose();
    }

    /// <summary>Fails instead of hanging if a scan blocks on a device or pipe.</summary>
    private static YaraScanResult WithWatchdog(Func<YaraScanResult> scan)
    {
        var task = Task.Run(scan);
        Assert.True(task.Wait(Watchdog), "The scan did not finish in time");
        return task.Result;
    }

    // --- Regular files ---

    [Fact]
    public void FileWithMarker_Matches_ThroughTheMappedHandle()
    {
        var path = _dir.WriteFile("marker.txt", YaraTestRules.MarkerBytes());

        var result = new YaraScanner(_rules).ScanFile(path);

        Assert.True(result.IsScanned, result.ErrorMessage);
        Assert.Equal("Test_Marker", Assert.Single(result.Matches).Identifier);
        Assert.Equal(new FileInfo(path).Length, result.Length);
        Assert.Equal(_rules.Fingerprint, result.RulesFingerprint);
    }

    [Fact]
    public void FileWithoutMarker_IsScanned_WithNoMatches()
    {
        var path = _dir.WriteFile("clean.txt", "nothing to see here"u8.ToArray());

        var result = new YaraScanner(_rules).ScanFile(path);

        Assert.Equal(ScanStatus.Scanned, result.Status);
        Assert.Empty(result.Matches);
        Assert.Empty(result.Detections);
    }

    [Fact]
    public void ExtendedLengthPath_IsScanned()
    {
        var path = _dir.WriteFile("long-form.txt", YaraTestRules.MarkerBytes());

        Assert.Single(new YaraScanner(_rules).ScanFile(@"\\?\" + path).Matches);
    }

    [Fact]
    public void EmptyFile_IsScanned_AsAnEmptyBuffer()
    {
        var path = _dir.WriteFile("empty.bin", []);
        using var rules = YaraRuleSet.FromSource("empty.yar", "rule Empty_File { condition: filesize == 0 }");

        var result = new YaraScanner(rules).ScanFile(path);

        Assert.True(result.IsScanned, result.ErrorMessage);
        Assert.Equal(0, result.Length);
        Assert.Equal("Empty_File", Assert.Single(result.Matches).Identifier);
    }

    [Fact]
    public void FileAtTheLimit_IsScanned_OverTheLimit_IsTooLarge_WithoutReading()
    {
        var bytes = YaraTestRules.MarkerBytes();
        var path = _dir.WriteFile("limit.txt", bytes);

        Assert.True(new YaraScanner(_rules, maxSizeBytes: bytes.Length).ScanFile(path).IsScanned);

        bool reached = false;
        _rules.BeforeNativeScanHook = () => reached = true;
        var result = new YaraScanner(_rules, maxSizeBytes: bytes.Length - 1).ScanFile(path);

        Assert.Equal(YaraFailureReason.TooLarge, result.FailureReason);
        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Equal(bytes.Length, result.Length);
        Assert.False(reached, "an oversized file must not reach the engine");
        Assert.Equal(Sha256Hasher.DefaultMaxSizeBytes, new YaraScanner(_rules).MaxSizeBytes);
    }

    [Fact]
    public void BufferOverTheLimit_IsTooLarge()
    {
        var result = new YaraScanner(_rules, maxSizeBytes: 4).ScanMemory([1, 2, 3, 4, 5]);

        Assert.Equal(YaraFailureReason.TooLarge, result.FailureReason);
    }

    [Fact]
    public void FileModifiedDuringScan_IsChangedDuringScan()
    {
        var path = _dir.WriteFile("changing.txt", YaraTestRules.MarkerBytes());
        _rules.BeforeNativeScanHook = () => File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(5));

        var result = new YaraScanner(_rules).ScanFile(path);

        Assert.Equal(YaraFailureReason.ChangedDuringScan, result.FailureReason);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void FileGrownDuringScan_IsChangedDuringScan()
    {
        var path = _dir.WriteFile("growing.txt", YaraTestRules.MarkerBytes());
        _rules.BeforeNativeScanHook = () =>
        {
            using var w = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            w.Write(new byte[1000]);
        };

        Assert.Equal(YaraFailureReason.ChangedDuringScan, new YaraScanner(_rules).ScanFile(path).FailureReason);
    }

    [Fact]
    public void OfflineFile_IsSkippedOffline_WithoutScanning()
    {
        var path = _dir.WriteFile("offline.txt", YaraTestRules.MarkerBytes());
        File.SetAttributes(path, FileAttributes.Offline);
        try
        {
            var result = new YaraScanner(_rules).ScanFile(path);

            Assert.Equal(YaraFailureReason.Offline, result.FailureReason);
            Assert.Equal(ScanStatus.SkippedOffline, result.Status);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    [Fact]
    public void MissingFile_IsNotFound()
    {
        Assert.Equal(YaraFailureReason.NotFound, new YaraScanner(_rules).ScanFile(_dir.File("missing.bin")).FailureReason);
    }

    [Fact]
    public void LockedFile_IsLocked()
    {
        var path = _dir.WriteFile("locked.txt", YaraTestRules.MarkerBytes());
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var result = new YaraScanner(_rules).ScanFile(path);

        Assert.Equal(YaraFailureReason.Locked, result.FailureReason);
        Assert.Equal(ScanStatus.Locked, result.Status);
    }

    // --- Non-regular targets: never scanned, never thrown ---

    [Theory]
    [InlineData(@"\\.\NUL")]
    [InlineData("NUL")]
    [InlineData("CON")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\?\GLOBALROOT\Device\Null")]
    public void DevicePaths_AreNotRegularFile(string path)
    {
        var result = WithWatchdog(() => new YaraScanner(_rules).ScanFile(path));

        Assert.Equal(YaraFailureReason.NotRegularFile, result.FailureReason);
        Assert.Equal(ScanStatus.Error, result.Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("a\0b")]
    public void InvalidPaths_AreInvalidPath(string path)
    {
        Assert.Equal(YaraFailureReason.InvalidPath, new YaraScanner(_rules).ScanFile(path).FailureReason);
    }

    [Fact]
    public async Task NamedPipe_IsNotRegularFile_AndNeverOpened()
    {
        await using var probe = new PipeProbe();

        var result = WithWatchdog(() => new YaraScanner(_rules).ScanFile(probe.Path));

        Assert.Equal(YaraFailureReason.NotRegularFile, result.FailureReason);
        Assert.False(await probe.WasConnectedAsync());
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToNamedPipe_IsNotRegularFile_WithNothingWritten()
    {
        await using var probe = new PipeProbe();
        var link = _dir.File("looks-like-a-file.txt");
        File.CreateSymbolicLink(link, probe.Path);

        var result = WithWatchdog(() => new YaraScanner(_rules).ScanFile(link));

        Assert.Equal(YaraFailureReason.NotRegularFile, result.FailureReason);
        Assert.Equal(0, await probe.BytesWrittenByClientAsync());
    }

    [RequiresFact(Requires.PipeNamespaceJunction)]
    public void JunctionToPipeNamespace_IsRejectedAfterOpen_ByFileType()
    {
        var junc = _dir.File("j");
        Assert.Null(RawJunction.TryCreate(junc, @"\??\pipe\"));

        var result = WithWatchdog(() => new YaraScanner(_rules).ScanFile(junc));

        Assert.Equal(YaraFailureReason.NotRegularFile, result.FailureReason);
        Assert.Contains("file type", result.ErrorMessage);
    }

    [RequiresFact(Requires.Symlinks)]
    public void SymlinkToRegularFile_IsScannedAsTarget()
    {
        var target = _dir.WriteFile("target.txt", YaraTestRules.MarkerBytes());
        var link = _dir.File("link.txt");
        File.CreateSymbolicLink(link, target);

        Assert.Single(new YaraScanner(_rules).ScanFile(link).Matches);
    }

    [Fact]
    public void Directory_IsDirectory()
    {
        var result = new YaraScanner(_rules).ScanFile(_dir.Path);

        Assert.Equal(YaraFailureReason.Directory, result.FailureReason);
        Assert.Equal(ScanStatus.Error, result.Status);
    }

    // --- Crash safety: map only on local fixed volumes, otherwise read into a buffer ---

    [Fact]
    public void LocalFile_IsMapped_ExactlyWhenOnALocalFixedVolume()
    {
        var path = _dir.WriteFile("local.txt", YaraTestRules.MarkerBytes());
        bool? mapped = null;
        var scanner = new YaraScanner(_rules) { ScanModeHook = m => mapped = m };

        Assert.Single(scanner.ScanFile(path).Matches);

        using var handle = File.OpenHandle(path);
        Assert.Equal(NativeFile.IsOnLocalFixedVolume(handle), mapped);
    }

    [Fact]
    public void BufferedPath_FindsTheSameMatches_AndHasItsOwnLowerCap()
    {
        var bytes = YaraTestRules.MarkerBytes();
        var path = _dir.WriteFile("removable.txt", bytes);
        bool? mapped = null;

        var buffered = new YaraScanner(_rules) { ForceBufferedRead = true, ScanModeHook = m => mapped = m };
        Assert.Single(buffered.ScanFile(path).Matches);
        Assert.False(mapped);

        var capped = new YaraScanner(_rules, maxBufferedSizeBytes: bytes.Length - 1) { ForceBufferedRead = true };
        var result = capped.ScanFile(path);
        Assert.Equal(YaraFailureReason.TooLarge, result.FailureReason);
        Assert.Contains("not on a local fixed disk", result.ErrorMessage);
        Assert.Equal(YaraScanner.DefaultMaxBufferedSizeBytes, new YaraScanner(_rules).MaxBufferedSizeBytes);
    }

    [RequiresFact(Requires.AdminShare)]
    public void NetworkFile_IsNeverMapped()
    {
        var path = _dir.WriteFile("share.txt", YaraTestRules.MarkerBytes());
        var unc = $@"\\localhost\{path[0]}$" + path[2..];
        bool? mapped = null;

        var result = new YaraScanner(_rules) { ScanModeHook = m => mapped = m }.ScanFile(unc);

        Assert.Single(result.Matches);
        Assert.False(mapped);
    }

    // --- Timeout ---

    [Fact]
    public void SlowRule_TimesOut_AsNotScanned()
    {
        // A SHA-256 of 4 KiB at every offset of 1 MiB: about 4 GB hashed, far beyond the 1-second budget.
        using var slow = YaraRuleSet.FromSource("slow.yar",
            "import \"hash\" rule Slow { condition: for any i in (0..filesize) : (hash.sha256(i, 4096) == \"x\") }");
        var scanner = new YaraScanner(slow, timeout: TimeSpan.FromMilliseconds(10));
        Assert.Equal(1, scanner.TimeoutSeconds); // the engine's unit is whole seconds

        var result = WithWatchdog(() => scanner.ScanMemory(new byte[1024 * 1024]));

        Assert.Equal(YaraFailureReason.Timeout, result.FailureReason);
        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void Timeout_Validation()
    {
        Assert.Equal(30, new YaraScanner(_rules).TimeoutSeconds);
        Assert.Equal(0, new YaraScanner(_rules, timeout: Timeout.InfiniteTimeSpan).TimeoutSeconds);
        Assert.Equal(3, new YaraScanner(_rules, timeout: TimeSpan.FromSeconds(2.1)).TimeoutSeconds);
        Assert.Throws<ArgumentOutOfRangeException>(() => new YaraScanner(_rules, timeout: TimeSpan.Zero));
    }

    // --- Concurrency, dispose and reload ---

    [Fact]
    public void ConcurrentScans_WithOneSharedRuleSet_AllCorrect()
    {
        var hit = _dir.WriteFile("hit.txt", YaraTestRules.MarkerBytes());
        var miss = _dir.WriteFile("miss.txt", "clean"u8.ToArray());
        var scanner = new YaraScanner(_rules);
        int wrong = 0;

        Parallel.For(0, 2000, new ParallelOptions { MaxDegreeOfParallelism = 48 }, i =>
        {
            var result = (i % 3) switch
            {
                0 => scanner.ScanFile(hit),
                1 => scanner.ScanFile(miss),
                _ => scanner.ScanMemory(YaraTestRules.MarkerBytes()),
            };
            bool expectHit = i % 3 != 1;
            if (!result.IsScanned || result.Matches.Count != (expectHit ? 1 : 0))
            {
                Interlocked.Increment(ref wrong);
            }
        });

        Assert.Equal(0, wrong);
    }

    [Fact]
    public void DisposedRuleSet_ReturnsRulesDisposed_NotAnException()
    {
        var rules = YaraTestRules.MarkerSet();
        var scanner = new YaraScanner(rules);
        rules.Dispose();
        rules.Dispose(); // idempotent

        var result = scanner.ScanMemory(YaraTestRules.MarkerBytes());

        Assert.Equal(YaraFailureReason.RulesDisposed, result.FailureReason);
        Assert.True(rules.IsDisposed);
        Assert.True(rules.IsNativeReleased);
    }

    [Fact]
    public void DisposeDuringAScan_FreesNativeRulesOnlyAfterTheScanFinishes()
    {
        var rules = YaraTestRules.MarkerSet();
        bool releasedDuringScan = true;
        rules.BeforeNativeScanHook = () =>
        {
            rules.Dispose();
            releasedDuringScan = rules.IsNativeReleased;
        };

        var result = new YaraScanner(rules).ScanMemory(YaraTestRules.MarkerBytes());

        Assert.True(result.IsScanned, result.ErrorMessage);
        Assert.Single(result.Matches);
        Assert.False(releasedDuringScan, "native rules were freed while the engine was using them");
        Assert.True(rules.IsNativeReleased);
    }

    [Fact]
    public void SwapRules_ReloadsWithoutRestart_AndRetriesAScanThatLostTheRace()
    {
        var v1 = YaraRuleSet.FromSource("r.yar", YaraTestRules.MarkerRule("Version_1"));
        var scanner = new YaraScanner(v1);
        Assert.Equal("Version_1", Assert.Single(scanner.ScanMemory(YaraTestRules.MarkerBytes()).Matches).Identifier);

        using var v2 = YaraRuleSet.FromSource("r.yar", YaraTestRules.MarkerRule("Version_2"));
        var old = scanner.SwapRules(v2);
        Assert.Same(v1, old);
        old.Dispose();
        Assert.NotEqual(v1.Fingerprint, v2.Fingerprint);

        Assert.Equal("Version_2", Assert.Single(scanner.ScanMemory(YaraTestRules.MarkerBytes()).Matches).Identifier);
    }

    [Fact]
    public void Cancellation_IsHonoredBeforeScanning()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var scanner = new YaraScanner(_rules);

        Assert.Throws<OperationCanceledException>(() => scanner.ScanFile(_dir.File("x"), cts.Token));
        Assert.Throws<OperationCanceledException>(() => scanner.ScanMemory([1], cts.Token));
    }

    // --- Result mapping for A7 ---

    [Fact]
    public void EveryHashFailureReason_MapsToTheSameNamedYaraReason_AndStatus()
    {
        foreach (var reason in Enum.GetValues<HashFailureReason>().Where(r => r != HashFailureReason.None))
        {
            var yara = YaraScanResult.FromHashFailure(reason);
            Assert.Equal(HashResult.StatusFor(reason), YaraScanResult.StatusFor(yara));
        }

        foreach (var reason in Enum.GetValues<YaraFailureReason>().Where(r => r != YaraFailureReason.None))
        {
            var result = YaraScanResult.NotScanned(reason);
            var scan = result.ToNotScannedResult(new ScanItem(@"C:\x.bin", ScanTrigger.CustomScan), DateTimeOffset.UnixEpoch);
            Assert.Null(scan.Verdict);
            Assert.Equal(result.Status, scan.Status);
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => YaraScanResult.StatusFor(YaraFailureReason.None));
    }
}
