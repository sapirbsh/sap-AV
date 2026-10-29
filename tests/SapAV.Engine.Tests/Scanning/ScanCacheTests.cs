using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Blocklist;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Yara;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Cache;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>Fixed fingerprints the tests change at will.</summary>
internal sealed class FakeFingerprints : IScanCacheFingerprints
{
    public const string DefaultRules = "1111111111111111111111111111111111111111111111111111111111111111";

    public string Rules { get; set; } = DefaultRules;

    public HashBlocklist Blocklist { get; set; } = HashBlocklist.Empty;

    public string Engine { get; set; } = "test-engine";

    public bool Known { get; set; } = true;

    public ScanCacheContext? Current() => Known ? new ScanCacheContext(Rules, Blocklist, Engine) : null;

    public static HashBlocklist BlocklistOf(params string[] hashes) =>
        HashBlocklist.LoadAsync(new StringReader(string.Join('\n', hashes))).GetAwaiter().GetResult();
}

/// <summary>
/// A scan job harness with a real SQLite cache in a temp folder (its own protected ACL, a fixed MAC key) and a fake broker
/// whose reports are cacheable (a YARA scan under <see cref="FakeFingerprints.Rules"/>). Nothing outside the temp folder.
/// </summary>
internal sealed class CacheHarness : IDisposable
{
    private readonly TempDir _cacheTemp = new();

    public CacheHarness()
    {
        Folder = Path.Combine(_cacheTemp.Path, "Cache");
        Options = new ScanCacheOptions { Folder = Folder };
        Cache = CreateCache();
        Jobs = new ScanJobHarness { Cache = Cache };
        Jobs.Broker.OnScan = (item, file, _) =>
        {
            var report = FakeScanBroker.Judge(item, file, Jobs.Time);
            return Task.FromResult<FileScanReport?>(Rules is { } rules
                ? report with { Yara = YaraScanResult.Scanned([], report.Hash.Length ?? 0, rules) }
                : report);
        };
    }

    public static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    public string Folder { get; }

    public ScanCacheOptions Options { get; }

    public FakeFingerprints Fingerprints { get; } = new();

    public ScanCache Cache { get; }

    public ScanJobHarness Jobs { get; }

    /// <summary>The rules fingerprint the fake broker's reports carry (null = no YARA scan in the report).</summary>
    public string? Rules { get; set; } = FakeFingerprints.DefaultRules;

    public static QuarantineAccessPolicy Policy => new([QuarantineTestContext.CurrentUser]);

    public ScanCache CreateCache() =>
        ScanCache.TryCreate(Options, "unused", new FakeScanBroker(), new FixedKeyProvider(Key), Policy, TimeProvider.System, NullLogger.Instance,
            parentIsDataRoot: false, fingerprints: Fingerprints) ?? throw new InvalidOperationException("The test cache wasn't created.");

    public async Task<ScanJob> RunAsync(ScanJobRequest? request = null)
    {
        var job = Jobs.Service.Create(request ?? new ScanJobRequest([Jobs.Root], ScanTrigger.CustomScan));
        Assert.Equal(ScanJobStartResult.Started, Jobs.Service.Start(job.Id));
        await JobWait.Done(job);
        return job;
    }

    public void Dispose()
    {
        Jobs.Dispose();
        Cache.Dispose();
        SqliteConnection.ClearAllPools();
        _cacheTemp.Dispose();
    }
}

/// <summary>
/// C5: the SQLite scan cache. Hits only for an unchanged file object at the same path under the same rules and engine;
/// the blocklist is re-checked on every hit (no re-read); never-cache rules; MAC, corruption rebuild, ACL, pruning and
/// concurrency. Temp folders and synthetic content only.
/// </summary>
public sealed class ScanCacheTests(Xunit.Abstractions.ITestOutputHelper output)
{
    [Fact]
    public async Task UnchangedFile_IsAHit_OnTheSecondScan_CountedAsCached_AndTheBrokerIsNotCalled()
    {
        using var h = new CacheHarness();
        h.Jobs.Write("a.txt", "alpha");
        h.Jobs.Write(@"sub\b.txt", "bravo");

        var first = await h.RunAsync();
        var second = await h.RunAsync();

        Assert.Equal(2, h.Jobs.Broker.Calls);
        Assert.Equal(0, first.GetProgress().Counters.Cached);
        Assert.Equal(2, second.GetProgress().Counters.Cached);
        Assert.Equal(2, second.GetProgress().Counters.Clean);
        Assert.Equal(2, h.Cache.Stats.Hits);
    }

    [Theory]
    [InlineData("content")]
    [InlineData("timestamp")]
    [InlineData("recreated")]
    public async Task ChangedFile_IsAMiss_AndScannedAgain(string change)
    {
        using var h = new CacheHarness();
        var path = h.Jobs.Write("a.txt", "alpha");
        await h.RunAsync();

        switch (change)
        {
            case "content":
                File.WriteAllText(path, "ALPHA"); // same size, new content: last-write / change time / USN move
                break;
            case "timestamp":
                File.SetLastWriteTimeUtc(path, new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc)); // timestomping moves the change time too
                break;
            default:
                File.Delete(path);
                File.WriteAllText(path, "alpha"); // same name, size and content, but another file object
                break;
        }

        var second = await h.RunAsync();

        Assert.Equal(2, h.Jobs.Broker.Calls);
        Assert.Equal(0, second.GetProgress().Counters.Cached);
    }

    [Fact]
    public async Task RenamedFile_KeepsItsIdentity_ButIsScannedAgain_BecauseTheVerdictDependsOnThePath()
    {
        using var h = new CacheHarness();
        var path = h.Jobs.Write("report.txt", "alpha");
        await h.RunAsync();

        File.Move(path, Path.Combine(h.Jobs.Root, "report.pdf.exe")); // same file object, a name the heuristics would judge differently
        var renamed = await h.RunAsync();
        var again = await h.RunAsync();

        Assert.Equal(0, renamed.GetProgress().Counters.Cached);
        Assert.Equal(1, again.GetProgress().Counters.Cached); // the row was replaced with the new path
        Assert.Equal(2, h.Jobs.Broker.Calls);
        Assert.Equal(1, h.Cache.Store.Count());
    }

    [Fact]
    public async Task RulesOrEngineChange_InvalidatesTheRow_AndCaseOnlyPathDifferencesStillHit()
    {
        using var h = new CacheHarness();
        h.Jobs.Write("a.txt", "alpha");
        await h.RunAsync();

        var upper = await h.RunAsync(new ScanJobRequest([h.Jobs.Root.ToUpperInvariant()], ScanTrigger.CustomScan));
        Assert.Equal(1, upper.GetProgress().Counters.Cached); // C:\X.bin and c:\x.bin are the same file (A1 / B2)

        h.Fingerprints.Rules = new string('2', 64);
        h.Rules = h.Fingerprints.Rules;
        Assert.Equal(0, (await h.RunAsync()).GetProgress().Counters.Cached); // new rules: YARA runs again
        Assert.Equal(1, (await h.RunAsync()).GetProgress().Counters.Cached);

        h.Fingerprints.Engine = "test-engine-2";
        Assert.Equal(0, (await h.RunAsync()).GetProgress().Counters.Cached);
        Assert.Equal(3, h.Jobs.Broker.Calls);
    }

    [Fact]
    public async Task BlocklistUpdate_FlagsACachedHashMalicious_WithoutReadingTheFileAgain()
    {
        using var h = new CacheHarness();
        var handler = new RecordingVerdictHandler();
        h.Jobs.Handler = handler;
        var path = h.Jobs.Write("tool.bin", "a synthetic tool");
        var other = h.Jobs.Write("other.bin", "something else");
        await h.RunAsync();
        string sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

        h.Fingerprints.Blocklist = FakeFingerprints.BlocklistOf(sha);
        var job = await h.RunAsync();

        Assert.Equal(2, h.Jobs.Broker.Calls); // nothing was scanned again
        var flagged = Assert.Single(job.Results);
        Assert.Equal(Verdict.Malicious, flagged.Verdict);
        Assert.True(flagged.FromCache);
        Assert.Contains(flagged.Detections, d => d.Source == DetectionSource.Blocklist);
        Assert.Contains(handler.Seen, s => s.Path.EndsWith("tool.bin", StringComparison.Ordinal) && s.Verdict == Verdict.Malicious && s.HandleOpen);
        Assert.Equal(1, h.Cache.Stats.BlocklistUpgrades);
        Assert.Equal(1, h.Cache.Store.Count()); // the Malicious row is gone; other.bin's row carries the new blocklist fingerprint
        var row = h.Cache.Store.Get(Stamp(other).Volume, Stamp(other).FileId)!;
        Assert.Equal(h.Fingerprints.Blocklist.Fingerprint, row.BlocklistFingerprint);
    }

    [Fact]
    public async Task SuspiciousFile_IsCached_AndTheResultSaysSo_InTheJobAndOnThePipe()
    {
        using var h = new CacheHarness();
        h.Jobs.Write("sus-file.txt", "odd");

        await h.RunAsync();
        var job = await h.RunAsync();

        var result = Assert.Single(job.Results);
        Assert.Equal(Verdict.Suspicious, result.Verdict);
        Assert.True(result.FromCache);
        Assert.True(SapAV.Engine.Pipe.PipeMapping.Result(0, result).FromCache);
        Assert.Equal(1, SapAV.Engine.Pipe.PipeMapping.Progress(job.GetProgress()).Counters.Cached);
    }

    [Fact]
    public async Task NeverCached_MaliciousFiles_IncompleteScans_AndAFileABlocklistedHashTurnsUpIn()
    {
        using var h = new CacheHarness();
        h.Jobs.Write("mal-dropper.bin", "bad");
        await h.RunAsync();
        Assert.Equal(0, h.Cache.Store.Count()); // Malicious: quarantined or the user's decision, never cached

        h.Rules = null; // the report has no YARA scan (failed / timed out)
        h.Jobs.Write("plain.txt", "fine");
        await h.RunAsync();
        Assert.Equal(0, h.Cache.Store.Count());

        h.Rules = h.Fingerprints.Rules;
        h.Fingerprints.Blocklist = FakeFingerprints.BlocklistOf(Convert.ToHexStringLower(SHA256.HashData("fine"u8)));
        await h.RunAsync();
        Assert.Equal(0, h.Cache.Store.Count()); // the engine's blocklist already lists it (the worker may have had an older one)
    }

    [Fact]
    public async Task StandardUserJobs_AndRemoteAllowingJobs_BypassTheCache_NeitherReadingNorWriting()
    {
        using var h = new CacheHarness();
        h.Jobs.Write("a.txt", "alpha");
        var restricted = new ScanJobRequest([h.Jobs.Root], ScanTrigger.CustomScan) { Access = new AllowAll(), Origin = ScanJobOrigin.StandardUser };

        await h.RunAsync(restricted);
        Assert.Equal(0, h.Cache.Store.Count()); // not written from a restricted perspective

        await h.RunAsync(); // engine job: stored
        Assert.Equal(1, h.Cache.Store.Count());
        var again = await h.RunAsync(restricted with { });
        Assert.Equal(0, again.GetProgress().Counters.Cached); // and not read either
        var remote = await h.RunAsync(new ScanJobRequest([h.Jobs.Root], ScanTrigger.CustomScan) { AllowRemoteFiles = true });
        Assert.Equal(0, remote.GetProgress().Counters.Cached);
        Assert.Equal(4, h.Jobs.Broker.Calls); // every run scanned: only the engine job stored, and nobody else read
    }

    [Fact]
    public async Task FileOpenForWriting_IsNotCached()
    {
        using var h = new CacheHarness();
        var path = h.Jobs.Write("busy.log", "line");
        using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
        {
            await h.RunAsync(); // opened shared with a USN baseline (or Locked): either way not cached
        }

        Assert.Equal(0, h.Cache.Store.Count());
    }

    [Fact]
    public void TamperedRow_FailsItsMac_IsDeleted_AndNeverUsed()
    {
        using var h = new CacheHarness();
        var row = SampleRow(1);
        h.Cache.Store.Put(row);

        using (var connection = new SqliteConnection($"Data Source={Path.Combine(h.Folder, ScanCacheStore.DatabaseName)};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE entries SET verdict = 0, size = size + 1"; // a forged "Clean", or a forged size
            command.ExecuteNonQuery();
        }

        Assert.Null(h.Cache.Store.Get(row.Stamp.Volume, row.Stamp.FileId));
        Assert.Equal(1, h.Cache.Store.Tampered);
        Assert.Equal(0, h.Cache.Store.Count());
    }

    [Fact]
    public void CorruptDatabase_IsDeletedAndRebuilt_WithAHealthNote()
    {
        using var h = new CacheHarness();
        h.Cache.Store.Put(SampleRow(1));
        h.Cache.Dispose();
        SqliteConnection.ClearAllPools();
        File.WriteAllBytes(Path.Combine(h.Folder, ScanCacheStore.DatabaseName), RandomNumberGenerator.GetBytes(8192)); // not a database
        File.Delete(Path.Combine(h.Folder, ScanCacheStore.DatabaseName + "-wal"));

        using var reopened = h.CreateCache();

        Assert.Equal(1, reopened.Store.Rebuilds);
        Assert.Contains("rebuilt", reopened.Store.LastProblem, StringComparison.Ordinal);
        Assert.Equal(0, reopened.Store.Count());
        reopened.Store.Put(SampleRow(2));
        Assert.NotNull(reopened.Store.Get(SampleRow(2).Stamp.Volume, SampleRow(2).Stamp.FileId));
    }

    [Fact]
    public void CacheFolder_HasTheProtectedDacl_InheritedByTheDatabase_AndAWiderFolderIsRefused()
    {
        using var h = new CacheHarness();
        var trusted = CacheHarness.Policy.TrustedSids;

        var folderAcl = new DirectoryInfo(h.Folder).GetAccessControl();
        Assert.True(folderAcl.AreAccessRulesProtected);
        var rules = folderAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, r => Assert.Contains((SecurityIdentifier)r.IdentityReference, trusted));
        Assert.DoesNotContain(rules, r => ((SecurityIdentifier)r.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid));
        var dbRules = new FileInfo(Path.Combine(h.Folder, ScanCacheStore.DatabaseName)).GetAccessControl()
            .GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();
        Assert.All(dbRules, r => Assert.Contains((SecurityIdentifier)r.IdentityReference, trusted));

        // A folder someone pre-created with normal inheritance is refused: the cache stays off.
        var wide = Directory.CreateDirectory(Path.Combine(Path.GetDirectoryName(h.Folder)!, "Wide")).FullName;
        Assert.Null(ScanCache.TryCreate(new ScanCacheOptions { Folder = wide }, "unused", new FakeScanBroker(), new FixedKeyProvider(CacheHarness.Key),
            CacheHarness.Policy, TimeProvider.System, NullLogger.Instance, parentIsDataRoot: false, fingerprints: h.Fingerprints));
    }

    [Fact]
    public void Prune_DropsOldRows_AndTheLeastRecentlyUsedPastTheCap()
    {
        var time = new ManualTime();
        using var temp = new TempDir();
        string folder = ScanCacheFolder.Ensure(Path.Combine(temp.Path, "Cache"), CacheHarness.Policy, parentIsDataRoot: false);
        var options = new ScanCacheOptions { MaxEntries = 100, MaxAge = TimeSpan.FromDays(10) };
        using (var store = new ScanCacheStore(folder, CacheHarness.Key, options, time, NullLogger.Instance))
        {
            long now = time.Now.ToUnixTimeMilliseconds();
            store.Put(SampleRow(0) with { LastUsed = (time.Now - TimeSpan.FromDays(11)).ToUnixTimeMilliseconds() });
            for (int i = 1; i <= 150; i++)
            {
                store.Put(SampleRow(i) with { LastUsed = now - (150 - i) });
            }

            int deleted = store.Prune();

            Assert.Equal(61, deleted); // the 11-day-old row, then 150 -> 90
            Assert.Equal(90, store.Count());
            Assert.Null(store.Get(SampleRow(60).Stamp.Volume, SampleRow(60).Stamp.FileId)); // least recently used
            Assert.NotNull(store.Get(SampleRow(150).Stamp.Volume, SampleRow(150).Stamp.FileId));
        }

        SqliteConnection.ClearAllPools();
    }

    [Fact]
    public async Task ConcurrentReadersAndWriters_DontFail_AndEveryRowIsReadable()
    {
        using var h = new CacheHarness();
        var store = h.Cache.Store;

        await Task.WhenAll(Enumerable.Range(0, 8).Select(t => Task.Run(() =>
        {
            for (int i = 0; i < 100; i++)
            {
                var row = SampleRow(t * 1000 + i);
                store.Put(row);
                Assert.NotNull(store.Get(row.Stamp.Volume, row.Stamp.FileId));
                store.Put(SampleRow(999_999)); // everyone also rewrites one shared row
                _ = store.Get(SampleRow(999_999).Stamp.Volume, SampleRow(999_999).Stamp.FileId);
            }
        })));

        Assert.Equal(801, store.Count());
        Assert.Equal(0, store.Tampered);
        Assert.Null(store.LastProblem);
    }

    [Fact]
    public async Task RepeatScan_OfATempTree_WithTheRealScanner_IsServedFromTheCache_AndFaster()
    {
        // The real pipeline in-process (hashing, Authenticode, YARA with the shipped rules, heuristics) and the real
        // fingerprints (the broker's rules, the engine's own blocklist copy): the measured speed-up is reported.
        using var temp = new TempDir();
        string tree = Directory.CreateDirectory(Path.Combine(temp.Path, "tree")).FullName;
        const int Files = 300;
        for (int i = 0; i < Files; i++)
        {
            string dir = Directory.CreateDirectory(Path.Combine(tree, $"d{i % 10}")).FullName;
            File.WriteAllBytes(Path.Combine(dir, $"f{i}.bin"), RandomNumberGenerator.GetBytes(32 * 1024));
        }

        var sandbox = new SapAV.Engine.Sandbox.SandboxOptions();
        using var broker = new SapAV.Engine.Sandbox.InProcessScanBroker(new SapAV.Engine.Sandbox.DirectoryScanRulesSource(sandbox), NullLogger.Instance);
        await broker.ReloadRulesAsync();
        var cache = ScanCache.TryCreate(new ScanCacheOptions { Folder = Path.Combine(temp.Path, "Cache") }, sandbox.ResolvedBlocklistPath, broker,
            new FixedKeyProvider(CacheHarness.Key), CacheHarness.Policy, TimeProvider.System, NullLogger.Instance, parentIsDataRoot: false)!;
        Assert.NotNull(cache);
        var service = new ScanJobService(new ScanJobOptions(), broker, ExclusionSet.Always(new FolderSet([])), null, null, TimeProvider.System,
            NullLogger.Instance, cache: cache);
        try
        {
            async Task<(ScanJob Job, TimeSpan Took)> Run()
            {
                var job = service.Create(new ScanJobRequest([tree], ScanTrigger.FullScan));
                var watch = System.Diagnostics.Stopwatch.StartNew();
                Assert.Equal(ScanJobStartResult.Started, service.Start(job.Id));
                await JobWait.Done(job).WaitAsync(TimeSpan.FromMinutes(2));
                return (job, watch.Elapsed);
            }

            var (first, cold) = await Run();
            var (second, warm) = await Run();

            Assert.Equal(Files, first.GetProgress().Counters.Clean);
            Assert.Equal(0, first.GetProgress().Counters.Cached);
            Assert.Equal(Files, second.GetProgress().Counters.Cached);
            Assert.Equal(Files, second.GetProgress().Counters.Clean);
            output.WriteLine($"{Files} files x 32 KiB: first scan {cold.TotalMilliseconds:0} ms, repeat {warm.TotalMilliseconds:0} ms " +
                $"({cold.TotalMilliseconds / Math.Max(1, warm.TotalMilliseconds):0.0}x faster).");
        }
        finally
        {
            service.Dispose();
            cache.Dispose();
            SqliteConnection.ClearAllPools();
        }
    }

    private static FileStamp Stamp(string path)
    {
        using var handle = File.OpenHandle(path);
        return FileStamp.Capture(handle, FileIdentity.TryCapture(handle)!)!.Value;
    }

    internal static ScanCacheRow SampleRow(int n) =>
        new(new FileStamp(0xABCD, (UInt128)n + 1, 10 + n, 1000 + n, 2000 + n, n % 2 == 0 ? 5000 + n : null), $@"\\?\C:\data\file{n}.bin",
            new string('a', 64), Verdict.Clean, "Clean", null, FakeFingerprints.DefaultRules, HashBlocklist.Empty.Fingerprint, "test-engine",
            "{}"u8.ToArray(), 1, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    private sealed class AllowAll : IScanAccessCheck
    {
        public bool CanList(Microsoft.Win32.SafeHandles.SafeFileHandle directory) => true;

        public bool CanRead(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => true;
    }
}
