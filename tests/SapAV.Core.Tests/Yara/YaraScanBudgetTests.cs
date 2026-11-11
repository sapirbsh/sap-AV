using System.Diagnostics;
using System.Text;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Yara;

/// <summary>E2: the YARA scan-time budget (a per-file YARA-X timeout plus a total per run) and a timing test with all shipped rules.</summary>
public sealed class YaraScanBudgetTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A clock that moves forward by a fixed step every time it is read.</summary>
    private sealed class SteppingTimeProvider(TimeSpan step) : TimeProvider
    {
        private long _ticks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Interlocked.Add(ref _ticks, step.Ticks);
    }

    [Fact]
    public void Timeout_IsThePerFileLimit_CappedByWhatIsLeft_ThenScansAreRefused()
    {
        var budget = new YaraScanBudget(TimeSpan.FromSeconds(12), TimeSpan.FromSeconds(10));

        Assert.True(budget.TryGetTimeoutSeconds(out int first));
        budget.Charge(TimeSpan.FromSeconds(9.5));
        Assert.True(budget.TryGetTimeoutSeconds(out int second)); // 2.5 s left -> rounded up to whole seconds
        budget.Charge(TimeSpan.FromSeconds(2.5));

        Assert.Equal((10, 3), (first, second));
        Assert.True(budget.IsExhausted);
        Assert.False(budget.TryGetTimeoutSeconds(out _));
        Assert.Equal(1, budget.RefusedCount);
        Assert.Throws<ArgumentOutOfRangeException>(() => new YaraScanBudget(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new YaraScanBudget(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void AScannerWithAUsedUpBudget_RefusesToScan_AndTheFileIsNotScanned_NeverClean()
    {
        using var rules = YaraTestRules.MarkerSet();
        // Every scan "takes" 3 s on this clock; the run may use 5 s.
        var budget = new YaraScanBudget(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), new SteppingTimeProvider(TimeSpan.FromSeconds(3)));
        var scanner = new YaraScanner(rules, budget: budget);
        var marker = YaraTestRules.MarkerBytes();

        var first = scanner.ScanMemory(marker);
        var second = scanner.ScanMemory(marker);
        var third = scanner.ScanMemory(marker);

        Assert.True(first.IsScanned && second.IsScanned);
        Assert.Single(first.Matches);
        Assert.Equal((ScanStatus.Error, YaraFailureReason.BudgetExhausted), (third.Status, third.FailureReason));
        var notScanned = third.ToNotScannedResult(new ScanItem(_dir.File("x.txt"), ScanTrigger.FullScan), DateTimeOffset.UnixEpoch);
        Assert.Null(notScanned.Verdict);

        // A new run gets a fresh budget.
        Assert.Same(budget, scanner.SetBudget(new YaraScanBudget(TimeSpan.FromMinutes(1))));
        Assert.True(scanner.ScanMemory(marker).IsScanned);
    }

    [Fact]
    public void AllShippedRules_ScanASyntheticTempTree_Quickly_WithinTheBudget_AndWithoutMatches()
    {
        // About 100 files, 25 MB in total: random data, repeated text, zeros and small JSON/INI files. Never a PE ("MZ") file.
        var random = new Random(20261111);
        var paths = new List<string>();
        for (int i = 0; i < 100; i++)
        {
            string folder = Path.Combine(_dir.Path, $"sub{i % 4}", $"deep{i % 3}");
            Directory.CreateDirectory(folder);
            byte[] content = (i % 4) switch
            {
                0 => RandomBytes(random, random.Next(64 * 1024, 768 * 1024)),
                1 => Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat($"Line {i}: the quick brown fox jumps over the lazy dog. ", random.Next(500, 5000)))),
                2 => new byte[random.Next(1024, 512 * 1024)],
                _ => Encoding.UTF8.GetBytes($"{{\n  \"name\": \"settings-{i}\",\n  \"enabled\": true,\n  \"path\": \"C:\\\\Program Files\\\\App{i}\"\n}}\n[section]\nkey=value\n"),
            };
            string path = Path.Combine(folder, $"file{i}.dat");
            File.WriteAllBytes(path, content);
            paths.Add(path);
        }

        var load = Stopwatch.StartNew();
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        load.Stop();
        Assert.Empty(rules.FileErrors);
        Assert.True(rules.Rules.Count > 200, $"only {rules.Rules.Count} rules loaded");

        var budget = new YaraScanBudget(TimeSpan.FromMinutes(2), TimeSpan.FromSeconds(10));
        var scanner = new YaraScanner(rules, budget: budget);
        var scan = Stopwatch.StartNew();
        var results = paths.Select(p => scanner.ScanFile(p)).ToList();
        scan.Stop();

        Assert.All(results, r => Assert.True(r.IsScanned, r.ErrorMessage));
        Assert.All(results, r => Assert.Empty(r.Matches)); // no false positive on ordinary data
        Assert.True(load.Elapsed < TimeSpan.FromSeconds(60), $"compiling the rules took {load.Elapsed}");
        Assert.True(scan.Elapsed < TimeSpan.FromSeconds(60), $"scanning {paths.Count} files took {scan.Elapsed}");
        Assert.False(budget.IsExhausted);
        Assert.Equal(0, budget.RefusedCount);
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        bytes[0] = 0; // never "MZ" at the start
        return bytes;
    }
}
