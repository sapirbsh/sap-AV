using System.Diagnostics;
using SapAV.Core.Tests.Hashing;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Yara;

/// <summary>
/// File handles, mapping/view handles and native rule sets must not leak: the handle count stays flat over
/// thousands of scans (every early return included), and compiling/disposing rule sets doesn't grow memory.
/// Runs in the non-parallel handle-count collection.
/// </summary>
[Collection(HandleCountCollection.Name)]
public sealed class YaraHandleLeakTests(ITestOutputHelper output) : IDisposable
{
    private const int Iterations = 3000;
    private const int AllowedGrowth = 100;
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static int HandleCount()
    {
        using var p = Process.GetCurrentProcess();
        return p.HandleCount;
    }

    private void AssertFlat(string label, Action scan)
    {
        for (int i = 0; i < 100; i++)
        {
            scan();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        int before = HandleCount();
        for (int i = 0; i < Iterations; i++)
        {
            scan();
        }

        int after = HandleCount(); // no GC in between on purpose: leaked SafeHandles would still be open
        output.WriteLine($"{label}: handles {before} -> {after} over {Iterations} scans");
        Assert.True(after - before < AllowedGrowth, $"{label}: handle count grew by {after - before}");
    }

    [Fact]
    public void FileScans_MatchedClean_Empty_TooLarge_Directory_HandleCountStaysFlat()
    {
        using var rules = YaraTestRules.MarkerSet();
        var scanner = new YaraScanner(rules, maxSizeBytes: 1000);
        var hit = _dir.WriteFile("hit.txt", YaraTestRules.MarkerBytes());
        var empty = _dir.WriteFile("empty.bin", []);
        var big = _dir.WriteFile("big.bin", new byte[2000]);

        AssertFlat("matched", () => Assert.Single(scanner.ScanFile(hit).Matches));
        AssertFlat("empty", () => Assert.True(scanner.ScanFile(empty).IsScanned));
        AssertFlat("too large", () => Assert.Equal(YaraFailureReason.TooLarge, scanner.ScanFile(big).FailureReason));
        AssertFlat("directory", () => Assert.Equal(YaraFailureReason.Directory, scanner.ScanFile(_dir.Path).FailureReason));

        // Deterministic: an exclusive open works right after a scan, so no handle or mapping is left open.
        scanner.ScanFile(hit);
        using var exclusive = new FileStream(hit, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    [Fact]
    public void CompileAndDispose_ManyTimes_DoesNotGrowMemoryOrHandles()
    {
        static void Cycle()
        {
            using var set = YaraRuleSet.FromSources(
            [
                new YaraRuleSource("a.yar", YaraTestRules.MarkerRule("A")),
                new YaraRuleSource("b.yar", "rule B { strings: $x = /ab[0-9]{2,8}cd/ condition: $x }"),
                new YaraRuleSource("bad.yar", "rule Bad {"),
            ]);
            Assert.Single(new YaraScanner(set).ScanMemory(YaraTestRules.MarkerBytes()).Matches);
        }

        for (int i = 0; i < 50; i++)
        {
            Cycle();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        long memoryBefore = process.PrivateMemorySize64;
        int handlesBefore = HandleCount();

        for (int i = 0; i < 1000; i++)
        {
            Cycle();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        process.Refresh();
        long growth = process.PrivateMemorySize64 - memoryBefore;
        int handleGrowth = HandleCount() - handlesBefore;
        output.WriteLine($"1000 compile/dispose cycles: private bytes +{growth / 1024} KiB, handles +{handleGrowth}");

        // Each set holds at least tens of KiB of native arenas; 1000 leaked sets would be tens of MiB.
        Assert.True(growth < 16L * 1024 * 1024, $"private memory grew by {growth / 1024} KiB");
        Assert.True(handleGrowth < AllowedGrowth, $"handle count grew by {handleGrowth}");
    }
}
