using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning.Cache;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// Review D3 M1: the scan cache checks hits against the blocklist bytes the broker actually loaded (trust-checked by the rules
/// source), never a file re-read by path, which a configured user-writable path could make differ.
/// </summary>
public sealed class ScanCacheBlocklistSourceTests
{
    private static readonly string Listed = new('e', 64);

    [Fact]
    public void TheCacheBlocklist_IsBuiltFromTheLoadedBytes_AndIsOffWhenTheyAreUnknown()
    {
        var broker = new FakeScanBroker { Rules = new RulesLoadSummary(1, [], 0, "fp", 1, 0) { Blocklist = Encoding.ASCII.GetBytes(Listed + "\n") } };
        var fingerprints = new EngineScanFingerprints(broker, NullLogger.Instance);

        var context = fingerprints.Current();
        Assert.True(context!.Blocklist.Contains(Listed));
        Assert.Equal(1, context.Blocklist.Count);

        broker.Rules = new RulesLoadSummary(1, [], 0, "fp", 1, 0); // a load whose bytes aren't known: no cache rather than a guess
        Assert.Null(fingerprints.Current());

        broker.Rules = new RulesLoadSummary(1, [], 0, "fp2", 0, 0) { Blocklist = [] }; // a refused list loads as empty, and so does the cache's
        Assert.Equal(0, fingerprints.Current()!.Blocklist.Count);
    }

    [Fact]
    public async Task TheBrokerSummary_CarriesTheExactBytesItSentToTheScanner()
    {
        using var temp = new TempDir();
        var blocklist = Path.Combine(temp.Path, "blocklist.txt");
        File.WriteAllText(blocklist, Listed + "\n");
        using var broker = new InProcessScanBroker(new DirectoryScanRulesSource(new SandboxOptions { RulesDirectory = temp.Path, BlocklistPath = blocklist }),
            NullLogger.Instance);

        var summary = await broker.ReloadRulesAsync();
        File.WriteAllText(blocklist, "# emptied after the load\n");

        Assert.Equal(Listed + "\n", Encoding.ASCII.GetString(summary!.Blocklist!));
        Assert.True(new EngineScanFingerprints(broker, NullLogger.Instance).Current()!.Blocklist.Contains(Listed)); // the file is never re-read
    }
}
