using System.Security.Cryptography;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Blocklist;

/// <summary>
/// ROADMAP A2 "done when": the AV test string's hash is found in a test blocklist. The test string is
/// built and hashed in memory only; just its hash (harmless text) is written to a temp blocklist file.
/// </summary>
public sealed class BlocklistEndToEndTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task AvTestStringHash_IsFoundInTempBlocklistFile_AsMalicious()
    {
        var hash = await new Sha256Hasher().HashStreamAsync(new MemoryStream(Eicar.Bytes()));
        Assert.True(hash.IsHashed);
        Assert.Equal(Eicar.KnownSha256, hash.Sha256);

        var path = _dir.File("test-blocklist.txt");
        await File.WriteAllTextAsync(path, $"# temp test blocklist\n{hash.Sha256.ToUpperInvariant()}\n");
        var blocklist = await HashBlocklist.LoadAsync(path);

        Assert.True(blocklist.TryMatch(hash.Sha256, out var detection));
        Assert.Equal(Verdict.Malicious, detection.Verdict);
        Assert.Equal(DetectionSource.Blocklist, detection.Source);
        Assert.Equal("T1204.002", detection.TechniqueId);

        // How A7 will combine the pieces.
        var item = new ScanItem(@"C:\Users\test\Downloads\sample.com", ScanTrigger.RealTime);
        var result = new ScanResult(item, [detection], DateTimeOffset.UnixEpoch, hash.Sha256);
        Assert.Equal(Verdict.Malicious, result.Verdict);
        Assert.Equal(Eicar.KnownSha256, result.Sha256);
    }

    [Fact]
    public async Task UnlistedHash_IsNotFound()
    {
        var path = _dir.File("test-blocklist.txt");
        await File.WriteAllTextAsync(path, Eicar.KnownSha256 + "\n");
        var blocklist = await HashBlocklist.LoadAsync(path);

        var benign = await new Sha256Hasher().HashStreamAsync(new MemoryStream("just a normal file"u8.ToArray()));

        Assert.True(benign.IsHashed);
        Assert.False(blocklist.Contains(benign.Sha256));
        Assert.False(blocklist.TryMatch(benign.Sha256, out _));
    }

    [Fact]
    public void AvTestString_IsBuiltAtRuntime_WithExpectedShape()
    {
        var bytes = Eicar.Bytes();

        Assert.Equal(68, bytes.Length);
        Assert.Equal(Eicar.KnownSha256, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }
}
