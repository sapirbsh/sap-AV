using System.Diagnostics;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Yara;

/// <summary>
/// The build-time integrity check of the YARA-X native DLL (<c>native/yara-x/YaraX.targets</c>): a cached asset
/// with the wrong SHA-256 fails the build and is deleted. Runs the real MSBuild target against a temp cache
/// directory holding a fake asset, so nothing is downloaded.
/// </summary>
public sealed class YaraXNativePinTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Pins_AreWellFormed()
    {
        Assert.Matches(@"^\d+\.\d+\.\d+$", YaraXPins.Version);
        Assert.Matches("^[0-9a-f]{64}$", YaraXPins.AssetSha256);
        Assert.Matches("^[0-9a-f]{64}$", YaraXPins.DllSha256);
    }

    [Fact]
    public void TamperedCachedAsset_FailsTheBuild_AndIsDeleted()
    {
        var cache = _dir.Path + Path.DirectorySeparatorChar;
        var fakeZip = _dir.WriteFile(YaraXPins.AssetName, "not the real release asset"u8.ToArray());

        var (exitCode, log) = RunTarget(cache);
        output.WriteLine(log);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("SAPAV001", log);
        Assert.Contains(YaraXPins.AssetSha256, log, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(fakeZip), "the tampered asset must be deleted so the next build re-downloads it");
    }

    private static (int ExitCode, string Log) RunTarget(string cacheDir)
    {
        var dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host && File.Exists(host) ? host : "dotnet";
        var psi = new ProcessStartInfo(dotnet)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in new[]
        {
            "msbuild", YaraXPins.TargetsPath, "-t:YaraXEnsureNative", "-nologo", "-v:m", "-nodeReuse:false",
            $"-p:YaraXCacheDir={cacheDir}",
        })
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(120_000), "msbuild did not finish");
        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
