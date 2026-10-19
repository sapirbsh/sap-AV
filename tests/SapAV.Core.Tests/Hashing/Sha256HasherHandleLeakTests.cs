using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Hashing;

/// <summary>Runs alone, so other test classes opening handles in parallel don't disturb the count.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class HandleCountCollection
{
    public const string Name = "Handle count (not parallel)";
}

/// <summary>
/// Every early return after the open (NotRegularFile, Directory, Offline, TooLarge) and the normal path
/// must close the handle. Checked two ways: deterministically (an exclusive open succeeds right after one
/// hash), and by hashing 10,000 times with the GC held off, so leaked SafeHandles can't be finalized
/// away before <see cref="Process.HandleCount"/> is read.
/// </summary>
[Collection(HandleCountCollection.Name)]
[SupportedOSPlatform("windows")]
public sealed class Sha256HasherHandleLeakTests(ITestOutputHelper output) : IDisposable
{
    private const int Iterations = 10_000;
    private const int AllowedGrowth = 100; // runtime noise (thread pool, timers); a leak would be ~10,000
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static int HandleCount()
    {
        using var p = Process.GetCurrentProcess();
        return p.HandleCount;
    }

    private async Task AssertNoHandleGrowth(string path, HashFailureReason expected, Sha256Hasher? hasher = null)
    {
        hasher ??= new Sha256Hasher();
        var first = await hasher.HashFileAsync(path);
        Assert.True(first.FailureReason == expected, $"{first.FailureReason}: {first.ErrorMessage}");
        for (int i = 0; i < 200; i++)
        {
            await hasher.HashFileAsync(path); // warm up pools, JIT, thread pool
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        int before = HandleCount();

        bool noGc = false;
        try
        {
            noGc = GC.TryStartNoGCRegion(200L * 1024 * 1024);
        }
        catch (ArgumentOutOfRangeException)
        {
        }

        bool gcRan = false;
        try
        {
            for (int i = 0; i < Iterations; i++)
            {
                var r = await hasher.HashFileAsync(path);
                if (r.FailureReason != expected)
                {
                    Assert.Fail($"iteration {i}: {r.FailureReason}: {r.ErrorMessage}");
                }
            }
        }
        finally
        {
            int after = HandleCount(); // read before the GC region ends
            if (noGc)
            {
                try
                {
                    GC.EndNoGCRegion();
                }
                catch (InvalidOperationException)
                {
                    gcRan = true; // the allocation budget was exceeded and a GC happened
                }
            }

            output.WriteLine($"{expected}: handles {before} -> {after} over {Iterations} hashes " +
                $"(GC held off: {noGc && !gcRan})");
            Assert.True(after - before < AllowedGrowth, $"handle count grew by {after - before} over {Iterations} hashes");
        }
    }

    /// <summary>Opens with no sharing: fails with a sharing violation if any handle to the path is still open.</summary>
    private static void AssertNoOtherHandleOpen(string path)
    {
        using var h = CreateFileW(path, 0x80000000, 0, IntPtr.Zero, 3, 0x02000000 /* backup semantics */, IntPtr.Zero);
        Assert.False(h.IsInvalid, $"exclusive open failed (Win32 error {Marshal.GetLastPInvokeError()}): a handle is still open");
    }

    private bool TryCreateSymlink(string link, string target)
    {
        try
        {
            File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            output.WriteLine($"SKIPPED (no assertions): cannot create symlinks here: {ex.Message}");
            return false;
        }
    }

    // --- Directory ---

    [Fact]
    public async Task Directory_ClosesTheHandle()
    {
        var dir = _dir.File("d");
        Directory.CreateDirectory(dir);

        Assert.Equal(HashFailureReason.Directory, (await new Sha256Hasher().HashFileAsync(dir)).FailureReason);
        AssertNoOtherHandleOpen(dir);
    }

    [Fact]
    public async Task Directory_10kTimes_HandleCountStaysFlat()
    {
        var dir = _dir.File("d");
        Directory.CreateDirectory(dir);
        await AssertNoHandleGrowth(dir, HashFailureReason.Directory);
    }

    // --- Offline ---

    [Fact]
    public async Task Offline_ClosesTheHandle()
    {
        var path = _dir.WriteFile("off.bin", new byte[10]);
        File.SetAttributes(path, FileAttributes.Offline);
        try
        {
            Assert.Equal(HashFailureReason.Offline, (await new Sha256Hasher().HashFileAsync(path)).FailureReason);
            AssertNoOtherHandleOpen(path);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    [Fact]
    public async Task Offline_10kTimes_HandleCountStaysFlat()
    {
        var path = _dir.WriteFile("off.bin", new byte[10]);
        File.SetAttributes(path, FileAttributes.Offline);
        try
        {
            await AssertNoHandleGrowth(path, HashFailureReason.Offline);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    // --- NotRegularFile via GetFileType: a junction to a non-disk device opens, then is rejected ---

    [Fact]
    public async Task NotRegularFile_AfterOpen_10kTimes_HandleCountStaysFlat()
    {
        // Junction to the root of the named-pipe file system: reusable, unlike a single pipe instance.
        // (A reparse point to \??\NUL is refused by Windows with ERROR_INVALID_REPARSE_DATA.)
        var junc = _dir.File("j");
        if (RawJunction.TryCreate(junc, @"\??\pipe\") is { } why)
        {
            output.WriteLine($"SKIPPED (no assertions): {why}");
            return;
        }

        var first = await new Sha256Hasher().HashFileAsync(junc);
        output.WriteLine($"first: {first.FailureReason}: {first.ErrorMessage}");
        Assert.Contains("file type", first.ErrorMessage); // went through the post-open GetFileType check

        await AssertNoHandleGrowth(junc, HashFailureReason.NotRegularFile);
    }

    [Fact]
    public async Task SymlinkToNulDevice_FailsCleanly_AsIoError()
    {
        // File.CreateSymbolicLink(link, @"\\.\NUL") stores reparse data Windows rejects (ERROR_INVALID_REPARSE_DATA,
        // 4392). Pins that this is a clean IoError from the file path (the only file-path IoError producer here).
        var link = _dir.File("to-nul.bin");
        if (!TryCreateSymlink(link, @"\\.\NUL"))
        {
            return;
        }

        var result = await new Sha256Hasher().HashFileAsync(link);
        output.WriteLine($"{result.FailureReason}: {result.ErrorMessage}");

        Assert.False(result.IsHashed);
        Assert.True(result.FailureReason is HashFailureReason.IoError or HashFailureReason.NotRegularFile,
            $"{result.FailureReason}: {result.ErrorMessage}");
    }

    [Fact]
    public async Task NotRegularFile_ThroughSymlinkToPipe_ReleasesThePipe()
    {
        // The pipe has one instance: if the hasher's handle stayed open, the server would never see the
        // client disconnect (a read would block instead of returning end-of-pipe).
        await using var probe = new PipeProbe();
        var link = _dir.File("to-pipe.bin");
        if (!TryCreateSymlink(link, probe.Path))
        {
            return;
        }

        var result = await new Sha256Hasher().HashFileAsync(link);
        Assert.Equal(HashFailureReason.NotRegularFile, result.FailureReason);
        Assert.True(await probe.WasConnectedAsync());

        Assert.True(await probe.ClientDisconnectedAsync(TimeSpan.FromSeconds(2)), "the hasher's pipe handle is still open");
    }

    // --- TooLarge and the normal path, for completeness ---

    [Fact]
    public async Task TooLarge_10kTimes_HandleCountStaysFlat()
    {
        var path = _dir.WriteFile("big.bin", new byte[200]);
        await AssertNoHandleGrowth(path, HashFailureReason.TooLarge, new Sha256Hasher(maxSizeBytes: 100));
        AssertNoOtherHandleOpen(path);
    }

    [Fact]
    public async Task Hashed_10kTimes_HandleCountStaysFlat()
    {
        var path = _dir.WriteFile("ok.bin", new byte[64]);
        await AssertNoHandleGrowth(path, HashFailureReason.None);
        AssertNoOtherHandleOpen(path);
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
