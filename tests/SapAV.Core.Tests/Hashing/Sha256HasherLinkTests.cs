using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Hashing;

/// <summary>
/// Symlink / junction handling: loops, long chains, relative targets, junctions, metadata from the target,
/// and what is guaranteed when a link leads to a named pipe.
/// </summary>
/// <remarks>
/// Guarantee for anything reached through a reparse point (see <see cref="IFileHasher"/>): it may be opened,
/// but only with anonymous impersonation and no recall, and it is rejected as NotRegularFile before any
/// read unless it is a disk file. So for a link to a pipe: (a) NotRegularFile, (b) nothing read from and
/// nothing written to the pipe, (c) the pipe server can't act as the hasher's identity.
/// A direct device path is never opened at all.
/// </remarks>
public sealed class Sha256HasherLinkTests(ITestOutputHelper output) : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    // --- Helpers ---

    // Tests using these are gated by [RequiresFact(Requires.Symlinks / Requires.Junctions)], so a failure
    // to create a link here is a real failure, not a skip.
    private static void CreateSymlink(string link, string target) => File.CreateSymbolicLink(link, target);

    private static void CreateJunction(string link, string targetDir)
    {
        var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{targetDir}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        string err = p.StandardError.ReadToEnd();
        p.WaitForExit(10_000);
        Assert.True(p.ExitCode == 0 && Directory.Exists(link), $"mklink /J failed: {err}");
    }

    /// <summary>Creates link0 -> link1 -> ... -> link(n-1) -> finalTarget. Returns link0.</summary>
    private string CreateChain(int links, string finalTarget, string prefix = "hop")
    {
        for (int i = links - 1; i >= 0; i--)
        {
            var link = _dir.File($"{prefix}{i}.bin");
            var target = i == links - 1 ? finalTarget : $"{prefix}{i + 1}.bin"; // relative hops
            CreateSymlink(link, target);
        }

        return _dir.File($"{prefix}0.bin");
    }

    private static async Task<HashResult> WithTimeout(Task<HashResult> task)
    {
        var finished = await Task.WhenAny(task, Task.Delay(Timeout));
        Assert.True(ReferenceEquals(task, finished), "Hashing did not finish in time");
        return await task;
    }

    private static byte[] Data(int n)
    {
        var b = new byte[n];
        new Random(7).NextBytes(b);
        return b;
    }

    private static string Sha(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    /// <summary>
    /// Hashes <paramref name="path"/> (which leads to <paramref name="probe"/>'s pipe through links) and
    /// checks guarantees (a) and (b): NotRegularFile, the read loop never ran, nothing written to the pipe.
    /// </summary>
    private async Task AssertPipeRejectedWithoutIo(PipeProbe probe, string path)
    {
        int reads = 0;
        var hasher = new Sha256Hasher { BeforeReadHook = _ => { reads++; return Task.CompletedTask; } };

        var result = await WithTimeout(hasher.HashFileAsync(path));
        output.WriteLine($"path taken: {result.FailureReason}: {result.ErrorMessage}");

        Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}"); // (a)
        Assert.False(result.IsHashed);
        Assert.Null(result.Length);
        Assert.Equal(0, reads);                                       // (b) no read from the pipe
        Assert.Equal(0, await probe.BytesWrittenByClientAsync());     // (b) nothing written to the pipe
    }

    // --- The pipe probe itself ---

    [Fact]
    public async Task PipeProbe_Control_DetectsADirectOpen()
    {
        // await using: disposed even if an assertion fails; the explicit dispose below is idempotent.
        await using var probe = new PipeProbe();
        await using (var client = new FileStream(probe.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            Assert.True(await probe.WasConnectedAsync(), "probe must see a real client open");
        }

        await probe.DisposeAsync();
        Assert.False(PipeProbe.Exists(probe.Name), "pipe server must be gone after dispose");
    }

    [Fact]
    public async Task IsConnected_WithoutWaitForConnection_DoesNotSeeAClient()
    {
        // Documents why a plain Assert.False(server.IsConnected) proves nothing; use PipeProbe instead.
        var name = "sapav-test-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(
            name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new FileStream(@"\\.\pipe\" + name, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        Assert.False(server.IsConnected);
    }

    [Fact]
    public async Task ImpersonationProbe_Control_DefaultFlags_ExposeTheRealIdentity()
    {
        // Without SQOS flags a pipe client is impersonable at SecurityImpersonation level. This proves the
        // probe can detect impersonation, so a null result in the tests below means something.
        await using var probe = new PipeProbe();
        using var handle = PipeProbe.OpenClient(probe.Path, flags: 0x40000000 /* overlapped only */);
        await using var client = new FileStream(handle, FileAccess.ReadWrite, 0, isAsync: true);
        await client.WriteAsync(new byte[] { 1 }).AsTask().WaitAsync(Timeout);
        // No Flush: FlushFileBuffers on a pipe blocks until the server has read the data.

        var identity = await probe.ClientIdentityAfterOneByteAsync().WaitAsync(Timeout);

        Assert.Equal(WindowsIdentity.GetCurrent().Name, identity);
    }

    [Fact]
    public async Task HashingFlags_GiveThePipeServerOnlyAnonymousImpersonation()
    {
        // (c) Same client as the control, but with the hasher's exact CreateFileW flags. Even a client that
        // writes (the hasher never does) can't be impersonated as a real identity.
        await using var probe = new PipeProbe();
        using var handle = PipeProbe.OpenClient(probe.Path, NativeFile.HashingFlags);
        await using var client = new FileStream(handle, FileAccess.ReadWrite, 0, isAsync: true);
        await client.WriteAsync(new byte[] { 1 }).AsTask().WaitAsync(Timeout);
        // No Flush: FlushFileBuffers on a pipe blocks until the server has read the data.

        var identity = await probe.ClientIdentityAfterOneByteAsync().WaitAsync(Timeout);
        output.WriteLine($"identity seen by server: {identity ?? "(impersonation failed)"}");

        Assert.True(identity is null || identity.Contains("ANONYMOUS", StringComparison.OrdinalIgnoreCase),
            $"pipe server impersonated the client as '{identity}'");
        Assert.NotEqual(WindowsIdentity.GetCurrent().Name, identity);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task HasherOpenThroughSymlink_IsNonDiskHandle_AndSendsNothing()
    {
        // The hasher's own open, held open on purpose, through a symlink to the pipe: it is seen as a
        // non-disk handle and the read-only client never sends a byte. This does NOT prove the anonymous
        // impersonation level (a silent client can't be impersonated with any flags); that guarantee is
        // HashingFlags_GiveThePipeServerOnlyAnonymousImpersonation + HashingFlags_AreExplicit.
        await using var probe = new PipeProbe();
        var link = _dir.File("to-pipe-imp.bin");
        CreateSymlink(link, probe.Path);

        using var handle = NativeFile.OpenForHashing(Path.GetFullPath(link), out int error);
        Assert.False(handle.IsInvalid, $"Win32 error {error}");
        Assert.NotEqual(NativeFile.FileTypeDisk, NativeFile.GetFileType(handle));

        Assert.Null(await probe.ClientIdentityAfterOneByteAsync().WaitAsync(Timeout)); // read-only client sends nothing to impersonate
    }

    // --- Direct device paths are never opened ---

    [Fact]
    public async Task DirectPipePath_IsNeverOpened()
    {
        await using var probe = new PipeProbe(); // disposed even if an assertion fails (dispose is idempotent)
        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(probe.Path));

        Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
        output.WriteLine($"path taken: {result.ErrorMessage}");
        Assert.False(await probe.WasConnectedAsync());
        await probe.DisposeAsync();
        Assert.False(PipeProbe.Exists(probe.Name));
    }

    [Theory]
    [InlineData(@"\\?\pipe\")]
    [InlineData(@"//./pipe/")]
    public async Task DirectPipePath_OtherSpellings_AreNeverOpened(string prefix)
    {
        await using var probe = new PipeProbe();

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(prefix + probe.Name));

        Assert.Equal(HashFailureReason.NotRegularFile, result.FailureReason);
        Assert.False(await probe.WasConnectedAsync());
    }

    // --- Links to pipes: (a) NotRegularFile, (b) no I/O ---

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToPipe_IsRejected_WithoutIo()
    {
        await using var probe = new PipeProbe();
        var link = _dir.File("to-pipe.bin");
        CreateSymlink(link, probe.Path);

        await AssertPipeRejectedWithoutIo(probe, link);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task ChainOf16LinksToPipe_IsRejected_WithoutIo()
    {
        await using var probe = new PipeProbe();
        var head = CreateChain(16, probe.Path);

        await AssertPipeRejectedWithoutIo(probe, head);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task ChainOf17LinksToPipe_IsRejected_WithoutIo()
    {
        // No hop limit of our own any more: Windows follows the chain (up to 63 reparse points) and the
        // file-type check rejects the pipe before any read.
        await using var probe = new PipeProbe();
        var head = CreateChain(17, probe.Path);

        await AssertPipeRejectedWithoutIo(probe, head);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task RelativeHopsAcrossDirectories_ToPipe_AreRejected_WithoutIo()
    {
        // a\l1 -> ..\b\l2 ; b\l2 -> l3 (must resolve in b, not a) ; b\l3 -> pipe
        await using var probe = new PipeProbe();
        Directory.CreateDirectory(_dir.File("a"));
        Directory.CreateDirectory(_dir.File("b"));
        File.WriteAllBytes(_dir.File(@"a\l3"), Data(10)); // decoy: wrong resolution would hash this
        CreateSymlink(_dir.File(@"b\l3"), probe.Path);
        CreateSymlink(_dir.File(@"b\l2"), "l3");
        CreateSymlink(_dir.File(@"a\l1"), @"..\b\l2");

        await AssertPipeRejectedWithoutIo(probe, _dir.File(@"a\l1"));
    }

    [RequiresFact(Requires.Symlinks, Requires.Junctions)]
    public async Task SymlinkToPipe_InsideAJunctionedFolder_IsRejected_WithoutIo()
    {
        await using var probe = new PipeProbe();
        var real = _dir.File("real");
        Directory.CreateDirectory(real);
        CreateSymlink(Path.Combine(real, "p.bin"), probe.Path);
        CreateJunction(_dir.File("junc"), real);

        await AssertPipeRejectedWithoutIo(probe, _dir.File(@"junc\p.bin"));
    }

    [RequiresFact(Requires.PipeNamespaceJunction)]
    public async Task FileUnderAJunctionThatPointsAtThePipeNamespace_IsRejected_WithoutIo()
    {
        // C:\...\j -> \??\pipe\ ; hash C:\...\j\<name>. A string walk never sees this; the open check does.
        // mklink /J refuses non-volume targets, so the reparse point is written directly.
        await using var probe = new PipeProbe();
        var junc = _dir.File("j");
        Assert.Null(RawJunction.TryCreate(junc, @"\??\pipe\")); // guaranteed by Requires.PipeNamespaceJunction

        await AssertPipeRejectedWithoutIo(probe, Path.Combine(junc, probe.Name));
    }

    [RequiresFact(Requires.PipeNamespaceJunction)]
    public async Task JunctionToPipeNamespace_SeenFromTheJunctionItself_IsNotHashed()
    {
        var junc = _dir.File("j2");
        Assert.Null(RawJunction.TryCreate(junc, @"\??\pipe\")); // guaranteed by Requires.PipeNamespaceJunction

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(junc));
        output.WriteLine($"path taken: {result.FailureReason}: {result.ErrorMessage}");

        Assert.False(result.IsHashed);
        Assert.Equal(ScanStatus.Error, result.Status);
    }

    // --- Loops and long chains ---

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkLoop_TwoLinks_FailsCleanly_WithoutHanging()
    {
        var a = _dir.File("a.bin");
        var b = _dir.File("b.bin");
        CreateSymlink(a, "b.bin");
        CreateSymlink(b, "a.bin");

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(a));

        Assert.False(result.IsHashed);
        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.NotEqual(HashFailureReason.None, result.FailureReason);
        output.WriteLine($"loop -> {result.FailureReason}: {result.ErrorMessage}");
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToItself_FailsCleanly_WithoutHanging()
    {
        var self = _dir.File("self.bin");
        CreateSymlink(self, "self.bin");

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(self));

        Assert.False(result.IsHashed);
        Assert.Equal(ScanStatus.Error, result.Status);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task ChainOf20LinksToRegularFile_IsHashed()
    {
        var data = Data(321);
        var target = _dir.WriteFile("final.bin", data);
        var head = CreateChain(20, target);

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(head));

        Assert.True(result.IsHashed, $"{result.FailureReason}: {result.ErrorMessage}");
        Assert.Equal(Sha(data), result.Sha256);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task DanglingSymlink_IsNotFound()
    {
        var link = _dir.File("dangling.bin");
        CreateSymlink(link, _dir.File("missing.bin"));

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(link));

        Assert.Equal(HashFailureReason.NotFound, result.FailureReason);
    }

    // --- Relative targets ---

    [RequiresFact(Requires.Symlinks)]
    public async Task RelativeSymlinkTarget_WithParentSegment_IsHashed()
    {
        var data = Data(77);
        _dir.WriteFile("up.bin", data);
        Directory.CreateDirectory(_dir.File("sub"));
        var link = _dir.File(@"sub\rel.bin");
        CreateSymlink(link, @"..\up.bin");

        var result = await new Sha256Hasher().HashFileAsync(link);

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Sha(data), result.Sha256);
    }

    // --- Junctions and directory links ---

    [RequiresFact(Requires.Junctions)]
    public async Task Junction_ToAnotherFolder_IsDirectory()
    {
        var real = _dir.File("elsewhere");
        Directory.CreateDirectory(real);
        var junc = _dir.File("junction");
        CreateJunction(junc, real);

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(junc));

        Assert.Equal(HashFailureReason.Directory, result.FailureReason);
        Assert.False(result.IsHashed);
    }

    [RequiresFact(Requires.Junctions)]
    public async Task FileThroughAJunction_IsHashed()
    {
        var real = _dir.File("elsewhere");
        Directory.CreateDirectory(real);
        var data = Data(500);
        File.WriteAllBytes(Path.Combine(real, "f.bin"), data);
        var junc = _dir.File("junction");
        CreateJunction(junc, real);

        var result = await new Sha256Hasher().HashFileAsync(Path.Combine(junc, "f.bin"));

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Sha(data), result.Sha256);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task DirectorySymlink_IsDirectory()
    {
        var real = _dir.File("realdir");
        Directory.CreateDirectory(real);
        var link = _dir.File("dirlink");
        Directory.CreateSymbolicLink(link, real);

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(link));

        Assert.Equal(HashFailureReason.Directory, result.FailureReason);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task FileSymlinkPointingAtADirectory_IsDirectory()
    {
        var real = _dir.File("realdir");
        Directory.CreateDirectory(real);
        var link = _dir.File("file-flavored-link");
        CreateSymlink(link, real);

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(link));

        Assert.False(result.IsHashed);
        Assert.Equal(HashFailureReason.Directory, result.FailureReason);
    }

    // --- Metadata comes from the target, not the link ---

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToRegularFile_MetadataIsFromTheTarget()
    {
        var data = Data(1234);
        var target = _dir.WriteFile("target.bin", data);
        var targetTime = new DateTime(2024, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(target, targetTime);
        File.SetAttributes(target, FileAttributes.ReadOnly | FileAttributes.Archive);

        var link = _dir.File("link.bin");
        try
        {
            CreateSymlink(link, target);

            var result = await new Sha256Hasher().HashFileAsync(link);

            Assert.True(result.IsHashed, result.ErrorMessage);
            Assert.Equal(Sha(data), result.Sha256);
            Assert.Equal(1234, result.Length);
            Assert.Equal(targetTime, result.LastWriteTimeUtc);
            Assert.NotEqual(new FileInfo(link).LastWriteTimeUtc, result.LastWriteTimeUtc); // link's own time differs
            Assert.NotNull(result.Attributes);
            Assert.False(result.Attributes!.Value.HasFlag(FileAttributes.ReparsePoint), "attributes are the link's, not the target's");
            Assert.True(result.Attributes.Value.HasFlag(FileAttributes.ReadOnly));
        }
        finally
        {
            File.SetAttributes(target, FileAttributes.Normal);
        }
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToOfflineFile_IsSkippedOffline()
    {
        var target = _dir.WriteFile("offline-target.bin", Data(40));
        var link = _dir.File("to-offline.bin");
        File.SetAttributes(target, FileAttributes.Offline);
        try
        {
            CreateSymlink(link, target);

            var result = await new Sha256Hasher().HashFileAsync(link);

            Assert.Equal(ScanStatus.SkippedOffline, result.Status);
            Assert.Equal(HashFailureReason.Offline, result.FailureReason);
            Assert.Null(result.Sha256);
        }
        finally
        {
            File.SetAttributes(target, FileAttributes.Normal);
        }
    }
}
