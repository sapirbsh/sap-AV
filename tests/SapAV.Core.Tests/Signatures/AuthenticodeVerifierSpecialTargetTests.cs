using SapAV.Core.Hashing;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Signatures;

/// <summary>
/// Devices, pipes, directories, links, offline files and bad paths: always a not-checked result, never an
/// exception, and never a read from a pipe. Same guarantees as the hasher, because it's the same open path.
/// </summary>
public sealed class AuthenticodeVerifierSpecialTargetTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly AuthenticodeVerifier _verifier = new();

    public void Dispose() => _dir.Dispose();

    private SignatureCheckResult Verify(string path)
    {
        var result = _verifier.Verify(path);
        output.WriteLine($"{path}: checked={result.IsChecked} {result.NotCheckedReason}: {result.Message}");
        return result;
    }

    private static void AssertNotChecked(SignatureCheckResult result, HashFailureReason expected)
    {
        Assert.False(result.IsChecked);
        Assert.Null(result.Status);
        Assert.Equal(expected, result.NotCheckedReason);
        Assert.Equal(SignatureFailureReason.None, result.FailureReason);
        Assert.Equal(SignatureKind.None, result.Kind);
        Assert.Null(result.Signer);
        Assert.Null(result.TrustedSignerName);
    }

    [Theory]
    [InlineData(@"\\.\NUL")]
    [InlineData(@"\\.\pipe\sapav-no-such-pipe")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\.\C:")]
    [InlineData(@"\\?\GLOBALROOT\Device\Null")]
    [InlineData("NUL")]
    [InlineData("CON")]
    [InlineData("COM1")]
    public void DevicePaths_AreNotRegularFile_AndNotOpened(string path)
    {
        AssertNotChecked(Verify(path), HashFailureReason.NotRegularFile);
    }

    [Fact]
    public async Task LiveNamedPipe_IsNeverOpened()
    {
        await using var probe = new PipeProbe();

        AssertNotChecked(Verify(probe.Path), HashFailureReason.NotRegularFile);
        Assert.False(await probe.WasConnectedAsync());
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToNamedPipe_IsNotRegularFile_NothingWritten_AndReleased()
    {
        await using var probe = new PipeProbe();
        var link = _dir.File("to-pipe.exe");
        File.CreateSymbolicLink(link, probe.Path);

        AssertNotChecked(Verify(link), HashFailureReason.NotRegularFile);
        if (await probe.WasConnectedAsync())
        {
            Assert.True(await probe.ClientDisconnectedAsync(TimeSpan.FromSeconds(2)), "the verifier's pipe handle is still open");
        }
    }

    [RequiresFact(Requires.PipeNamespaceJunction)]
    public void JunctionToThePipeFileSystem_IsNotRegularFile_AfterGetFileType()
    {
        var junction = _dir.File("j");
        Assert.Null(RawJunction.TryCreate(junction, @"\??\pipe\"));

        var result = Verify(junction);

        AssertNotChecked(result, HashFailureReason.NotRegularFile);
        Assert.Contains("file type", result.Message);
    }

    [Fact]
    public void Directory_IsNotChecked()
    {
        AssertNotChecked(Verify(_dir.Path), HashFailureReason.Directory);
        AssertNotChecked(Verify(Environment.GetFolderPath(Environment.SpecialFolder.Windows)), HashFailureReason.Directory);
    }

    [RequiresFact(Requires.Symlinks, Requires.SignedDotNetRuntime)]
    public void SymlinkToSignedFile_IsCheckedAsTheTarget()
    {
        var target = SignedSamples.RequireEmbeddedSignedMicrosoftDll();
        var link = _dir.File("link.dll");
        File.CreateSymbolicLink(link, target);

        Assert.Equal(SignatureStatus.Microsoft, Verify(link).Status);
    }

    [Fact]
    public void OfflineFile_IsNotChecked_Offline()
    {
        var path = _dir.WriteFile("offline.exe", [0x4D, 0x5A]);
        File.SetAttributes(path, FileAttributes.Offline);
        try
        {
            AssertNotChecked(Verify(path), HashFailureReason.Offline);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    [Fact]
    public void MissingFile_IsNotFound()
    {
        AssertNotChecked(Verify(_dir.File("nope.exe")), HashFailureReason.NotFound);
        AssertNotChecked(Verify(Path.Combine(_dir.Path, "no-dir", "nope.exe")), HashFailureReason.NotFound);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("C:\\a\0b.exe")]
    public void InvalidPaths_AreInvalidPath(string path)
    {
        AssertNotChecked(Verify(path), HashFailureReason.InvalidPath);
    }

    [Fact]
    public void NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _verifier.Verify(null!));
    }

    [Fact]
    public void CanceledToken_Throws_BeforeOpening()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => _verifier.Verify(_dir.File("x.exe"), cts.Token));
    }

    [Fact]
    public void ExclusivelyLockedFile_IsLocked()
    {
        var path = _dir.WriteFile("locked.exe", [1, 2, 3]);
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        AssertNotChecked(Verify(path), HashFailureReason.Locked);
    }
}
