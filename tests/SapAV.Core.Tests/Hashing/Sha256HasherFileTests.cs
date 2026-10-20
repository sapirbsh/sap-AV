using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Hashing;

/// <summary>File-path hashing against real temp files (benign content only; no AV test file on disk).</summary>
public sealed class Sha256HasherFileTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        new Random(7).NextBytes(bytes);
        return bytes;
    }

    [Fact]
    public async Task File_IsHashed_AcrossManyBuffers()
    {
        var data = RandomBytes(300_000);
        var path = _dir.WriteFile("data.bin", data);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.True(result.IsHashed);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), result.Sha256);
        Assert.Equal(data.Length, result.Length);
    }

    [Fact]
    public async Task EmptyFile_HasKnownHash()
    {
        var path = _dir.WriteFile("empty.bin", []);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result.Sha256);
    }

    [Theory]
    [InlineData(99, ScanStatus.Scanned)]
    [InlineData(100, ScanStatus.Scanned)]
    [InlineData(101, ScanStatus.SkippedTooLarge)]
    public async Task SizeLimit_UnderAtOver(int size, ScanStatus expected)
    {
        var path = _dir.WriteFile($"f{size}.bin", RandomBytes(size));

        var result = await new Sha256Hasher(maxSizeBytes: 100, bufferSize: 16).HashFileAsync(path);

        Assert.Equal(expected, result.Status);
        Assert.Equal(size, result.Length);
        Assert.Equal(expected == ScanStatus.Scanned, result.Sha256 is not null);
    }

    [Fact]
    public async Task OversizeFile_MapsToSkippedTooLargeScanResult()
    {
        var path = _dir.WriteFile("big.bin", RandomBytes(2048));
        var item = new ScanItem(path, ScanTrigger.CustomScan);

        var hash = await new Sha256Hasher(maxSizeBytes: 1024).HashFileAsync(path);
        var scan = hash.ToNotScannedResult(item, DateTimeOffset.UnixEpoch);

        Assert.Equal(ScanStatus.SkippedTooLarge, scan.Status);
        Assert.Null(scan.Verdict);
    }

    [Fact]
    public async Task FileOpenedWithFileShareNone_IsLocked()
    {
        var path = _dir.WriteFile("locked.bin", RandomBytes(10));
        await using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.Equal(ScanStatus.Locked, result.Status);
        Assert.Equal(HashFailureReason.Locked, result.FailureReason);
        Assert.Null(result.Sha256);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public async Task FileOpenForWritingByAnotherHandle_CanStillBeHashed()
    {
        // The other handle has write access and only shares Read. Our open must share Write
        // (FileShare.ReadWrite), or this would be a sharing violation.
        var data = RandomBytes(500);
        var path = _dir.WriteFile("writing.bin", data);
        await using var writer = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), result.Sha256);
    }

    [Fact]
    public async Task FileOpenWithDeleteAccessByAnotherHandle_CanStillBeHashed()
    {
        // DeleteOnClose makes the other handle hold DELETE access; Windows then only allows opens that
        // share Delete. This proves our open uses FileShare.Delete (so we never block a delete/rename).
        var data = RandomBytes(300);
        var path = _dir.WriteFile("deletable.bin", data);
        await using var other = new FileStream(
            path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 1, FileOptions.DeleteOnClose);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), result.Sha256);
    }

    [Fact]
    public async Task MissingFile_IsError()
    {
        var result = await new Sha256Hasher().HashFileAsync(_dir.File("does-not-exist.bin"));

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(HashFailureReason.NotFound, result.FailureReason);
        Assert.Null(result.Sha256);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public async Task MissingDirectory_IsError()
    {
        var result = await new Sha256Hasher().HashFileAsync(Path.Combine(_dir.Path, "no-such-dir", "x.bin"));

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(HashFailureReason.NotFound, result.FailureReason);
    }

    [Fact]
    public async Task FileWithReadDenied_IsAccessDenied()
    {
        var path = _dir.WriteFile("denied.bin", RandomBytes(10));
        var file = new FileInfo(path);
        var user = WindowsIdentity.GetCurrent().User!;
        var deny = new FileSystemAccessRule(user, FileSystemRights.ReadData, AccessControlType.Deny);

        var security = file.GetAccessControl();
        security.AddAccessRule(deny);
        file.SetAccessControl(security);
        try
        {
            var result = await new Sha256Hasher().HashFileAsync(path);

            Assert.Equal(ScanStatus.AccessDenied, result.Status);
            Assert.Equal(HashFailureReason.AccessDenied, result.FailureReason);
            Assert.Null(result.Sha256);
        }
        finally
        {
            var restore = file.GetAccessControl();
            restore.RemoveAccessRule(deny);
            file.SetAccessControl(restore);
        }
    }

    [Fact]
    public async Task PreCanceledToken_Throws_EvenForMissingFile()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var hasher = new Sha256Hasher();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => hasher.HashFileAsync(_dir.WriteFile("c.bin", [1, 2, 3]), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => hasher.HashFileAsync(_dir.File("missing.bin"), cts.Token));
    }

    [Fact]
    public async Task CancellationDuringFileHashing_Throws()
    {
        // 8 MiB through a 16-byte buffer is ~500k reads, far longer than the timer. The loop checks the
        // token every iteration, so this works even if reads complete synchronously.
        var path = _dir.WriteFile("long.bin", RandomBytes(8 * 1024 * 1024));
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(20));
        var hasher = new Sha256Hasher(bufferSize: 16);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => hasher.HashFileAsync(path, cts.Token));
    }

    [Fact]
    public async Task NullPath_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => new Sha256Hasher().HashFileAsync(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("C:\\temp\\a\0b.bin")]
    [InlineData("\0")]
    public async Task EmptyBlankOrNulPath_IsInvalidPath_NotThrown(string path)
    {
        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(HashFailureReason.InvalidPath, result.FailureReason);
        Assert.Null(result.Sha256);
    }
}
