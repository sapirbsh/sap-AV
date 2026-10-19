using System.Security.Cryptography;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Hashing;

/// <summary>Size-limit edges (limit / limit+1) for files and streams, plus empty-file details.</summary>
public sealed class Sha256HasherBoundaryTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        new Random(123).NextBytes(bytes);
        return bytes;
    }

    private static string Expected(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    // Buffer smaller than, equal to, dividing, and larger than the limit; the read cap (limit + 1)
    // must work in each case.
    [Theory]
    [InlineData(64, 1)]
    [InlineData(64, 7)]
    [InlineData(64, 16)]   // limit is a multiple of the buffer
    [InlineData(64, 64)]   // buffer == limit
    [InlineData(64, 65)]   // buffer == limit + 1
    [InlineData(64, 4096)] // buffer much larger than limit
    public async Task File_ExactlyAtLimit_IsHashed(int limit, int bufferSize)
    {
        var data = RandomBytes(limit);
        var path = _dir.WriteFile($"at-{bufferSize}.bin", data);

        var result = await new Sha256Hasher(limit, bufferSize).HashFileAsync(path);

        Assert.Equal(ScanStatus.Scanned, result.Status);
        Assert.Equal(Expected(data), result.Sha256);
        Assert.Equal(limit, result.Length);
    }

    [Theory]
    [InlineData(64, 1)]
    [InlineData(64, 16)]
    [InlineData(64, 64)]
    [InlineData(64, 65)]
    [InlineData(64, 4096)]
    public async Task File_LimitPlusOne_IsSkipped(int limit, int bufferSize)
    {
        var path = _dir.WriteFile($"over-{bufferSize}.bin", RandomBytes(limit + 1));

        var result = await new Sha256Hasher(limit, bufferSize).HashFileAsync(path);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Null(result.Sha256);
        Assert.Equal(limit + 1, result.Length);
    }

    [Theory]
    [InlineData(true, 1)]
    [InlineData(true, 16)]
    [InlineData(true, 64)]
    [InlineData(true, 4096)]
    [InlineData(false, 1)]
    [InlineData(false, 16)]
    [InlineData(false, 64)]
    [InlineData(false, 65)]
    [InlineData(false, 4096)]
    public async Task Stream_ExactlyAtLimit_IsHashed(bool seekable, int bufferSize)
    {
        const int limit = 64;
        var data = RandomBytes(limit);
        var stream = new ScriptedStream(data) { Seekable = seekable };

        var result = await new Sha256Hasher(limit, bufferSize).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.Scanned, result.Status);
        Assert.Equal(Expected(data), result.Sha256);
        Assert.Equal(limit, result.Length);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(4096)]
    public async Task NonSeekableStream_LimitPlusOne_IsSkipped_AfterReadingExactlyLimitPlusOne(int bufferSize)
    {
        const int limit = 64;
        var stream = new ScriptedStream(RandomBytes(limit + 1)) { Seekable = false };

        var result = await new Sha256Hasher(limit, bufferSize).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Null(result.Sha256);
        Assert.Equal(limit + 1, result.Length);
        Assert.Equal(limit + 1, stream.TotalBytesRead);
    }

    [Fact]
    public async Task NonSeekableStream_FarOverLimit_StopsAtLimitPlusOne_WithSmallBuffer()
    {
        // Cap must also hold when the overflow byte lands in the middle of a buffer.
        const int limit = 100;
        var stream = new ScriptedStream(RandomBytes(10_000)) { Seekable = false };

        var result = await new Sha256Hasher(limit, bufferSize: 7).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Equal(limit + 1, result.Length);
        Assert.Equal(limit + 1, stream.TotalBytesRead);
    }

    [Fact]
    public async Task SeekableStream_LimitPlusOne_IsSkipped_WithoutReading()
    {
        const int limit = 64;
        var stream = new ScriptedStream(RandomBytes(limit + 1));

        var result = await new Sha256Hasher(limit, bufferSize: 16).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Equal(limit + 1, result.Length);
        Assert.Equal(0, stream.ReadCount);
    }

    [Fact]
    public async Task EmptyFile_IsScanned_WithLengthZero()
    {
        var path = _dir.WriteFile("empty.bin", []);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.Equal(ScanStatus.Scanned, result.Status);
        Assert.True(result.IsHashed);
        Assert.Equal(0, result.Length);
        Assert.Null(result.ErrorMessage);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result.Sha256);
    }

    [Fact]
    public async Task EmptyFile_WithZeroLimit_IsScanned()
    {
        var path = _dir.WriteFile("empty0.bin", []);

        var result = await new Sha256Hasher(maxSizeBytes: 0).HashFileAsync(path);

        Assert.Equal(ScanStatus.Scanned, result.Status);
        Assert.Equal(0, result.Length);
    }

    [Fact]
    public async Task OneByteFile_WithZeroLimit_IsSkipped()
    {
        var path = _dir.WriteFile("one.bin", [0x41]);

        var result = await new Sha256Hasher(maxSizeBytes: 0).HashFileAsync(path);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Equal(1, result.Length);
    }
}
