using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Hashing;

public class Sha256HasherStreamTests
{
    private const string EmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string AbcSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static byte[] RandomBytes(int count, int seed = 42)
    {
        var bytes = new byte[count];
        new Random(seed).NextBytes(bytes);
        return bytes;
    }

    private static string Expected(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA256.HashData(data));

    // --- Known hashes ---

    [Fact]
    public async Task EmptyInput_HasKnownHash()
    {
        var result = await new Sha256Hasher().HashStreamAsync(new MemoryStream());

        Assert.True(result.IsHashed);
        Assert.Equal(EmptySha256, result.Sha256);
        Assert.Equal(0, result.Length);
    }

    [Fact]
    public async Task Abc_HasKnownHash()
    {
        var result = await new Sha256Hasher().HashStreamAsync(new MemoryStream(Encoding.ASCII.GetBytes("abc")));

        Assert.Equal(AbcSha256, result.Sha256);
        Assert.Equal(3, result.Length);
    }

    [Fact]
    public async Task AvTestString_FromMemory_HasPublishedSha256()
    {
        var result = await new Sha256Hasher().HashStreamAsync(new MemoryStream(Eicar.Bytes()));

        Assert.True(result.IsHashed);
        Assert.Equal(Eicar.KnownSha256, result.Sha256);
        Assert.Equal(68, result.Length);
    }

    // --- Streaming ---

    [Theory]
    [InlineData(4096, 1024 * 1024 + 7)]   // many full buffers + a partial one
    [InlineData(4096, 4096)]              // exactly one buffer
    [InlineData(4096, 4097)]              // one byte into the second buffer
    [InlineData(1, 1000)]                 // 1-byte buffer
    public async Task InputLargerThanBuffer_MatchesOneShotHash(int bufferSize, int size)
    {
        var data = RandomBytes(size);
        var stream = new ScriptedStream(data);

        var result = await new Sha256Hasher(bufferSize: bufferSize).HashStreamAsync(stream);

        Assert.Equal(Expected(data), result.Sha256);
        Assert.Equal(size, result.Length);
        Assert.True(stream.ReadCount >= size / bufferSize, "should read in buffer-sized chunks");
    }

    [Fact]
    public async Task NonSeekableStream_IsHashed()
    {
        var data = RandomBytes(10_000);

        var result = await new Sha256Hasher(bufferSize: 512).HashStreamAsync(new ScriptedStream(data) { Seekable = false });

        Assert.Equal(Expected(data), result.Sha256);
    }

    [Fact]
    public async Task HashesFromCurrentPosition_AndLeavesStreamOpen()
    {
        var data = RandomBytes(100);
        var stream = new MemoryStream(data) { Position = 40 };

        var result = await new Sha256Hasher(maxSizeBytes: 60).HashStreamAsync(stream);

        Assert.Equal(Expected(data.AsSpan(40)), result.Sha256);
        Assert.Equal(60, result.Length);
        Assert.True(stream.CanRead); // not disposed
    }

    // --- Size limit ---

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SizeUnderAndAtLimit_IsHashed(bool seekable)
    {
        var hasher = new Sha256Hasher(maxSizeBytes: 10, bufferSize: 3);

        var under = await hasher.HashStreamAsync(new ScriptedStream(RandomBytes(9)) { Seekable = seekable });
        var at = await hasher.HashStreamAsync(new ScriptedStream(RandomBytes(10)) { Seekable = seekable });

        Assert.True(under.IsHashed);
        Assert.True(at.IsHashed);
        Assert.Equal(Expected(RandomBytes(10)), at.Sha256);
    }

    [Fact]
    public async Task SeekableOverLimit_IsSkipped_WithoutReading()
    {
        var stream = new ScriptedStream(RandomBytes(11));

        var result = await new Sha256Hasher(maxSizeBytes: 10).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.False(result.IsHashed);
        Assert.Null(result.Sha256);
        Assert.Equal(11, result.Length);
        Assert.Equal(0, stream.ReadCount);
    }

    [Fact]
    public async Task NonSeekableOverLimit_IsSkipped_ReadingAtMostLimitPlusOne()
    {
        var stream = new ScriptedStream(RandomBytes(100_000)) { Seekable = false };

        var result = await new Sha256Hasher(maxSizeBytes: 10, bufferSize: 4096).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Equal(11, result.Length);
        Assert.Equal(11, stream.TotalBytesRead);
    }

    [Fact]
    public async Task ContentGrowingPastReportedLength_IsSkipped_NotReadPastLimit()
    {
        // Reported size is under the limit (as when a file grows after it was opened),
        // but the content keeps coming.
        var stream = new ScriptedStream(RandomBytes(1_000_000)) { ReportedLength = 5 };

        var result = await new Sha256Hasher(maxSizeBytes: 1000, bufferSize: 64).HashStreamAsync(stream);

        Assert.Equal(ScanStatus.SkippedTooLarge, result.Status);
        Assert.Equal(1001, result.Length);
        Assert.Equal(1001, stream.TotalBytesRead);
    }

    [Fact]
    public async Task ZeroLimit_HashesOnlyEmptyContent()
    {
        var hasher = new Sha256Hasher(maxSizeBytes: 0);

        Assert.Equal(EmptySha256, (await hasher.HashStreamAsync(new MemoryStream())).Sha256);
        Assert.Equal(ScanStatus.SkippedTooLarge, (await hasher.HashStreamAsync(new MemoryStream([1]))).Status);
        Assert.Equal(ScanStatus.SkippedTooLarge,
            (await hasher.HashStreamAsync(new ScriptedStream([1]) { Seekable = false })).Status);
    }

    [Fact]
    public async Task MaxLongLimit_DoesNotOverflow()
    {
        var result = await new Sha256Hasher(maxSizeBytes: long.MaxValue)
            .HashStreamAsync(new ScriptedStream(Encoding.ASCII.GetBytes("abc")) { Seekable = false });

        Assert.Equal(AbcSha256, result.Sha256);
    }

    // --- Cancellation ---

    [Fact]
    public async Task PreCanceledToken_Throws()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new Sha256Hasher().HashStreamAsync(new MemoryStream([1, 2, 3]), cts.Token));
    }

    [Fact]
    public async Task CancellationDuringHashing_Throws_AndStopsReading()
    {
        using var cts = new CancellationTokenSource();
        var stream = new ScriptedStream(RandomBytes(100_000))
        {
            BeforeRead = n => { if (n == 3) cts.Cancel(); },
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new Sha256Hasher(bufferSize: 100).HashStreamAsync(stream, cts.Token));
        Assert.True(stream.ReadCount <= 4, $"kept reading after cancel: {stream.ReadCount} reads");
    }

    [Fact]
    public async Task OperationCanceledFromStream_IsNotSwallowed()
    {
        var stream = new ScriptedStream(RandomBytes(10)) { FailWith = new OperationCanceledException() };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new Sha256Hasher().HashStreamAsync(stream));
    }

    // --- Read failures map to a status instead of throwing ---

    public static TheoryData<Exception, ScanStatus> ReadFailures => new()
    {
        { new IOException("sharing", unchecked((int)0x80070020)), ScanStatus.Locked },  // ERROR_SHARING_VIOLATION
        { new IOException("lock", unchecked((int)0x80070021)), ScanStatus.Locked },     // ERROR_LOCK_VIOLATION
        { new UnauthorizedAccessException("denied"), ScanStatus.AccessDenied },
        { new IOException("device error"), ScanStatus.Error },
        { new FileNotFoundException("gone"), ScanStatus.Error },
    };

    [Theory]
    [MemberData(nameof(ReadFailures))]
    public async Task ReadFailure_MapsToStatus(Exception failure, ScanStatus expected)
    {
        var stream = new ScriptedStream(RandomBytes(1000)) { FailWith = failure, FailOnRead = 2 };

        var result = await new Sha256Hasher(bufferSize: 100).HashStreamAsync(stream);

        Assert.Equal(expected, result.Status);
        Assert.Null(result.Sha256);
        Assert.Equal(failure.Message, result.ErrorMessage);
    }

    [Fact]
    public async Task UnexpectedException_IsNotSwallowed()
    {
        var stream = new ScriptedStream(RandomBytes(10)) { FailWith = new InvalidOperationException("bug") };

        await Assert.ThrowsAsync<InvalidOperationException>(() => new Sha256Hasher().HashStreamAsync(stream));
    }

    // --- Argument validation ---

    [Fact]
    public async Task RejectsNullOrUnreadableStream()
    {
        var hasher = new Sha256Hasher();
        await Assert.ThrowsAsync<ArgumentNullException>(() => hasher.HashStreamAsync(null!));

        var disposed = new MemoryStream();
        disposed.Dispose();
        await Assert.ThrowsAsync<ArgumentException>(() => hasher.HashStreamAsync(disposed));
    }

    [Fact]
    public void Constructor_RejectsBadOptions()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Sha256Hasher(maxSizeBytes: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Sha256Hasher(bufferSize: 0));
        Assert.Equal(Sha256Hasher.DefaultMaxSizeBytes, new Sha256Hasher().MaxSizeBytes);
    }
}
