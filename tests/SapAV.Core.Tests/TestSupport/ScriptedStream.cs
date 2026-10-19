namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Test stream over an in-memory byte array, with knobs for seekability, a fake reported length
/// (to simulate a file that grows after its size was taken), read callbacks and injected failures.
/// </summary>
internal sealed class ScriptedStream(byte[] data) : Stream
{
    private long _position;

    public bool Seekable { get; init; } = true;

    /// <summary>Length reported by <see cref="Length"/>; defaults to the real data length.</summary>
    public long? ReportedLength { get; init; }

    /// <summary>Called before each read with the 1-based read number.</summary>
    public Action<int>? BeforeRead { get; init; }

    /// <summary>Thrown from the read with this 1-based number (default: never).</summary>
    public Exception? FailWith { get; init; }

    public int FailOnRead { get; init; } = 1;

    public long TotalBytesRead { get; private set; }

    public int ReadCount { get; private set; }

    public override bool CanRead => true;
    public override bool CanSeek => Seekable;
    public override bool CanWrite => false;

    public override long Length =>
        Seekable ? ReportedLength ?? data.Length : throw new NotSupportedException();

    public override long Position
    {
        get => Seekable ? _position : throw new NotSupportedException();
        set => _position = Seekable ? value : throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ReadCount++;
        BeforeRead?.Invoke(ReadCount);
        if (FailWith is not null && ReadCount == FailOnRead)
        {
            throw FailWith;
        }

        int n = (int)Math.Min(buffer.Length, data.Length - _position);
        data.AsSpan((int)_position, n).CopyTo(buffer);
        _position += n;
        TotalBytesRead += n;
        return n;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
