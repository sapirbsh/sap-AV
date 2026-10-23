namespace SapAV.Engine.Scanning;

/// <summary>
/// Smoothed scan throughput and ETA. Completed work is collected in sample windows of at least
/// <see cref="SampleInterval"/>; each closed window updates an exponentially weighted moving average of bytes/s and
/// files/s (weight <see cref="Smoothing"/> for the newest window), so one slow or fast file doesn't swing the ETA.
/// Not thread-safe (the job calls it under its lock).
/// </summary>
internal sealed class ThroughputEstimator(TimeProvider time)
{
    /// <summary>Shortest sample window.</summary>
    public TimeSpan SampleInterval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Weight of the newest window in the moving average (0-1].</summary>
    public double Smoothing { get; init; } = 0.3;

    private DateTimeOffset? _windowStart;
    private long _windowBytes;
    private long _windowFiles;

    /// <summary>Smoothed bytes per second, or null before the first full window.</summary>
    public double? BytesPerSecond { get; private set; }

    /// <summary>Smoothed files per second, or null before the first full window.</summary>
    public double? FilesPerSecond { get; private set; }

    /// <summary>Starts a new window now, dropping the open one (call at start and on resume, so paused time never counts).</summary>
    public void Restart()
    {
        _windowStart = time.GetUtcNow();
        _windowBytes = 0;
        _windowFiles = 0;
    }

    /// <summary>Counts finished work; closes the window if it is at least <see cref="SampleInterval"/> long.</summary>
    public void Record(long bytes, long files)
    {
        var now = time.GetUtcNow();
        _windowStart ??= now;
        _windowBytes += Math.Max(0, bytes);
        _windowFiles += Math.Max(0, files);
        var elapsed = now - _windowStart.Value;
        if (elapsed < SampleInterval)
        {
            return;
        }

        double seconds = elapsed.TotalSeconds;
        BytesPerSecond = Blend(BytesPerSecond, _windowBytes / seconds);
        FilesPerSecond = Blend(FilesPerSecond, _windowFiles / seconds);
        _windowStart = now;
        _windowBytes = 0;
        _windowFiles = 0;
    }

    /// <summary>
    /// Time left for the remaining work: by bytes when there are bytes left and a byte rate, else by files; null when
    /// there is no rate yet. Zero when nothing is left.
    /// </summary>
    public TimeSpan? Estimate(long remainingBytes, long remainingFiles)
    {
        if (remainingFiles <= 0)
        {
            return TimeSpan.Zero;
        }

        double? seconds =
            remainingBytes > 0 && BytesPerSecond is > 0 and var bps ? remainingBytes / bps
            : FilesPerSecond is > 0 and var fps ? remainingFiles / fps
            : null;
        return seconds is { } s ? TimeSpan.FromSeconds(Math.Min(s, TimeSpan.MaxValue.TotalSeconds / 2)) : null;
    }

    private double Blend(double? previous, double sample) => previous is { } p ? (Smoothing * sample) + ((1 - Smoothing) * p) : sample;
}
