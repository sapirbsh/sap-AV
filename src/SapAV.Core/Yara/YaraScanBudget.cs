namespace SapAV.Core.Yara;

/// <summary>
/// E2: a scan-time budget for YARA, so a large rule set (the third-party rules) or files that defeat rule atoms can't make a
/// scan run (a scan job, a folder tree) slow: a YARA-X timeout per file, plus a total amount of YARA time for the run.
/// Thread-safe; one instance is shared by every scan of one run (see <see cref="YaraScanner.SetBudget"/>).
/// </summary>
/// <remarks>
/// <para>Before each scan, <see cref="TryGetTimeoutSeconds"/> gives the YARA-X timeout: the per-file timeout, capped by what is
/// left of the total (YARA-X counts whole seconds, so it is rounded up, at least 1 s). Once the total is used up, scans are
/// refused (<see cref="YaraFailureReason.BudgetExhausted"/>: the file is NotScanned, never Clean) instead of running.</para>
/// <para>Only the time spent inside YARA-X counts (measured with <see cref="TimeProvider"/>). Scans running in parallel each
/// get the remaining budget when they start, so the total can be overrun by at most one per-file timeout per thread.</para>
/// </remarks>
public sealed class YaraScanBudget
{
    /// <summary>Default per-file YARA-X timeout for a budgeted run: 10 seconds.</summary>
    public static readonly TimeSpan DefaultPerFile = TimeSpan.FromSeconds(10);

    private readonly TimeProvider _time;
    private long _spentTicks;
    private int _refused;

    /// <param name="total">Total YARA time for the run (positive).</param>
    /// <param name="perFile">YARA-X timeout per file (positive; default <see cref="DefaultPerFile"/>).</param>
    /// <param name="time">Clock (tests use a fake one).</param>
    /// <exception cref="ArgumentOutOfRangeException">A time span is zero or negative.</exception>
    public YaraScanBudget(TimeSpan total, TimeSpan? perFile = null, TimeProvider? time = null)
    {
        var file = perFile ?? DefaultPerFile;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(total, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(file, TimeSpan.Zero, nameof(perFile));
        Total = total;
        PerFile = file;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>The total YARA time allowed for the run.</summary>
    public TimeSpan Total { get; }

    /// <summary>The YARA-X timeout for one file.</summary>
    public TimeSpan PerFile { get; }

    /// <summary>YARA time used so far.</summary>
    public TimeSpan Spent => TimeSpan.FromTicks(Interlocked.Read(ref _spentTicks));

    /// <summary>What is left of <see cref="Total"/> (never negative).</summary>
    public TimeSpan Remaining => Total > Spent ? Total - Spent : TimeSpan.Zero;

    /// <summary>True once the total is used up.</summary>
    public bool IsExhausted => Remaining <= TimeSpan.Zero;

    /// <summary>Scans refused because the budget was used up.</summary>
    public int RefusedCount => Volatile.Read(ref _refused);

    /// <summary>
    /// The YARA-X timeout, in whole seconds, for the next scan: <see cref="PerFile"/> capped by <see cref="Remaining"/>, rounded
    /// up, at least 1. False (and counted in <see cref="RefusedCount"/>) when the budget is used up: don't scan.
    /// </summary>
    public bool TryGetTimeoutSeconds(out int seconds)
    {
        var remaining = Remaining;
        if (remaining <= TimeSpan.Zero)
        {
            Interlocked.Increment(ref _refused);
            seconds = 0;
            return false;
        }

        var limit = remaining < PerFile ? remaining : PerFile;
        seconds = (int)Math.Clamp(Math.Ceiling(limit.TotalSeconds), 1, int.MaxValue);
        return true;
    }

    /// <summary>Adds the time one scan took.</summary>
    public void Charge(TimeSpan elapsed)
    {
        if (elapsed > TimeSpan.Zero)
        {
            Interlocked.Add(ref _spentTicks, elapsed.Ticks);
        }
    }

    internal long GetTimestamp() => _time.GetTimestamp();

    internal TimeSpan GetElapsedTime(long start) => _time.GetElapsedTime(start);
}
