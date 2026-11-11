namespace SapAV.Engine.Defender;

/// <summary>Settings for the Defender status collector (E5), section <c>Defender</c>.</summary>
public sealed class DefenderStatusOptions
{
    public const string SectionName = "Defender";

    public static readonly TimeSpan MinQueryTimeout = TimeSpan.FromMilliseconds(100);
    public static readonly TimeSpan MaxQueryTimeout = TimeSpan.FromMinutes(2);

    /// <summary>The longest one WMI read may take before it counts as TimedOut (clamped to 100 ms - 2 min).</summary>
    public TimeSpan QueryTimeout { get; set; } = TimeSpan.FromSeconds(10);

    internal TimeSpan EffectiveQueryTimeout => QueryTimeout < MinQueryTimeout ? MinQueryTimeout
        : QueryTimeout > MaxQueryTimeout ? MaxQueryTimeout
        : QueryTimeout;
}
