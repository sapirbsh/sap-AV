using System.Globalization;

namespace SapAV.Engine.Defender;

/// <summary>Settings for the Defender status collector (E5), section <c>Defender</c>.</summary>
public sealed class DefenderStatusOptions
{
    public const string SectionName = "Defender";

    public static readonly TimeSpan DefaultQueryTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan MinQueryTimeout = TimeSpan.FromMilliseconds(100);
    public static readonly TimeSpan MaxQueryTimeout = TimeSpan.FromMinutes(2);

    /// <summary>The longest one WMI read may take before it counts as TimedOut (clamped to 100 ms - 2 min).</summary>
    public TimeSpan QueryTimeout { get; set; } = DefaultQueryTimeout;

    internal TimeSpan EffectiveQueryTimeout => QueryTimeout < MinQueryTimeout ? MinQueryTimeout
        : QueryTimeout > MaxQueryTimeout ? MaxQueryTimeout
        : QueryTimeout;

    /// <summary>
    /// Binds the section by hand: a malformed <c>QueryTimeout</c> keeps the default instead of throwing when the options are
    /// first used (which would fail every Defender read).
    /// </summary>
    public static void Bind(IConfiguration section, DefenderStatusOptions options)
    {
        ArgumentNullException.ThrowIfNull(section);
        ArgumentNullException.ThrowIfNull(options);
        if (TimeSpan.TryParse(section[nameof(QueryTimeout)], CultureInfo.InvariantCulture, out var timeout))
        {
            options.QueryTimeout = timeout;
        }
    }
}
