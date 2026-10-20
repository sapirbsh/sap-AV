namespace SapAV.Core.Yara;

/// <summary>A rule file that was skipped because it could not be read or did not compile.</summary>
/// <param name="File">The file's path relative to the rules directory (also its YARA namespace), or the source name.</param>
/// <param name="Errors">The compiler's messages (<c>line N: message</c>), or the read error. At least one.</param>
public sealed record YaraRuleFileError(string File, IReadOnlyList<string> Errors)
{
    public override string ToString() => $"{File}: {string.Join("; ", Errors)}";
}

/// <summary>What a <see cref="YaraRuleWarning"/> is about.</summary>
public enum YaraWarningKind
{
    /// <summary>
    /// The rule's <c>mitre</c> meta was changed by the lenient parser: an invalid token was dropped
    /// (e.g. <c>"001"</c> in <c>"T1059,001"</c>), or nothing was valid and the fallback T1204.002 is used.
    /// Trimming and upper-casing alone never warn; neither does a missing <c>mitre</c> meta.
    /// </summary>
    Mitre,

    /// <summary>The rule's <c>verdict</c> meta is not a known value; the rule reports Suspicious.</summary>
    Verdict,

    /// <summary>A warning from the YARA compiler itself (e.g. a rule that may slow down scanning).</summary>
    Compiler,
}

/// <summary>
/// A non-fatal problem found while loading rules. Core has no logging, so the engine logs these
/// (<see cref="YaraRuleSet.Warnings"/>) once per load.
/// </summary>
/// <param name="File">Rule file (namespace) the rule came from.</param>
/// <param name="Rule">The rule identifier, if the warning is about one rule.</param>
/// <param name="Kind">What the warning is about.</param>
/// <param name="RawValue">The meta value as written in the rule (for Mitre / Verdict), else null.</param>
/// <param name="Message">Human-readable text naming the rule, the raw value and what was used instead.</param>
public sealed record YaraRuleWarning(string File, string? Rule, YaraWarningKind Kind, string? RawValue, string Message)
{
    public override string ToString() => Message;
}
