using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Yara;

/// <summary>
/// One compiled (non-private) rule and what a match on it means, decided once at load time from its meta.
/// </summary>
/// <remarks>
/// Meta fields read (identifiers are matched case-insensitively):
/// <list type="bullet">
/// <item><c>verdict</c>: <c>"malicious"</c> (also the default when missing) → Malicious; <c>"suspicious"</c>,
/// <c>"pup"</c> or <c>"hacktool"</c> → Suspicious; anything else → Suspicious plus a
/// <see cref="YaraWarningKind.Verdict"/> warning (unknown values err on the side of fewer false Malicious).</item>
/// <item><c>mitre</c>: technique IDs via <see cref="MitreTechniqueIdFormat.SelectOrDefault"/>, fallback
/// <see cref="MitreTechniqueIds.MaliciousFile"/>.</item>
/// <item><c>description</c>: optional, kept for display.</item>
/// </list>
/// </remarks>
public sealed record YaraRuleInfo
{
    internal YaraRuleInfo(
        string file, string identifier, IReadOnlyList<string> tags, Verdict verdict,
        MitreTechniqueSelection mitre, string? description)
    {
        File = file;
        Identifier = identifier;
        Tags = tags;
        Verdict = verdict;
        Mitre = mitre;
        Description = description;
    }

    /// <summary>The rule file relative to the rules directory, which is also the rule's YARA namespace.</summary>
    public string File { get; }

    public string Identifier { get; }

    public IReadOnlyList<string> Tags { get; }

    /// <summary>Suspicious or Malicious.</summary>
    public Verdict Verdict { get; }

    public MitreTechniqueSelection Mitre { get; }

    public string? Description { get; }

    /// <summary>The detection a match on this rule produces (source Yara, reason = rule name + file).</summary>
    public Detection ToDetection() =>
        new(Verdict, $"YARA rule {Identifier} matched ({File})", Mitre.PrimaryId, DetectionSource.Yara, Mitre.SecondaryIds);
}

/// <summary>Rule text to compile, named like a file (the name becomes the YARA namespace).</summary>
/// <param name="Name">Unique name, e.g. <c>antivirus-test-file.yar</c> or <c>third-party/x.yar</c>.</param>
/// <param name="Text">YARA source.</param>
public sealed record YaraRuleSource(string Name, string Text);
