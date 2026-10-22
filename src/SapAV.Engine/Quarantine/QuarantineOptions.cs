using System.Security.Principal;

namespace SapAV.Engine.Quarantine;

/// <summary>Quarantine settings (configuration section <c>Quarantine</c>).</summary>
public sealed class QuarantineOptions
{
    public const string SectionName = "Quarantine";

    /// <summary>The default store: <c>%ProgramData%\sap-AV\Quarantine</c>.</summary>
    public static string DefaultRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "sap-AV", "Quarantine");

    /// <summary>The store root (a local, fully qualified path). Null = <see cref="DefaultRoot"/>.</summary>
    public string? Root { get; set; }

    /// <summary>Largest file the quarantine hashes and copies (matches the scanner's default hash limit).</summary>
    public long MaxFileSizeBytes { get; set; } = Core.Hashing.Sha256Hasher.DefaultMaxSizeBytes;

    /// <summary>
    /// Test seam only (internal, so configuration binding can't set it): extra SIDs trusted like SYSTEM and
    /// Administrators, so a non-elevated test process can use a store on a temp root.
    /// </summary>
    internal IReadOnlyList<SecurityIdentifier> AdditionalTrustedSids { get; init; } = [];

    internal string EffectiveRoot => string.IsNullOrWhiteSpace(Root) ? DefaultRoot : Root;
}
