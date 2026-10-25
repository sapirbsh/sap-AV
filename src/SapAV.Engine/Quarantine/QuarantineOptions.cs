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
    /// Quota for everything in the store (review B2 M4): a quarantine that would take the store over it is refused with
    /// StoreFull, so mass-dropped unique files can't fill the drive. Default 4 GiB.
    /// </summary>
    public long MaxStoreBytes { get; set; } = 4L * 1024 * 1024 * 1024;

    /// <summary>Free space the store's drive must keep after a quarantine (default 2 GiB); below it, StoreFull.</summary>
    public long MinFreeSpaceBytes { get; set; } = 2L * 1024 * 1024 * 1024;

    /// <summary>
    /// Section B M1: what one standard user may have in the store through their own requests (QuarantineFromResult, and
    /// auto-quarantines in their own scan jobs): at most this many bytes (default 512 MiB) ...
    /// </summary>
    public long MaxBytesPerRequester { get; set; } = 512L * 1024 * 1024;

    /// <summary>... and at most this many items (default 200). Engine-initiated quarantines use only the global quota.</summary>
    public int MaxItemsPerRequester { get; set; } = 200;

    /// <summary>
    /// Test seam only (internal, so configuration binding can't set it): extra SIDs trusted like SYSTEM and
    /// Administrators, so a non-elevated test process can use a store on a temp root.
    /// </summary>
    internal IReadOnlyList<SecurityIdentifier> AdditionalTrustedSids { get; init; } = [];

    internal string EffectiveRoot => string.IsNullOrWhiteSpace(Root) ? DefaultRoot : Root;
}
