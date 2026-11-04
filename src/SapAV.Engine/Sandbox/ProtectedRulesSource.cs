using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Yara;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// Where the engine's rule package (YARA rules + SHA-256 blocklist) comes from (D3; carried over from the A2 review, M5).
/// A user who could edit the blocklist could take their own malware off it, so as SYSTEM or elevated the engine loads it only
/// from a folder no standard user can write.
/// </summary>
/// <remarks>
/// Precedence (<see cref="Apply"/>, pure: no file system access):
/// <list type="number">
/// <item><b>Configured</b> <c>Sandbox:RulesDirectory</c> / <c>Sandbox:BlocklistPath</c> (an administrator's
/// <c>appsettings.json</c>): used, but as SYSTEM or elevated each folder must pass <see cref="IFolderTrust"/> at every load
/// (owner SYSTEM / Administrators / TrustedInstaller, no write access for anyone else, no links), or it is refused.</item>
/// <item><b>Protected default</b> (SYSTEM, elevated or a service): <c>%ProgramData%\sap-AV\Rules\</c> and
/// <c>%ProgramData%\sap-AV\Blocklist\blocklist.txt</c>, created / verified with the protected SYSTEM + Administrators ACL
/// (<see cref="EngineDataSubfolder"/>; a pre-existing folder with a wider ACL or an untrusted owner is refused, never
/// fixed).</item>
/// <item><b>Debug</b> (a non-elevated console run): the shipped files next to the engine (<c>data\rules</c>,
/// <c>data\hashes\blocklist.txt</c>), as before. That engine has only the user's own rights, so nothing is gained by editing
/// them.</item>
/// </list>
/// The shipped files are the <b>seed</b> of the protected folders: copied in when missing or when the shipped copy is newer (an
/// update), and only if the install folder itself passes <see cref="IFolderTrust"/> (Program Files). Files in the protected
/// folders under other names (an administrator's own rules) are kept. Nothing is ever loaded from the install folder directly.
/// </remarks>
public sealed class ProtectedRulesSource : IScanRulesSource
{
    public const string BlocklistFileName = "blocklist.txt";

    private readonly SandboxOptions _options;
    private readonly QuarantineAccessPolicy _policy;
    private readonly IFolderTrust _trust;
    private readonly string _shippedRules;
    private readonly string _shippedBlocklist;
    private readonly string _managedRules;
    private readonly string _managedBlocklist;
    private readonly bool? _parentIsDataRoot;

    /// <param name="options">Already resolved with <see cref="Apply"/>.</param>
    /// <param name="managedRulesDirectory">The protected rules folder (default <see cref="EngineDataFolders.Rules"/>; tests use temp folders).</param>
    /// <param name="managedBlocklistPath">The protected blocklist file (default <see cref="EngineDataFolders.Blocklist"/>\blocklist.txt).</param>
    /// <param name="parentIsDataRoot">Passed to <see cref="EngineDataSubfolder.Ensure"/> (null: when it is the real data root).</param>
    internal ProtectedRulesSource(SandboxOptions options, QuarantineAccessPolicy policy, IFolderTrust trust,
        string? shippedRulesDirectory = null, string? shippedBlocklistPath = null,
        string? managedRulesDirectory = null, string? managedBlocklistPath = null, bool? parentIsDataRoot = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _shippedRules = Path.GetFullPath(shippedRulesDirectory ?? ShippedRulesDirectory);
        _shippedBlocklist = Path.GetFullPath(shippedBlocklistPath ?? ShippedBlocklistPath);
        _managedRules = Path.GetFullPath(managedRulesDirectory ?? EngineDataFolders.Rules);
        _managedBlocklist = Path.GetFullPath(managedBlocklistPath ?? ManagedBlocklistPath);
        _parentIsDataRoot = parentIsDataRoot;
    }

    /// <summary>The production source (SYSTEM + Administrators, the real data root).</summary>
    public static ProtectedRulesSource Create(SandboxOptions options) => new(options, QuarantineAccessPolicy.Default, FolderTrust.Default);

    /// <summary>The rules shipped next to the engine (the seed).</summary>
    public static string ShippedRulesDirectory => Path.Combine(AppContext.BaseDirectory, "data", "rules");

    /// <summary>The blocklist shipped next to the engine (the seed).</summary>
    public static string ShippedBlocklistPath => Path.Combine(AppContext.BaseDirectory, "data", "hashes", BlocklistFileName);

    /// <summary>The protected blocklist file.</summary>
    public static string ManagedBlocklistPath => Path.Combine(EngineDataFolders.Blocklist, BlocklistFileName);

    /// <summary>
    /// The precedence (see the remarks): when the engine is protected (SYSTEM, elevated or a service) and nothing is configured,
    /// point the options at the protected folders. Pure: no file system access (resolving the host must not create anything).
    /// </summary>
    public static void Apply(SandboxOptions options, bool protectedMode)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!protectedMode)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(options.RulesDirectory))
        {
            options.RulesDirectory = EngineDataFolders.Rules;
        }

        if (string.IsNullOrWhiteSpace(options.BlocklistPath))
        {
            options.BlocklistPath = ManagedBlocklistPath;
        }
    }

    public async Task<WorkerLoadRules> LoadAsync(CancellationToken cancellationToken = default)
    {
        var errors = new List<string>();
        string rulesDirectory = _options.ResolvedRulesDirectory;
        string blocklistPath = _options.ResolvedBlocklistPath;

        IReadOnlyList<YaraRuleFile> rules = [];
        switch (Prepare(rulesDirectory, _managedRules, "rules", errors, SeedRules, _shippedRules, Directory.Exists(_shippedRules)))
        {
            case Source.Target:
                rules = DirectoryScanRulesSource.ReadRules(rulesDirectory, errors, cancellationToken);
                break;
            case Source.Shipped:
                rules = DirectoryScanRulesSource.ReadRules(_shippedRules, errors, cancellationToken);
                break;
        }

        byte[] blocklist = [];
        bool blocklistManaged = Same(blocklistPath, _managedBlocklist);
        string blocklistFolder = Path.GetDirectoryName(blocklistPath) ?? blocklistPath;
        string shippedFolder = Path.GetDirectoryName(_shippedBlocklist) ?? _shippedBlocklist;
        switch (Prepare(blocklistFolder, blocklistManaged ? blocklistFolder : null, "blocklist", errors, SeedBlocklist, shippedFolder, File.Exists(_shippedBlocklist)))
        {
            case Source.Target:
                blocklist = await DirectoryScanRulesSource.ReadBlocklistAsync(blocklistPath, errors, cancellationToken).ConfigureAwait(false);
                break;
            case Source.Shipped:
                blocklist = await DirectoryScanRulesSource.ReadBlocklistAsync(_shippedBlocklist, errors, cancellationToken).ConfigureAwait(false);
                break;
        }

        return DirectoryScanRulesSource.Package(rules, blocklist, errors);
    }

    private enum Source
    {
        None,
        Target,
        Shipped,
    }

    /// <summary>
    /// Where to read: the protected folder (created / verified, then seeded), or a configured folder that passes the trust check
    /// (<see cref="Source.Target"/>). Review D3 H1: when the protected folder itself is refused (e.g. a standard user pre-created
    /// <c>%ProgramData%\sap-AV</c> before the first start), the shipped files are read directly, if the install folder passes the
    /// trust check, so a user can't switch YARA and the blocklist off that way; the read error stays, so the engine still raises
    /// the rules health alert (B3 M5). Otherwise <see cref="Source.None"/> with a read error.
    /// </summary>
    private Source Prepare(string folder, string? managed, string label, List<string> errors, Action<string, List<string>> seed,
        string shippedFolder, bool shippedExists)
    {
        if (managed is not null && Same(folder, managed))
        {
            try
            {
                EngineDataSubfolder.Ensure(folder, _policy, label, _parentIsDataRoot);
            }
            catch (QuarantineStoreException ex)
            {
                if (shippedExists && ShippedTrusted(shippedFolder, label, errors))
                {
                    errors.Add($"The protected {label} folder was refused ({ex.Message}); the {label} were loaded from the install folder {shippedFolder} instead.");
                    return Source.Shipped;
                }

                errors.Add($"Not loaded ({label}): {ex.Message}");
                return Source.None;
            }

            seed(folder, errors);
            return Source.Target;
        }

        string? problem = Check(folder);
        if (problem is not null)
        {
            errors.Add($"The configured {label} folder {folder} was refused: {problem}. Only a folder that no standard user can change is used.");
            return Source.None;
        }

        return Source.Target;
    }

    private string? Check(string folder)
    {
        try
        {
            return _trust.Problem(folder);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return $"it could not be checked ({ex.GetType().Name})";
        }
    }

    private void SeedRules(string target, List<string> errors)
    {
        if (!Directory.Exists(_shippedRules) || !ShippedTrusted(_shippedRules, "rules", errors))
        {
            return;
        }

        var shipped = YaraRuleSet.ReadDirectoryFiles(_shippedRules, out var readErrors);
        errors.AddRange(readErrors.Select(e => $"Shipped rule {e}"));
        foreach (var file in shipped)
        {
            string relative = file.Name.Replace('/', Path.DirectorySeparatorChar);
            CopyIfNewer(Path.Combine(_shippedRules, relative), Path.Combine(target, relative), file.Content, errors);
        }
    }

    private void SeedBlocklist(string target, List<string> errors)
    {
        string? folder = Path.GetDirectoryName(_shippedBlocklist);
        if (folder is null || !File.Exists(_shippedBlocklist) || !ShippedTrusted(folder, "blocklist", errors))
        {
            return;
        }

        try
        {
            var info = new FileInfo(_shippedBlocklist);
            if (info.Length > Core.Blocklist.HashBlocklist.DefaultMaxSizeBytes)
            {
                errors.Add($"The shipped blocklist {_shippedBlocklist} is over the size limit; not copied.");
                return;
            }

            CopyIfNewer(_shippedBlocklist, Path.Combine(target, Path.GetFileName(_managedBlocklist)), File.ReadAllBytes(_shippedBlocklist), errors);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            errors.Add($"The shipped blocklist {_shippedBlocklist} could not be read ({ex.GetType().Name}); not copied.");
        }
    }

    private bool ShippedTrusted(string folder, string label, List<string> errors)
    {
        if (Check(folder) is not { } problem)
        {
            return true;
        }

        errors.Add($"The shipped {label} files in {folder} can't be used (not copied, not loaded): {problem}. Install the engine into an " +
            "administrator-only folder (Program Files), or put the files into the protected folder as an administrator.");
        return false;
    }

    /// <summary>Writes <paramref name="content"/> to <paramref name="target"/> when it is missing or older than the shipped file.</summary>
    private static void CopyIfNewer(string source, string target, byte[] content, List<string> errors)
    {
        try
        {
            var shippedTime = File.GetLastWriteTimeUtc(source);
            if (File.Exists(target) && File.GetLastWriteTimeUtc(target) >= shippedTime)
            {
                return; // up to date, or changed by an administrator since
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!); // inside the protected folder: inherits its ACL
            string temp = target + ".tmp";
            File.WriteAllBytes(temp, content);
            File.SetLastWriteTimeUtc(temp, shippedTime);
            File.Move(temp, target, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            errors.Add($"The shipped file {Path.GetFileName(source)} could not be copied into the protected folder ({ex.GetType().Name}).");
        }
    }

    private static bool Same(string a, string b) =>
        string.Equals(FolderSet.Normalize(a), FolderSet.Normalize(b), StringComparison.OrdinalIgnoreCase);
}
