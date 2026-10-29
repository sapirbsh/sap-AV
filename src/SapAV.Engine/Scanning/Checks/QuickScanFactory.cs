using System.Security.Principal;
using Microsoft.Extensions.Options;
using SapAV.Core.Models;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>
/// Builds Quick Scan jobs (ROADMAP C4): one job of trigger QuickScan whose checks run in order: running programs →
/// autostart entries → (extra checks, e.g. the threat pack's, E7) → high-risk folders → recently changed files, under
/// <see cref="QuickScanOptions.TimeBudget"/>. Quick Scan is engine- or administrator-initiated only (the pipe refuses it
/// for standard users): it looks at every profile, every process and machine-wide autostarts.
/// </summary>
public sealed class QuickScanFactory
{
    private readonly QuickScanOptions _options;
    private readonly IProcessSource _processes;
    private readonly IPersistenceCollector _collector;
    private readonly IPersistenceScanner _persistence;
    private readonly IProfileFolderSource _folders;
    private readonly IReadOnlyList<IScanCheck> _extra;
    private readonly ILogger? _logger;

    internal QuickScanFactory(
        QuickScanOptions options, IProcessSource processes, IPersistenceCollector collector, IPersistenceScanner persistence, IProfileFolderSource folders,
        IReadOnlyList<IScanCheck>? extraChecks = null, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _collector = collector ?? throw new ArgumentNullException(nameof(collector));
        _persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
        _folders = folders ?? throw new ArgumentNullException(nameof(folders));
        _extra = extraChecks ?? [];
        _logger = logger;
    }

    /// <summary>The engine's factory, as registered in <see cref="EngineHost"/> (extra checks: every registered <see cref="IScanCheck"/>).</summary>
    internal static QuickScanFactory Create(IServiceProvider services) =>
        new(services.GetRequiredService<IOptions<QuickScanOptions>>().Value,
            new WindowsProcessSource(),
            services.GetRequiredService<IPersistenceCollector>(),
            services.GetRequiredService<IPersistenceScanner>(),
            new RegistryProfileFolders(new WindowsRegistryView()),
            services.GetServices<IScanCheck>().ToArray(),
            services.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.QuickScan"));

    public QuickScanOptions Options => _options;

    /// <summary>A fresh set of checks for one job (checks keep no state between jobs, but each job gets its own instances).</summary>
    internal IReadOnlyList<IScanCheck> Checks()
    {
        var rules = new QuickScanFileRules(_options);
        var ledger = new FolderWalkLedger(); // review C4 M2: phase 4 skips only the roots phase 3 finished
        return
        [
            new ProcessImageCheck(_processes, _logger),
            new PersistenceCheck(_collector, _persistence),
            .. _extra,
            new RiskyFolderCheck(_folders, rules, ledger),
            new RecentFilesCheck(_folders, rules, ledger),
        ];
    }

    /// <summary>The Quick Scan request (not started). <paramref name="requester"/>: the administrator who asked, or null for the engine.</summary>
    internal ScanJobRequest CreateRequest(ScanJobOrigin origin, SecurityIdentifier? requester = null)
    {
        if (origin == ScanJobOrigin.StandardUser)
        {
            throw new ArgumentException("Quick Scan is engine- or administrator-initiated only.", nameof(origin));
        }

        return new ScanJobRequest([], ScanTrigger.QuickScan, _options.TimeBudget)
        {
            Checks = Checks(),
            Origin = origin,
            Requester = requester,
        };
    }
}
