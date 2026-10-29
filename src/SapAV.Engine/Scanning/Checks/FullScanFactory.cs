using System.Security.Principal;
using Microsoft.Extensions.Options;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>
/// Full Scan's drive phase (C6): every file on every local fixed drive (<see cref="FullScanVolumes"/>), no extension or
/// size filter in the walk (the scanner's own size limit still applies). Each drive root is walked handle-bound
/// (<see cref="SafeTree"/>, one handle per level, a bounded queue, nothing listed ahead), so memory stays bounded however
/// big the tree. Skipped and counted, never opened: reparse points (junctions, symlinks, mount points), the engine's own
/// verified folders, cloud placeholders whose content isn't local (folders aren't listed, files aren't queued), the
/// system's paging / hibernation / swap files at each root, and <c>System Volume Information</c>. Depth and entry caps
/// (review B3 M2) stop a hostile tree; hitting one marks the phase incomplete. The drives' used space is announced as the
/// phase's expected bytes, so progress and the ETA mean something before the walk has counted every file.
/// </summary>
internal sealed class DriveWalkCheck(IVolumeSource volumes, FullScanOptions options) : IScanCheck
{
    public string Name => "Fixed drives";

    public double Weight => 100;

    public void Run(IScanCheckContext context)
    {
        var notes = new List<string>();
        var drives = FullScanVolumes.Select(volumes.List(), notes);
        foreach (var note in notes)
        {
            context.Note(note);
        }

        if (drives.Count == 0)
        {
            context.MarkIncomplete("No local fixed drive was found.");
            return;
        }

        context.ExpectBytes(drives.Sum(d => d.UsedBytes ?? 0));
        var roots = drives.Select(d => d.Root).ToArray();
        var skippedFiles = new HashSet<string>(roots.SelectMany(r => options.SkippedRootFiles.Select(f => Plain(Path.Join(r, f)))), StringComparer.OrdinalIgnoreCase);
        long placeholders = 0;
        var filter = new ScanWalkFilter
        {
            MaxDepth = options.MaxDepth,
            MaxEntries = options.MaxEntries,
            SkipFolder = QuickScanFileRules.SkipPredicate(roots.SelectMany(r => options.SkippedRootFolders.Select(f => Path.Join(r, f))), []),
            SkipFile = path => skippedFiles.Contains(Plain(path)),
            IncludeFile = e =>
            {
                if (!e.IsPlaceholder)
                {
                    return true;
                }

                placeholders++;
                return false;
            },
        };

        context.QueueTree(roots, filter);
        context.Note($"{drives.Count} drive(s) ({string.Join(", ", roots)}): {filter.EntriesSeen} entries listed; {filter.FilesSkipped} system paging files, "
            + $"{placeholders + filter.FoldersOffline} cloud placeholders (offline, not downloaded) and {filter.FoldersSkipped} system folders skipped.");
        if (filter.LimitReached)
        {
            context.MarkIncomplete($"Stopped after {options.MaxEntries} directory entries (the Full Scan entry limit).");
        }

        if (filter.FoldersTooDeep > 0)
        {
            context.MarkIncomplete($"{filter.FoldersTooDeep} folder(s) deeper than {options.MaxDepth} levels were not walked.");
        }
    }

    private static string Plain(string path) => ExactPath.StripPrefix(path).TrimEnd('\\');
}

/// <summary>
/// Builds Full Scan jobs (ROADMAP C6): one job of trigger FullScan whose checks run in order: running programs →
/// autostart entries (the full persistence check, C2 + C3) → (extra checks, e.g. the threat pack's, E7) → every file on
/// every fixed drive. No time budget by default (it runs to completion; pause / resume / cancel apply as for any job), the
/// scan cache (C5) skips files unchanged since an earlier scan, and scan threads run in background mode. Engine- or
/// administrator-initiated only, like Quick Scan: it reads every user's files, every process and machine-wide autostarts.
/// </summary>
public sealed class FullScanFactory
{
    private readonly FullScanOptions _options;
    private readonly IProcessSource _processes;
    private readonly IPersistenceCollector _collector;
    private readonly IPersistenceScanner _persistence;
    private readonly IVolumeSource _volumes;
    private readonly IReadOnlyList<IScanCheck> _extra;
    private readonly ILogger? _logger;

    internal FullScanFactory(
        FullScanOptions options, IProcessSource processes, IPersistenceCollector collector, IPersistenceScanner persistence, IVolumeSource volumes,
        IReadOnlyList<IScanCheck>? extraChecks = null, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _collector = collector ?? throw new ArgumentNullException(nameof(collector));
        _persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
        _volumes = volumes ?? throw new ArgumentNullException(nameof(volumes));
        _extra = extraChecks ?? [];
        _logger = logger;
    }

    /// <summary>The engine's factory, as registered in <see cref="EngineHost"/> (extra checks: every registered <see cref="IScanCheck"/>).</summary>
    internal static FullScanFactory Create(IServiceProvider services) =>
        new(services.GetRequiredService<IOptions<FullScanOptions>>().Value,
            new WindowsProcessSource(),
            services.GetRequiredService<IPersistenceCollector>(),
            services.GetRequiredService<IPersistenceScanner>(),
            new WindowsVolumeSource(),
            services.GetServices<IScanCheck>().ToArray(),
            services.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.FullScan"));

    public FullScanOptions Options => _options;

    /// <summary>A fresh set of checks for one job.</summary>
    internal IReadOnlyList<IScanCheck> Checks() =>
    [
        new ProcessImageCheck(_processes, _logger),
        new PersistenceCheck(_collector, _persistence),
        .. _extra,
        new DriveWalkCheck(_volumes, _options),
    ];

    /// <summary>The Full Scan request (not started). <paramref name="requester"/>: the administrator who asked, or null for the engine.</summary>
    internal ScanJobRequest CreateRequest(ScanJobOrigin origin, SecurityIdentifier? requester = null)
    {
        if (origin == ScanJobOrigin.StandardUser)
        {
            throw new ArgumentException("Full Scan is engine- or administrator-initiated only.", nameof(origin));
        }

        return new ScanJobRequest([], ScanTrigger.FullScan, _options.TimeBudget ?? FullScanOptions.NoBudget)
        {
            Checks = Checks(),
            Origin = origin,
            Requester = requester,
        };
    }
}
