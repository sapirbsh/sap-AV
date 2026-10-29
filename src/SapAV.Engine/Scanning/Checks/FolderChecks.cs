using SapAV.Core.Hashing;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>
/// What phases 3 and 4 share (C4): the file classes and their queue rank, the Mark-of-the-Web probe, the "recent" cutoff
/// and the folders that aren't walked.
/// </summary>
internal sealed class QuickScanFileRules
{
    private readonly HashSet<string> _executable;
    private readonly HashSet<string> _archive;
    private readonly HashSet<string> _office;

    public QuickScanFileRules(QuickScanOptions options)
    {
        Options = options ?? throw new ArgumentNullException(nameof(options));
        _executable = new(options.ExecutableExtensions, StringComparer.OrdinalIgnoreCase);
        _archive = new(options.ArchiveExtensions, StringComparer.OrdinalIgnoreCase);
        _office = new(options.OfficeMacroExtensions, StringComparer.OrdinalIgnoreCase);
    }

    public QuickScanOptions Options { get; }

    /// <summary>0 executables / scripts, 1 archives / disk images, 2 Office macro files, 3 anything else.</summary>
    public int ClassOf(string name)
    {
        string extension = Path.GetExtension(name);
        return _executable.Contains(extension) ? 0 : _archive.Contains(extension) ? 1 : _office.Contains(extension) ? 2 : 3;
    }

    public bool IsRisky(string name) => ClassOf(name) < 3;

    /// <summary>Recent: created, written or changed at or after <paramref name="cutoff"/> (from the listing; unknown = not recent).</summary>
    public static bool IsRecent(SafeTreeEntry entry, DateTimeOffset cutoff) => entry.NewestTimeUtc is { } newest && newest >= cutoff;

    public DateTimeOffset Cutoff(TimeProvider time) => time.GetUtcNow() - TimeSpan.FromDays(Options.RecentDays);

    /// <summary>
    /// Queue rank: a file with a Mark-of-the-Web (a <c>Zone.Identifier</c> stream; <paramref name="probeMotw"/>) first,
    /// then by class. Only the stream's existence is checked (an attributes-only open relative to the listed folder's
    /// handle); its content is parsed by the scan worker, never here.
    /// </summary>
    public int Rank(ScanTreeEntry entry, bool probeMotw) =>
        (probeMotw && HasMarkOfTheWeb(entry) ? 0 : 10) + ClassOf(entry.Name ?? entry.Path);

    internal static bool HasMarkOfTheWeb(ScanTreeEntry entry)
    {
        if (entry.Folder is null || string.IsNullOrEmpty(entry.Name))
        {
            return false;
        }

        using var stream = SafeTree.OpenChild(entry.Folder.Handle, entry.Name + ":Zone.Identifier", N.FileReadAttributes, SafeTree.ShareAll,
            N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out _, out _);
        return stream is not null;
    }

    /// <summary>
    /// A folder-skip predicate: true for an exact path (<c>\\?\</c> or plain) equal to one of <paramref name="folders"/>, or
    /// matching one of <paramref name="patterns"/> (absolute; <c>*</c> = exactly one folder name), case-insensitive.
    /// </summary>
    public static Func<string, bool> SkipPredicate(IEnumerable<string> folders, IEnumerable<string> patterns)
    {
        var exact = new HashSet<string>(folders.Select(Plain), StringComparer.OrdinalIgnoreCase);
        var split = patterns.Select(p => Plain(p).Split('\\')).ToArray();
        return path =>
        {
            string plain = Plain(path);
            if (exact.Contains(plain))
            {
                return true;
            }

            var parts = plain.Split('\\');
            return split.Any(pattern => pattern.Length == parts.Length
                && pattern.Zip(parts).All(p => p.First == "*" || string.Equals(p.First, p.Second, StringComparison.OrdinalIgnoreCase)));
        };
    }

    /// <summary>Each profile's skipped folders as absolute patterns.</summary>
    public IEnumerable<string> ProfilePatterns(IEnumerable<string> profiles) =>
        profiles.SelectMany(profile => Options.SkippedProfileFolders.Select(relative => Path.Join(profile, relative)));

    private static string Plain(string path) => ExactPath.StripPrefix(path).TrimEnd('\\');
}

/// <summary>
/// Quick Scan phase 3 (C4): the high-risk folders of <b>every</b> profile (<see cref="IProfileFolderSource"/>): Downloads
/// and Desktop (plus the public ones) first, then TEMP (each user's and the machine's), then AppData (Roaming, Local).
/// Walked handle-bound (SafeTree), at most <see cref="QuickScanOptions.MaxDepth"/> deep, skipping the known huge caches;
/// queued are executables / scripts / archives / Office macro files and any recent file under the size limit, downloaded
/// (Mark-of-the-Web) files first. A folder already walked in an earlier group isn't walked again.
/// </summary>
internal sealed class RiskyFolderCheck(IProfileFolderSource folders, QuickScanFileRules rules) : IScanCheck
{
    public string Name => "High-risk folders";

    public double Weight => 4;

    public void Run(IScanCheckContext context)
    {
        var set = folders.Resolve();
        foreach (var note in set.Notes.Take(5))
        {
            context.Note(note);
        }

        var cutoff = rules.Cutoff(context.Time);
        var walked = new List<string>();
        var patterns = rules.ProfilePatterns(set.Users.Select(u => u.Profile)).ToArray();
        string?[][] groups =
        [
            [.. set.Users.SelectMany(u => new[] { u.Downloads, u.Desktop }), set.PublicDownloads, set.PublicDesktop],
            [.. set.Users.Select(u => u.Temp), set.MachineTemp],
            [.. set.Users.SelectMany(u => new[] { u.RoamingAppData, u.LocalAppData })],
        ];

        long filtered = 0, tooDeep = 0, skipped = 0;
        for (int g = 0; g < groups.Length; g++)
        {
            var roots = Distinct(groups[g]).Where(r => !walked.Contains(r, StringComparer.OrdinalIgnoreCase)).ToArray();
            if (roots.Length == 0)
            {
                continue;
            }

            var filter = new ScanWalkFilter
            {
                MaxDepth = rules.Options.MaxDepth,
                IncludeFile = e => e.Length <= rules.Options.MaxFileSizeBytes && (rules.IsRisky(e.Name) || QuickScanFileRules.IsRecent(e, cutoff)),
                SkipFolder = QuickScanFileRules.SkipPredicate(walked, patterns),
            };
            bool probeMotw = g == 0; // downloads land in Downloads / Desktop
            context.QueueTree(roots, filter, e => rules.Rank(e, probeMotw));
            walked.AddRange(roots);
            filtered += filter.FilesFiltered;
            tooDeep += filter.FoldersTooDeep;
            skipped += filter.FoldersSkipped;
        }

        context.Note($"{walked.Count} folders in {set.Users.Count} profiles; {filtered} other files left to Full Scan, {skipped} cache folders skipped, "
            + $"{tooDeep} folders deeper than {rules.Options.MaxDepth} levels not walked.");
    }

    /// <summary>The folders this phase walks (the recent-files phase skips them).</summary>
    internal static IReadOnlyList<string> Roots(ProfileFolderSet set) =>
        Distinct([.. set.Users.SelectMany(u => new[] { u.Downloads, u.Desktop, u.Temp, u.RoamingAppData, u.LocalAppData }),
            set.PublicDownloads, set.PublicDesktop, set.MachineTemp]);

    internal static IReadOnlyList<string> Distinct(IEnumerable<string?> paths) =>
        paths.OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}

/// <summary>
/// Quick Scan phase 4 (C4): files created, written or changed in the last <see cref="QuickScanOptions.RecentDays"/> days,
/// <b>scoped to the user profiles and ProgramData</b> (not whole drives). Walked handle-bound with a time filter on the
/// listing's own timestamps (no extra open per file), under the size limit, skipping the folders phase 3 already walked
/// and the known caches. Executables and scripts are queued first. The engine's exclusion set (verified engine folders)
/// applies as in every walk. The USN journal isn't used: reading it needs a volume handle and parsing raw records for the
/// whole volume as SYSTEM, and mapping file IDs back to paths needs by-ID opens that bypass the handle-bound walk; the
/// listing filter keeps the walk safe and is fast enough for profiles + ProgramData.
/// </summary>
internal sealed class RecentFilesCheck(IProfileFolderSource folders, QuickScanFileRules rules) : IScanCheck
{
    public string Name => "Recently changed files";

    public double Weight => 3;

    public void Run(IScanCheckContext context)
    {
        var set = folders.Resolve();
        var cutoff = rules.Cutoff(context.Time);
        var roots = RiskyFolderCheck.Distinct([.. set.Users.Select(u => u.Profile), set.ProgramData]);
        var patterns = rules.ProfilePatterns(set.Users.Select(u => u.Profile))
            .Concat(set.ProgramData is null ? [] : rules.Options.SkippedProgramDataFolders.Select(p => Path.Join(set.ProgramData, p)));
        var filter = new ScanWalkFilter
        {
            MaxDepth = rules.Options.MaxDepth,
            IncludeFile = e => e.Length <= rules.Options.MaxFileSizeBytes && QuickScanFileRules.IsRecent(e, cutoff),
            SkipFolder = QuickScanFileRules.SkipPredicate(RiskyFolderCheck.Roots(set), patterns.ToArray()),
        };

        context.QueueTree(roots, filter, e => rules.Rank(e, probeMotw: false));
        context.Note($"{roots.Count} roots (profiles and ProgramData), files since {cutoff:yyyy-MM-dd HH:mm} UTC; {filter.FilesFiltered} older or larger files skipped, "
            + $"{filter.FoldersSkipped} folders skipped (already walked or caches), {filter.FoldersTooDeep} folders deeper than {rules.Options.MaxDepth} levels not walked.");
    }
}
