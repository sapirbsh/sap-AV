using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Persistence;

/// <summary>Collects every persistence entry (ROADMAP C2). C4 (Quick Scan), C6 and D4 use it.</summary>
internal interface IPersistenceCollector
{
    /// <summary>
    /// Collects the entries, read-only. Never throws for a collection problem: access denied, an unloaded hive, a
    /// malformed task, the time budget or a cap become <see cref="PersistenceCollection.Issues"/>.
    /// </summary>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled, or <see cref="PersistenceCollectOptions.Checkpoint"/> threw it.
    /// </exception>
    PersistenceCollection Collect(CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null);
}

/// <summary>Follow-up review M6: what a scan job adds to one collection.</summary>
internal sealed record PersistenceCollectOptions
{
    /// <summary>The whole collection's budget instead of <see cref="PersistenceLimits.TimeBudget"/> (never more than it); null = the limit's.</summary>
    public TimeSpan? TimeBudget { get; init; }

    /// <summary>
    /// Called between sources and between users (a scan job's pause / cancel / budget check). Time spent in it (paused) doesn't
    /// count against the budget; whatever it throws ends the collection.
    /// </summary>
    public Action? Checkpoint { get; init; }

    /// <summary>
    /// D4 review H5: the task definition files (task paths, <c>\Folder\Name</c>) the Tasks folder watch reported changed since
    /// the last collection. A listed file not in this set whose earlier parse result is kept is reused without being opened.
    /// Null = no hint (every file is opened and checked by its stamp): at start, after an overflow, at the safety rescan.
    /// </summary>
    public IReadOnlySet<string>? ChangedTaskFiles { get; init; }

    /// <summary>D4 review H5: the worker priority of this collection's definition-file parses; null = High.</summary>
    public Sandbox.ScanPriority? ParsePriority { get; init; }
}

/// <summary>
/// Runs each source's machine-wide part in order (registry autoruns, services, Startup folders, scheduled tasks), then each
/// user's own part under that user's sub-budget (section C review M4), against one context: the
/// machine environment and the user profiles are read once. A source that throws is reported as an
/// <see cref="PersistenceIssueReason.Error"/> issue and the next one runs. Nothing is written, executed, or opened beyond
/// registry keys, the Startup / Tasks folders and their files (no-follow, size-capped, parsed only in the sandboxed worker), and attribute-only existence
/// probes where the CreateProcess search order needs one.
/// </summary>
internal sealed class PersistenceCollector(
    IRegistryView registry, IPathProbe probe, IReadOnlyList<IPersistenceSource> sources, PersistenceLimits? limits = null,
    ILogger<PersistenceCollector>? logger = null, IPersistenceFileParser? parser = null, ParsedFileCache? parsedFiles = null) : IScopedPersistenceCollector
{
    /// <summary>Most user profiles looked at (ProfileList and loaded hives).</summary>
    public const int MaxProfiles = 256;

    private const string MachineEnvironmentKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    private readonly PersistenceLimits _limits = limits ?? new PersistenceLimits();
    private readonly ILogger _logger = logger ?? NullLogger<PersistenceCollector>.Instance;

    /// <summary>The real collector: the machine's registry, the safe probe, and every source.</summary>
    /// <param name="parser">Parses shortcuts and task definitions in the sandboxed worker; null = they are reported as not collected.</param>
    /// <remarks>D4: with a <see cref="ParsedFileCache"/>, so a repeat collection parses only the definition files that changed.</remarks>
    public static PersistenceCollector CreateDefault(ILogger<PersistenceCollector>? logger = null, IPersistenceFileParser? parser = null) =>
        new(new WindowsRegistryView(), new SafePathProbe(), DefaultSources(), logger: logger, parser: parser, parsedFiles: new ParsedFileCache());

    public static IReadOnlyList<IPersistenceSource> DefaultSources() => [new RegistryAutorunSource(), new ServiceSource(), new StartupFolderSource(), new ScheduledTaskSource()];

    public IRegistryView Registry => registry;

    /// <summary>The parse results kept for unchanged definition files (null = none kept).</summary>
    internal ParsedFileCache? ParsedFiles => parsedFiles;

    public PersistenceCollection Collect(CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null) =>
        CollectScoped(null, cancellationToken, options).Collection;

    public PersistenceScopedCollection CollectScoped(
        IReadOnlyCollection<PersistenceScope>? scopes, CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null)
    {
        var clock = Stopwatch.StartNew();
        using var freshProbe = probe is SafePathProbe safe ? safe.Fresh() : null;
        var resolver = new CommandLineResolver(freshProbe ?? probe);
        var machine = RegistryEnvironment.Machine(registry);
        var limits = options?.TimeBudget is { } budget && budget < _limits.TimeBudget ? _limits with { TimeBudget = budget } : _limits;
        var context = new PersistenceContext(registry, resolver, machine, [], limits, cancellationToken, clock, parser, parsedFiles)
        {
            ChangedTaskFiles = options?.ChangedTaskFiles,
        };
        using var priority = PersistenceParsePriority.Use(options?.ParsePriority);
        context.Users = RegistryEnvironment.Profiles(registry, machine, context.AddIssue, max: MaxProfiles);
        var timings = sources.ToDictionary(s => s, s => new PersistenceSourceTiming(s.Name, TimeSpan.Zero, 0, 0, 0, TimeSpan.Zero));
        var wanted = scopes is null ? null : new HashSet<PersistenceScope>(scopes);
        var tracker = new ScopeTracker();

        // Section C review M4: everything machine-wide first, so no user's own entries can use up what it needs.
        foreach (var source in sources)
        {
            if (wanted is null || wanted.Contains(new PersistenceScope(source.Name, null)))
            {
                Checkpoint(context, options);
                RunSource(context, source, timings, s => s.CollectMachine(context), new PersistenceScope(source.Name, null), tracker);
            }
        }

        foreach (var user in context.Users)
        {
            var mine = sources.Where(s => wanted is null || wanted.Contains(new PersistenceScope(s.Name, user.Sid))).ToArray();
            if (mine.Length == 0)
            {
                continue;
            }

            Checkpoint(context, options);
            if (!context.CanContinue)
            {
                foreach (var source in mine)
                {
                    tracker.Skipped(new PersistenceScope(source.Name, user.Sid));
                }

                continue;
            }

            context.BeginUser(user);
            foreach (var source in mine)
            {
                RunSource(context, source, timings, s => s.CollectUser(context, user), new PersistenceScope(source.Name, user.Sid), tracker);
            }

            context.EndUser();
        }

        var result = context.ToCollection(sources.Select(s => timings[s]).ToArray());
        _logger.Log(scopes is null ? LogLevel.Information : LogLevel.Debug, "Persistence collection{Scope}: {Entries} entries, {Issues} issues in {Milliseconds} ms. {Timings}",
            scopes is null ? string.Empty : $" of {string.Join(", ", scopes)}", result.Entries.Count, result.Issues.Count, (long)result.Duration.TotalMilliseconds,
            string.Join("; ", result.SourceTimings.Where(t => t.Duration > TimeSpan.Zero || t.Entries > 0)));
        return new PersistenceScopedCollection(result, tracker.EntryScopes, tracker.Outcomes, tracker.IssueScopes(result.Issues.Count));
    }

    public PersistenceWatchPlan Plan(CancellationToken cancellationToken = default)
    {
        var machine = RegistryEnvironment.Machine(registry);
        var resolver = new CommandLineResolver(probe);
        var context = new PersistenceContext(registry, resolver, machine, [], _limits, cancellationToken);
        context.Users = RegistryEnvironment.Profiles(registry, machine, context.AddIssue, max: MaxProfiles);
        bool profilesComplete = context.Issues.Count == 0 && context.Users.Count < MaxProfiles;
        var watches = new List<(PersistenceScope, PersistenceWatchTarget)>
        {
            (PersistenceScope.All, PersistenceWatchTarget.Key(RegistryRoot.LocalMachine, MachineEnvironmentKey)),
            (PersistenceScope.Profiles, PersistenceWatchTarget.Key(RegistryRoot.LocalMachine, RegistryEnvironment.ProfileListPath)),
            (PersistenceScope.Profiles, PersistenceWatchTarget.Key(RegistryRoot.Users, string.Empty)),
        };

        foreach (var source in sources)
        {
            AddTargets(watches, source, new PersistenceScope(source.Name, null), () => source.WatchTargets(context, null));
            foreach (var user in context.Users)
            {
                cancellationToken.ThrowIfCancellationRequested();
                AddTargets(watches, source, new PersistenceScope(source.Name, user.Sid), () => source.WatchTargets(context, user));
            }
        }

        return new PersistenceWatchPlan(watches, sources.Select(s => s.Name).ToArray(), context.Users.Select(u => u.Sid).ToArray(),
            context.Users.Where(u => u.HiveLoaded).Select(u => u.Sid).ToHashSet(StringComparer.OrdinalIgnoreCase), profilesComplete);
    }

    private void AddTargets(
        List<(PersistenceScope, PersistenceWatchTarget)> into, IPersistenceSource source, PersistenceScope scope, Func<IReadOnlyList<PersistenceWatchTarget>> targets)
    {
        try
        {
            foreach (var target in targets())
            {
                into.Add((scope, target));
            }
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            _logger.LogWarning(ex, "Persistence source {Source} couldn't name what to watch for {Scope}", source.Name, scope);
        }
    }

    /// <summary>D4: which scope each entry came from, and what happened to each scope.</summary>
    private sealed class ScopeTracker
    {
        public List<PersistenceScope> EntryScopes { get; } = [];

        public Dictionary<PersistenceScope, PersistenceScopeOutcome> Outcomes { get; } = [];

        private readonly List<(int From, int To, PersistenceScope Scope)> _issueRanges = [];

        public void Ran(PersistenceScope scope, int entries, IEnumerable<PersistenceIssueReason> reasons, bool truncated, int issuesFrom, int issuesTo)
        {
            EntryScopes.AddRange(Enumerable.Repeat(scope, entries));
            Outcomes[scope] = new PersistenceScopeOutcome(truncated, reasons.Distinct().ToArray());
            if (issuesTo > issuesFrom)
            {
                _issueRanges.Add((issuesFrom, issuesTo, scope));
            }
        }

        /// <summary>D4 review H3: the scope each issue was added in (null for the profile listing, before any source).</summary>
        public PersistenceScope?[] IssueScopes(int count)
        {
            var scopes = new PersistenceScope?[count];
            foreach (var (from, to, scope) in _issueRanges)
            {
                for (int i = from; i < to && i < count; i++)
                {
                    scopes[i] = scope;
                }
            }

            return scopes;
        }

        public void Skipped(PersistenceScope scope) => Outcomes[scope] = new PersistenceScopeOutcome(true, [PersistenceIssueReason.TimeBudgetExceeded]);
    }

    /// <summary>M6: the job's checkpoint between sources; time it blocks (paused) is taken off the collection's budget clock.</summary>
    private static void Checkpoint(PersistenceContext context, PersistenceCollectOptions? options)
    {
        if (options?.Checkpoint is not { } checkpoint)
        {
            return;
        }

        long started = Stopwatch.GetTimestamp();
        try
        {
            checkpoint();
        }
        finally
        {
            context.AddPausedTime(Stopwatch.GetElapsedTime(started));
        }
    }

    private void RunSource(
        PersistenceContext context, IPersistenceSource source, Dictionary<IPersistenceSource, PersistenceSourceTiming> timings, Action<IPersistenceSource> collect,
        PersistenceScope scope, ScopeTracker tracker)
    {
        if (!context.CanContinue)
        {
            tracker.Skipped(scope);
            return;
        }

        var (started, entries, issues, parsed, parseTime, reused) =
            (Stopwatch.GetTimestamp(), context.Entries.Count, context.Issues.Count, context.FilesParsed, context.ParseTime, context.ReusedFiles);
        try
        {
            collect(source);
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Persistence source {Source} failed", source.Name);
            context.AddIssue(null, null, source.Name, PersistenceIssueReason.Error, $"The {source.Name} collector failed ({ex.GetType().Name}).");
        }

        var soFar = timings[source];
        timings[source] = soFar with
        {
            Duration = soFar.Duration + Stopwatch.GetElapsedTime(started),
            Entries = soFar.Entries + context.Entries.Count - entries,
            Issues = soFar.Issues + context.Issues.Count - issues,
            ParsedFiles = soFar.ParsedFiles + context.FilesParsed - parsed,
            ParseTime = soFar.ParseTime + context.ParseTime - parseTime,
            ReusedFiles = soFar.ReusedFiles + context.ReusedFiles - reused,
        };
        tracker.Ran(scope, context.Entries.Count - entries, context.Issues.Skip(issues).Select(i => i.Reason), context.Truncated, issues, context.Issues.Count);
    }
}

/// <summary>
/// The real <see cref="IPathProbe"/>: an attributes-only open through <see cref="SafeTree"/>, component by component,
/// never following a junction / symlink / mount point, never on a network drive or UNC path (so SYSTEM can't be made to
/// authenticate to a server), never recalling a cloud file, never reading content. Answers are cached per collection.
/// </summary>
/// <remarks>
/// Speed (the slow-collection finding): opening a path component by component costs one NtCreateFile per folder, and an elevated
/// run probes thousands of candidates along the same few folders (System32, each PATH entry). So each folder is opened once,
/// through <see cref="SafeTree"/>, and kept for this collection (at most <see cref="MaxFolders"/>); a probe is then one
/// relative open, and a folder that doesn't exist answers for everything below it without any open at all.
/// </remarks>
internal sealed class SafePathProbe : IPathProbe, IDisposable
{
    public const int MaxFolders = 128;

    private const uint FolderAccess = N.FileTraverse | N.FileReadAttributes;

    private readonly Dictionary<string, PathProbeResult> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (SafeFileHandle? Handle, SafeTreeFailure Failure)> _folders = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A probe with an empty cache (one per collection, so a file created since is seen).</summary>
    public SafePathProbe Fresh() => new();

    public bool FileExists(string path) => Probe(path) == PathProbeResult.Exists;

    /// <summary>Missing only for "not found": a denied, locked or link-redirected path may well exist (section C review H4).</summary>
    public PathProbeResult Probe(string path)
    {
        if (_cache.TryGetValue(path, out var known))
        {
            return known;
        }

        if (_cache.Count > 10_000)
        {
            _cache.Clear();
        }

        var result = ProbeUncached(path);
        _cache[path] = result;
        return result;
    }

    public void Dispose()
    {
        foreach (var (handle, _) in _folders.Values)
        {
            handle?.Dispose();
        }

        _folders.Clear();
    }

    private PathProbeResult ProbeUncached(string path)
    {
        int separator = path.LastIndexOf('\\');
        if (separator <= 2 || separator == path.Length - 1)
        {
            return Classify(SafeTree.Open(path, N.FileReadAttributes, SafeTree.ShareAll, N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out var failure, out _), failure);
        }

        string parent = path[..separator];
        var (folder, folderFailure) = Folder(parent.EndsWith(':') ? parent + @"\" : parent); // \\?\C: alone isn't a folder
        if (folder is null)
        {
            return folderFailure == SafeTreeFailure.NotFound ? PathProbeResult.Missing : PathProbeResult.Unknown;
        }

        return Classify(SafeTree.OpenChild(folder, path[(separator + 1)..], N.FileReadAttributes, SafeTree.ShareAll, N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out var childFailure, out _), childFailure);
    }

    private static PathProbeResult Classify(SafeFileHandle? handle, SafeTreeFailure failure)
    {
        using (handle)
        {
            return handle is not null ? PathProbeResult.Exists : failure == SafeTreeFailure.NotFound ? PathProbeResult.Missing : PathProbeResult.Unknown;
        }
    }

    private (SafeFileHandle? Handle, SafeTreeFailure Failure) Folder(string path)
    {
        if (_folders.TryGetValue(path, out var known))
        {
            return known;
        }

        if (_folders.Count >= MaxFolders)
        {
            Dispose(); // over the cap: start over, so a hostile PATH can't hold many handles
        }

        var handle = SafeTree.Open(path, FolderAccess, SafeTree.ShareAll, N.FileDirectoryFile, out var failure, out _);
        return _folders[path] = (handle, failure);
    }
}
