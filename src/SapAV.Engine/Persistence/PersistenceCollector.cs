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
    ILogger<PersistenceCollector>? logger = null, IPersistenceFileParser? parser = null) : IPersistenceCollector
{
    private readonly PersistenceLimits _limits = limits ?? new PersistenceLimits();
    private readonly ILogger _logger = logger ?? NullLogger<PersistenceCollector>.Instance;

    /// <summary>The real collector: the machine's registry, the safe probe, and every source.</summary>
    /// <param name="parser">Parses shortcuts and task definitions in the sandboxed worker; null = they are reported as not collected.</param>
    public static PersistenceCollector CreateDefault(ILogger<PersistenceCollector>? logger = null, IPersistenceFileParser? parser = null) =>
        new(new WindowsRegistryView(), new SafePathProbe(), DefaultSources(), logger: logger, parser: parser);

    public static IReadOnlyList<IPersistenceSource> DefaultSources() => [new RegistryAutorunSource(), new ServiceSource(), new StartupFolderSource(), new ScheduledTaskSource()];

    public PersistenceCollection Collect(CancellationToken cancellationToken = default, PersistenceCollectOptions? options = null)
    {
        var clock = Stopwatch.StartNew();
        using var freshProbe = probe is SafePathProbe safe ? safe.Fresh() : null;
        var resolver = new CommandLineResolver(freshProbe ?? probe);
        var machine = RegistryEnvironment.Machine(registry);
        var limits = options?.TimeBudget is { } budget && budget < _limits.TimeBudget ? _limits with { TimeBudget = budget } : _limits;
        var context = new PersistenceContext(registry, resolver, machine, [], limits, cancellationToken, clock, parser);
        context.Users = RegistryEnvironment.Profiles(registry, machine, context.AddIssue, max: 256);
        var timings = sources.ToDictionary(s => s, s => new PersistenceSourceTiming(s.Name, TimeSpan.Zero, 0, 0, 0, TimeSpan.Zero));

        // Section C review M4: everything machine-wide first, so no user's own entries can use up what it needs.
        foreach (var source in sources)
        {
            Checkpoint(context, options);
            RunSource(context, source, timings, s => s.CollectMachine(context));
        }

        foreach (var user in context.Users)
        {
            Checkpoint(context, options);
            if (!context.CanContinue)
            {
                break;
            }

            context.BeginUser(user);
            foreach (var source in sources)
            {
                RunSource(context, source, timings, s => s.CollectUser(context, user));
            }

            context.EndUser();
        }

        var result = context.ToCollection(sources.Select(s => timings[s]).ToArray());
        _logger.LogInformation("Persistence collection: {Entries} entries, {Issues} issues in {Milliseconds} ms. {Timings}",
            result.Entries.Count, result.Issues.Count, (long)result.Duration.TotalMilliseconds, string.Join("; ", result.SourceTimings));
        return result;
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
        PersistenceContext context, IPersistenceSource source, Dictionary<IPersistenceSource, PersistenceSourceTiming> timings, Action<IPersistenceSource> collect)
    {
        if (!context.CanContinue)
        {
            return;
        }

        var (started, entries, issues, parsed, parseTime) = (Stopwatch.GetTimestamp(), context.Entries.Count, context.Issues.Count, context.ParsedFiles, context.ParseTime);
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
            ParsedFiles = soFar.ParsedFiles + context.ParsedFiles - parsed,
            ParseTime = soFar.ParseTime + context.ParseTime - parseTime,
        };
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
