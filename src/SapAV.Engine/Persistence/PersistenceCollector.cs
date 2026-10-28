using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    PersistenceCollection Collect(CancellationToken cancellationToken = default);
}

/// <summary>
/// Runs the sources in order (registry autoruns, services, Startup folders, scheduled tasks) against one context: the
/// machine environment and the user profiles are read once. A source that throws is reported as an
/// <see cref="PersistenceIssueReason.Error"/> issue and the next one runs. Nothing is written, executed, or opened beyond
/// registry keys, the Startup / Tasks folders and their files (no-follow, size-capped), and attribute-only existence
/// probes where the CreateProcess search order needs one.
/// </summary>
internal sealed class PersistenceCollector(
    IRegistryView registry, IPathProbe probe, IReadOnlyList<IPersistenceSource> sources, PersistenceLimits? limits = null,
    ILogger<PersistenceCollector>? logger = null) : IPersistenceCollector
{
    private readonly PersistenceLimits _limits = limits ?? new PersistenceLimits();
    private readonly ILogger _logger = logger ?? NullLogger<PersistenceCollector>.Instance;

    /// <summary>The real collector: the machine's registry, the safe probe, and every source.</summary>
    public static PersistenceCollector CreateDefault(ILogger<PersistenceCollector>? logger = null) =>
        new(new WindowsRegistryView(), new SafePathProbe(), DefaultSources(), logger: logger);

    public static IReadOnlyList<IPersistenceSource> DefaultSources() => [new RegistryAutorunSource(), new ServiceSource(), new StartupFolderSource(), new ScheduledTaskSource()];

    public PersistenceCollection Collect(CancellationToken cancellationToken = default)
    {
        var clock = Stopwatch.StartNew();
        var resolver = new CommandLineResolver(probe is SafePathProbe safe ? safe.Fresh() : probe);
        var machine = RegistryEnvironment.Machine(registry);
        var context = new PersistenceContext(registry, resolver, machine, [], _limits, cancellationToken, clock);
        context.Users = RegistryEnvironment.Profiles(registry, machine, context.AddIssue, max: 256);
        foreach (var source in sources)
        {
            if (!context.CanContinue)
            {
                break;
            }

            try
            {
                source.Collect(context);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Persistence source {Source} failed", source.Name);
                context.AddIssue(null, null, source.Name, PersistenceIssueReason.Error, $"The {source.Name} collector failed ({ex.GetType().Name}).");
            }
        }

        var result = context.ToCollection();
        _logger.LogInformation("Persistence collection: {Entries} entries, {Issues} issues in {Milliseconds} ms",
            result.Entries.Count, result.Issues.Count, (long)result.Duration.TotalMilliseconds);
        return result;
    }
}

/// <summary>
/// The real <see cref="IPathProbe"/>: an attributes-only open through <see cref="SafeTree"/>, component by component,
/// never following a junction / symlink / mount point, never on a network drive or UNC path (so SYSTEM can't be made to
/// authenticate to a server), never recalling a cloud file, never reading content. Answers are cached per collection.
/// </summary>
internal sealed class SafePathProbe : IPathProbe
{
    private readonly Dictionary<string, bool> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A probe with an empty cache (one per collection, so a file created since is seen).</summary>
    public SafePathProbe Fresh() => new();

    public bool FileExists(string path)
    {
        if (_cache.TryGetValue(path, out bool known))
        {
            return known;
        }

        if (_cache.Count > 10_000)
        {
            _cache.Clear();
        }

        using var handle = SafeTree.Open(path, N.FileReadAttributes, SafeTree.ShareAll, N.FileNonDirectoryFile | SafeTree.OpenNoRecall, out _, out _);
        bool exists = handle is not null;
        _cache[path] = exists;
        return exists;
    }
}
