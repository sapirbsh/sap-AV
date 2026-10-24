namespace SapAV.Engine.Scanning;

/// <summary>
/// What scan jobs don't scan and the quarantine never touches (review B H1, ROADMAP D3 M5):
/// <list type="bullet">
/// <item><b>Engine folders</b> (<see cref="EngineDataFolders"/>: quarantine store, sandbox folder, install, worker, rules and
/// blocklist folders) are excluded only while <see cref="IFolderTrust"/> verifies them. A path inside an engine folder is
/// excluded only if <b>every</b> engine folder containing it is verified (the install folder holds the worker and rules
/// folders). An unverified engine folder is scanned like any other folder, and <c>onUntrusted</c> is told (the engine
/// raises a health alert), because a user who controls it could hide files there.</item>
/// <item><b>Configured exclusions</b> (<see cref="ScanJobOptions.ExcludedFolders"/>, set by an administrator) are honored
/// as configured.</item>
/// </list>
/// Verification results are cached for <see cref="TrustCacheTime"/>, so a big unverified folder costs one check, not one
/// per file; a folder that changes is re-checked after that.
/// </summary>
public sealed class ExclusionSet
{
    /// <summary>How long one verification result is reused.</summary>
    public static readonly TimeSpan TrustCacheTime = TimeSpan.FromMinutes(1);

    private readonly IFolderTrust _trust;
    private readonly TimeProvider _time;
    private readonly Action<string, string>? _onUntrusted;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, (string? Problem, DateTimeOffset Until)> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="onUntrusted">Called with (folder, why) whenever an engine folder fails verification (once per cache period).</param>
    public ExclusionSet(FolderSet engineFolders, FolderSet configured, IFolderTrust trust, TimeProvider time, Action<string, string>? onUntrusted = null)
    {
        EngineFolders = engineFolders ?? throw new ArgumentNullException(nameof(engineFolders));
        Configured = configured ?? throw new ArgumentNullException(nameof(configured));
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _onUntrusted = onUntrusted;
    }

    /// <summary>Folders that are always excluded, nothing verified (configured exclusions; tests).</summary>
    public static ExclusionSet Always(FolderSet folders) => new(new FolderSet([]), folders, FolderTrust.Default, TimeProvider.System);

    public FolderSet EngineFolders { get; }

    public FolderSet Configured { get; }

    /// <summary>True if <paramref name="path"/> is excluded right now.</summary>
    public bool Contains(string? path)
    {
        if (Configured.Contains(path))
        {
            return true;
        }

        var matches = EngineFolders.Matches(path);
        return matches.Count > 0 && matches.All(IsVerified);
    }

    /// <summary>Verifies one engine folder (cached), reporting a failure.</summary>
    internal bool IsVerified(string folder)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (_cache.TryGetValue(folder, out var cached) && now < cached.Until)
            {
                return cached.Problem is null;
            }
        }

        string? problem;
        try
        {
            problem = _trust.Problem(folder);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            problem = $"it could not be checked ({ex.GetType().Name})";
        }

        lock (_lock)
        {
            _cache[folder] = (problem, now + TrustCacheTime);
        }

        if (problem is not null)
        {
            _onUntrusted?.Invoke(folder, problem);
        }

        return problem is null;
    }
}
