using System.Diagnostics;
using System.Security;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.Engine.Persistence;

/// <summary>A user profile the collectors look at (ROADMAP C2).</summary>
/// <param name="ProfilePath">The profile folder from ProfileList (expanded with the machine environment), or null.</param>
/// <param name="HiveLoaded">The user's hive is under <c>HKEY_USERS\&lt;SID&gt;</c> (the user is logged on or a service holds it).</param>
/// <param name="Environment">The user's environment (machine + their hive), or a partial one when the hive isn't loaded.</param>
internal sealed record UserProfile(string Sid, string? ProfilePath, bool HiveLoaded, EnvironmentBlock Environment);

/// <summary>Caps and budget of one collection.</summary>
internal sealed record PersistenceLimits
{
    public int MaxEntries { get; init; } = 20_000;

    public int MaxIssues { get; init; } = 1_000;

    /// <summary>Most subkeys / values read from one key (Services, IFEO, a Run key).</summary>
    public int MaxKeyItems { get; init; } = 4_096;

    /// <summary>The whole collection's budget (ROADMAP C2); whatever is left is reported as an issue.</summary>
    // An elevated or SYSTEM run opens every scheduled task; on a cold disk with real-time antivirus each open can cost tens of
    // milliseconds (a CI runner hit 10 s and 30 s budgets, the next run on the same code didn't). The per-source timings tell.
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Most entries from one user's own locations (section C review M4): one user can't crowd out the others.</summary>
    public int MaxEntriesPerUser { get; init; } = 2_000;

    /// <summary>Longest one user's own locations may take; machine-wide locations are always collected first.</summary>
    public TimeSpan UserTimeBudget { get; init; } = TimeSpan.FromSeconds(5);
}

/// <summary>
/// What every source shares during one collection: the registry, the resolver, the environments, the users, and the
/// bounded result. Not thread-safe (sources run one after another).
/// </summary>
internal sealed class PersistenceContext
{
    private readonly List<PersistenceEntry> _entries = [];
    private readonly List<PersistenceIssue> _issues = [];
    private readonly Stopwatch _clock;
    private bool _entryCapReported;
    private bool _budgetReported;
    private UserProfile? _currentUser;
    private bool _userReported;
    private int _userEntries;
    private TimeSpan _userStarted;
    private TimeSpan _paused;

    public PersistenceContext(
        IRegistryView registry, CommandLineResolver resolver, EnvironmentBlock machine, IReadOnlyList<UserProfile> users,
        PersistenceLimits limits, CancellationToken cancellationToken, Stopwatch? clock = null, IPersistenceFileParser? parser = null)
    {
        Registry = registry;
        Resolver = resolver;
        Machine = machine;
        Users = users;
        Limits = limits;
        CancellationToken = cancellationToken;
        _clock = clock ?? Stopwatch.StartNew();
        Parser = parser ?? UnavailablePersistenceParser.NoSandbox;
    }

    public IRegistryView Registry { get; }

    public CommandLineResolver Resolver { get; }

    public EnvironmentBlock Machine { get; }

    public IReadOnlyList<UserProfile> Users { get; set; }

    public PersistenceLimits Limits { get; }

    public CancellationToken CancellationToken { get; }

    /// <summary>Where shortcuts and task definitions get parsed: the sandboxed worker, never this process.</summary>
    public IPersistenceFileParser Parser { get; }

    /// <summary>The parser reported Unavailable in this collection: the rest is not sent to it (and reported once).</summary>
    public bool ParserDown { get; private set; }

    public IReadOnlyList<PersistenceEntry> Entries => _entries;

    public IReadOnlyList<PersistenceIssue> Issues => _issues;

    public TimeSpan Elapsed => Now;

    /// <summary>Running time: the clock minus the time a scan job held the collection paused (M6).</summary>
    private TimeSpan Now => _clock.Elapsed - _paused;

    /// <summary>M6: time the job's checkpoint blocked (paused); it doesn't count against the budgets.</summary>
    public void AddPausedTime(TimeSpan paused) => _paused += paused > TimeSpan.Zero ? paused : TimeSpan.Zero;

    /// <summary>
    /// False once the entry cap or the time budget is reached (each reported once): sources stop their loops.
    /// Throws when the caller cancelled.
    /// </summary>
    public bool CanContinue
    {
        get
        {
            CancellationToken.ThrowIfCancellationRequested();
            if (Now > Limits.TimeBudget)
            {
                if (!_budgetReported)
                {
                    _budgetReported = true;
                    AddIssue(null, null, "persistence collection", PersistenceIssueReason.TimeBudgetExceeded,
                        $"The collection stopped after {Limits.TimeBudget.TotalSeconds:0.#} s; the remaining locations were not collected.");
                }

                return false;
            }

            return !_entryCapReported && UserCanContinue();
        }
    }

    /// <summary>Section C review M4: from here on, what is collected counts against this user's sub-budget.</summary>
    public void BeginUser(UserProfile user)
    {
        _currentUser = user;
        _userReported = false;
        _userEntries = 0;
        _userStarted = Now;
    }

    /// <summary>The current user's part is over: back to the collection's own budget.</summary>
    public void EndUser() => _currentUser = null;

    private bool UserCanContinue()
    {
        if (_currentUser is not { } user)
        {
            return true;
        }

        if (Now - _userStarted > Limits.UserTimeBudget || _userEntries >= Limits.MaxEntriesPerUser)
        {
            if (!_userReported)
            {
                _userReported = true;
                bool outOfTime = _userEntries < Limits.MaxEntriesPerUser;
                AddIssue(null, user.Sid, @"HKU\" + user.Sid, outOfTime ? PersistenceIssueReason.TimeBudgetExceeded : PersistenceIssueReason.LimitReached,
                    outOfTime
                        ? $"The user's own locations took over {Limits.UserTimeBudget.TotalSeconds:0.#} s; the rest of them were not collected."
                        : $"More than {Limits.MaxEntriesPerUser} entries in the user's own locations; the rest were not collected.");
            }

            return false;
        }

        return true;
    }

    public void Add(PersistenceEntry entry)
    {
        if (_currentUser is not null)
        {
            if (!UserCanContinue())
            {
                return;
            }

            _userEntries++;
        }

        if (_entries.Count >= Limits.MaxEntries)
        {
            if (!_entryCapReported)
            {
                _entryCapReported = true;
                AddIssue(entry.Kind, entry.UserSid, entry.Location, PersistenceIssueReason.LimitReached,
                    $"More than {Limits.MaxEntries} entries; the rest were not collected.");
            }

            return;
        }

        _entries.Add(entry);
    }

    /// <summary>
    /// One definition file through the sandboxed parser (blocking: collectors run on a scan thread). The first Unavailable
    /// adds a <see cref="PersistenceIssueReason.ParserUnavailable"/> issue, and later files aren't sent: an unavailable
    /// worker can't cost a restart wait per file. Files are never parsed in this process instead.
    /// </summary>
    public PersistenceParseResult Parse(SafeFileHandle file, WorkerParseKind kind, string displayPath, PersistenceKind entryKind) =>
        ParseBatch([new PersistenceParseInput(file, kind, displayPath)], entryKind)[0];

    /// <summary>
    /// C2: several definition files in one go (the broker sends up to <see cref="WorkerLimits.MaxParseBatch"/> per worker
    /// request), one result per file in order; otherwise as <see cref="Parse"/>.
    /// </summary>
    public IReadOnlyList<PersistenceParseResult> ParseBatch(IReadOnlyList<PersistenceParseInput> files, PersistenceKind entryKind)
    {
        if (files.Count == 0)
        {
            return [];
        }

        if (ParserDown)
        {
            return Enumerable.Repeat(PersistenceParseResult.Unavailable("The sandboxed parser isn't available."), files.Count).ToArray();
        }

        long started = Stopwatch.GetTimestamp();
        IReadOnlyList<PersistenceParseResult> results;
        try
        {
            results = Parser.ParseBatchAsync(files, CancellationToken).GetAwaiter().GetResult();
            if (results.Count != files.Count)
            {
                throw new InvalidOperationException($"The parser returned {results.Count} results for {files.Count} files.");
            }
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            var failed = PersistenceParseResult.Malformed($"The sandboxed parser failed on this file ({ex.GetType().Name})."); // review C M3
            results = Enumerable.Repeat(failed, files.Count).ToArray();
        }
        finally
        {
            ParsedFiles += files.Count;
            ParseTime += Stopwatch.GetElapsedTime(started);
        }

        for (int i = 0; i < results.Count; i++)
        {
            if (results[i].Status == PersistenceParseStatus.Unavailable)
            {
                ParserDown = true;
                AddIssue(entryKind, null, files[i].DisplayPath, PersistenceIssueReason.ParserUnavailable, $"{results[i].Message} What was left of this source was not collected.");
                break;
            }
        }

        return results;
    }

    public void AddIssue(PersistenceKind? kind, string? userSid, string location, PersistenceIssueReason reason, string message)
    {
        if (_issues.Count < Limits.MaxIssues)
        {
            _issues.Add(new PersistenceIssue(kind, userSid, location, reason, message));
        }
    }

    /// <summary>
    /// Opens a key; null when it doesn't exist (nothing to report) or can't be read (an AccessDenied / Error issue is
    /// added). <paramref name="display"/> is the path shown in entries (<c>HKLM\...</c> / <c>HKU\...</c>).
    /// </summary>
    public IRegistryKeyReader? TryOpen(RegistryRoot root, string path, PersistenceKind? kind, string? userSid, out string display)
    {
        display = (root == RegistryRoot.LocalMachine ? @"HKLM\" : @"HKU\") + path;
        try
        {
            return Registry.Open(root, path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            AddIssue(kind, userSid, display, PersistenceIssueReason.AccessDenied, "The key can't be read.");
        }
        catch (Exception ex) when (ex is IOException or ArgumentException)
        {
            AddIssue(kind, userSid, display, PersistenceIssueReason.Error, $"The key can't be read ({ex.GetType().Name}).");
        }

        return null;
    }

    /// <summary>Subkey or value names, capped (a LimitReached issue past the cap); empty on an access problem (an issue).</summary>
    public IReadOnlyList<string> Names(IRegistryKeyReader key, bool subKeys, PersistenceKind? kind, string? userSid, string display)
    {
        try
        {
            var names = subKeys ? key.SubKeyNames() : key.ValueNames();
            if (names.Count <= Limits.MaxKeyItems)
            {
                return names;
            }

            AddIssue(kind, userSid, display, PersistenceIssueReason.LimitReached,
                $"More than {Limits.MaxKeyItems} {(subKeys ? "subkeys" : "values")}; the rest were not read.");
            return names.Take(Limits.MaxKeyItems).ToArray();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException)
        {
            AddIssue(kind, userSid, display, PersistenceIssueReason.AccessDenied, "The key can't be listed.");
            return [];
        }
    }

    /// <summary>A value, or null when missing or unreadable (never throws).</summary>
    public static RegistryData? ReadValue(IRegistryKeyReader key, string name)
    {
        try
        {
            return key.Value(name);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException)
        {
            return null;
        }
    }

    /// <summary>A subkey, or null when missing or unreadable (never throws).</summary>
    public static IRegistryKeyReader? OpenSub(IRegistryKeyReader key, string name)
    {
        try
        {
            return key.OpenSubKey(name);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Definition files sent to the parser so far, and how long the parser took (for the per-source timings).</summary>
    public int ParsedFiles { get; private set; }

    public TimeSpan ParseTime { get; private set; }

    public PersistenceCollection ToCollection(IReadOnlyList<PersistenceSourceTiming>? timings = null) => new(_entries, _issues, Now, timings);
}
