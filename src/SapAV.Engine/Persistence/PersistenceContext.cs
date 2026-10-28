using System.Diagnostics;
using System.Security;
using SapAV.Core.Persistence;

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

    /// <summary>Quick Scan budget (ROADMAP C2: well under 10 s); whatever is left is reported as an issue.</summary>
    // 30 s: an elevated or SYSTEM run reads every scheduled task, and slower machines (CI runners) took just over 10 s.
    // Still a small part of the 3-minute Quick Scan target.
    public TimeSpan TimeBudget { get; init; } = TimeSpan.FromSeconds(30);
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

    public PersistenceContext(
        IRegistryView registry, CommandLineResolver resolver, EnvironmentBlock machine, IReadOnlyList<UserProfile> users,
        PersistenceLimits limits, CancellationToken cancellationToken, Stopwatch? clock = null)
    {
        Registry = registry;
        Resolver = resolver;
        Machine = machine;
        Users = users;
        Limits = limits;
        CancellationToken = cancellationToken;
        _clock = clock ?? Stopwatch.StartNew();
    }

    public IRegistryView Registry { get; }

    public CommandLineResolver Resolver { get; }

    public EnvironmentBlock Machine { get; }

    public IReadOnlyList<UserProfile> Users { get; set; }

    public PersistenceLimits Limits { get; }

    public CancellationToken CancellationToken { get; }

    public IReadOnlyList<PersistenceEntry> Entries => _entries;

    public IReadOnlyList<PersistenceIssue> Issues => _issues;

    public TimeSpan Elapsed => _clock.Elapsed;

    /// <summary>
    /// False once the entry cap or the time budget is reached (each reported once): sources stop their loops.
    /// Throws when the caller cancelled.
    /// </summary>
    public bool CanContinue
    {
        get
        {
            CancellationToken.ThrowIfCancellationRequested();
            if (_clock.Elapsed > Limits.TimeBudget)
            {
                if (!_budgetReported)
                {
                    _budgetReported = true;
                    AddIssue(null, null, "persistence collection", PersistenceIssueReason.TimeBudgetExceeded,
                        $"The collection stopped after {Limits.TimeBudget.TotalSeconds:0.#} s; the remaining locations were not collected.");
                }

                return false;
            }

            return !_entryCapReported;
        }
    }

    public void Add(PersistenceEntry entry)
    {
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

    public PersistenceCollection ToCollection() => new(_entries, _issues, _clock.Elapsed);
}
