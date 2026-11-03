using SapAV.Core.Hashing;
using SapAV.Engine.Scanning.Checks;

namespace SapAV.Engine.RealTime;

/// <summary>Why a folder is watched.</summary>
internal enum WatchedFolderKind
{
    Downloads,
    Desktop,
    Documents,
    Temp,
    Startup,
    Public,
    MachineTemp,
    CommonStartup,

    /// <summary>An administrator's <see cref="RealTimeOptions.ExtraFolders"/> entry.</summary>
    Configured,
}

/// <summary>One folder to watch (recursively).</summary>
/// <param name="Path">Normalized local drive path (<c>C:\Users\alice\Downloads</c>).</param>
/// <param name="Sid">The profile it belongs to, or null for a machine-wide folder.</param>
internal sealed record WatchedFolder(string Path, WatchedFolderKind Kind, string? Sid = null);

/// <param name="Notes">Engine text: folders left out (network locations, nested in another watched folder, over the cap).</param>
internal sealed record WatchedFolderSet(IReadOnlyList<WatchedFolder> Folders, IReadOnlyList<string> Notes);

/// <summary>Which folders real-time monitoring watches; fake it in tests.</summary>
internal interface IWatchedFolderSource
{
    WatchedFolderSet Resolve();
}

/// <summary>
/// The watched folders (D1), resolved <b>the same way the Quick Scan finds user folders</b> (<see cref="IProfileFolderSource"/>:
/// every profile from the admin-only ProfileList, the defaults under each profile always, plus the user's own redirections
/// only when <see cref="UserFolderPolicy"/> accepts them; network shares are left out with a note). Per profile: Downloads,
/// Desktop, Documents, TEMP (<c>AppData\Local\Temp</c>) and the Startup folder under each accepted Roaming AppData.
/// Machine-wide: the machine TEMP, the Public profile and the all-users Startup folder under ProgramData. Then the
/// administrator's <see cref="RealTimeOptions.ExtraFolders"/>. A folder inside another watched folder is dropped (the outer
/// watch is recursive). Only path strings are produced here; <see cref="RealTimeMonitor"/> opens each through
/// <see cref="Scanning.SafeTree"/> (no link followed, local fixed volumes only) before watching it.
/// </summary>
internal sealed class ProfileWatchedFolders(IProfileFolderSource? profiles, RealTimeOptions options) : IWatchedFolderSource
{
    /// <summary>The Startup folder below a Roaming AppData folder (and below ProgramData for all users).</summary>
    public const string StartupRelative = @"Microsoft\Windows\Start Menu\Programs\Startup";

    public WatchedFolderSet Resolve()
    {
        var notes = new List<string>();
        var candidates = new List<WatchedFolder>();
        if (options.WatchDefaultFolders && profiles is not null)
        {
            var set = profiles.Resolve();
            notes.AddRange(set.Notes);
            foreach (var user in set.Users)
            {
                Add(candidates, user, UserFolderKind.Downloads, WatchedFolderKind.Downloads);
                Add(candidates, user, UserFolderKind.Desktop, WatchedFolderKind.Desktop);
                Add(candidates, user, UserFolderKind.Documents, WatchedFolderKind.Documents);
                Add(candidates, user, UserFolderKind.Temp, WatchedFolderKind.Temp);
                foreach (var roaming in user.Folders(UserFolderKind.RoamingAppData))
                {
                    candidates.Add(new(Path.Join(roaming, StartupRelative), WatchedFolderKind.Startup, user.Sid));
                }
            }

            AddMachine(candidates, set.MachineTemp, WatchedFolderKind.MachineTemp);
            AddMachine(candidates, set.Public, WatchedFolderKind.Public);
            AddMachine(candidates, set.ProgramData is null ? null : Path.Join(set.ProgramData, StartupRelative), WatchedFolderKind.CommonStartup);
        }

        foreach (var extra in options.ExtraFolders)
        {
            if (RegistryProfileFolders.Local(extra, $"The configured real-time folder '{extra}'", notes) is { } folder)
            {
                candidates.Add(new(folder, WatchedFolderKind.Configured));
            }
        }

        return new WatchedFolderSet(Outermost(candidates, options.MaxWatchedFolders, notes), notes);
    }

    private static void Add(List<WatchedFolder> into, UserFolders user, UserFolderKind kind, WatchedFolderKind watched)
    {
        foreach (var folder in user.Folders(kind))
        {
            into.Add(new(folder, watched, user.Sid));
        }
    }

    private static void AddMachine(List<WatchedFolder> into, string? folder, WatchedFolderKind kind)
    {
        if (folder is not null)
        {
            into.Add(new(folder, kind));
        }
    }

    /// <summary>
    /// Distinct folders (exact, case-insensitive), without any folder inside another one (the outer watch covers it), at most
    /// <paramref name="max"/> (the first ones win: user folders come before machine folders and configured extras).
    /// </summary>
    internal static IReadOnlyList<WatchedFolder> Outermost(IEnumerable<WatchedFolder> candidates, int max, List<string> notes)
    {
        var usable = new List<(WatchedFolder Folder, string Key)>();
        foreach (var candidate in candidates)
        {
            if (ExactPath.ToExtended(candidate.Path) is not { } exact)
            {
                notes.Add($"{candidate.Kind} folder '{candidate.Path}' isn't a local folder path; not watched.");
                continue;
            }

            usable.Add((candidate, ExactPath.StripPrefix(exact).TrimEnd('\\') + "\\"));
        }

        var kept = new List<(WatchedFolder Folder, string Key)>();
        foreach (var (folder, key) in usable)
        {
            if (usable.Any(o => o.Key.Length < key.Length && key.StartsWith(o.Key, StringComparison.OrdinalIgnoreCase))
                || kept.Any(k => string.Equals(k.Key, key, StringComparison.OrdinalIgnoreCase)))
            {
                continue; // inside another watched folder (or the same one again): covered by that recursive watch
            }

            kept.Add((folder, key));
        }

        if (kept.Count > max)
        {
            notes.Add($"{kept.Count - max} more folder(s) were not watched (at most {max}).");
        }

        return kept.Take(max).Select(k => k.Folder).ToArray();
    }
}
