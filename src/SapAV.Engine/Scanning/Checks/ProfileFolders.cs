using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>Which of a user's high-risk folders a path is.</summary>
internal enum UserFolderKind
{
    Desktop,
    Downloads,
    Temp,
    RoamingAppData,
    LocalAppData,
}

/// <summary>A user-configured folder (User Shell Folders / Environment) that passed <see cref="UserFolderPolicy"/>.</summary>
internal sealed record RedirectedFolder(UserFolderKind Kind, string Path);

/// <summary>
/// One user profile's high-risk folders (C4). The positional folders are the <b>defaults under the profile</b> (always
/// walked, review C4 M1 / L4); <see cref="Redirected"/> adds the user's own redirections that passed the policy. Local
/// drive paths, normalized.
/// </summary>
internal sealed record UserFolders(string Sid, string Profile, string? Desktop, string? Downloads, string? Temp, string? RoamingAppData, string? LocalAppData)
{
    /// <summary>User-configured folders accepted on top of the defaults (never instead of them).</summary>
    public IReadOnlyList<RedirectedFolder> Redirected { get; init; } = [];

    /// <summary>The default folder of <paramref name="kind"/> plus any accepted redirections of it.</summary>
    public IEnumerable<string> Folders(UserFolderKind kind)
    {
        string? fallback = kind switch
        {
            UserFolderKind.Desktop => Desktop,
            UserFolderKind.Downloads => Downloads,
            UserFolderKind.Temp => Temp,
            UserFolderKind.RoamingAppData => RoamingAppData,
            _ => LocalAppData,
        };
        if (fallback is not null)
        {
            yield return fallback;
        }

        foreach (var folder in Redirected.Where(r => r.Kind == kind))
        {
            yield return folder.Path;
        }
    }
}

/// <summary>Every profile's folders plus the machine-wide ones (C4 phases 3 and 4).</summary>
/// <param name="Notes">Engine text: folders that were left out (network locations, unusable paths), for the phase summary.</param>
internal sealed record ProfileFolderSet(
    IReadOnlyList<UserFolders> Users, string? MachineTemp, string? PublicDesktop, string? PublicDownloads, string? ProgramData, IReadOnlyList<string> Notes);

/// <summary>Resolves the folder set; fake it in tests.</summary>
internal interface IProfileFolderSource
{
    ProfileFolderSet Resolve();
}

/// <summary>
/// Review C4 M1: a user's own registry values (User Shell Folders, <c>HKU\&lt;SID&gt;\Environment</c>) decide what the
/// SYSTEM engine walks, so they are accepted only when they name something that user could have put there anyway:
/// <list type="bullet">
/// <item>a folder <b>inside that user's profile</b> (the profile path comes from the admin-only ProfileList), or</item>
/// <item>a folder on a <b>local fixed drive that the user owns</b>, read from the folder's own handle (opened through
/// SafeTree: no link followed, no network path).</item>
/// </list>
/// Anything else (<c>C:\</c>, Windows, another user's profile, a share, garbage) is ignored with a phase note, and the
/// default folder under the profile is walked as always, so a bad value can neither blind the scan nor steer it.
/// </summary>
internal sealed class UserFolderPolicy(Func<string, string, bool>? ownedBy = null)
{
    private readonly Func<string, string, bool> _ownedBy = ownedBy ?? IsOwnedOnFixedDrive;

    /// <summary>True if <paramref name="folder"/> (normalized) may be walked for the user <paramref name="sid"/>.</summary>
    public bool Accepts(string folder, string profile, string sid) => IsInside(folder, profile) || _ownedBy(folder, sid);

    internal static bool IsInside(string path, string folder) =>
        string.Equals(path, folder, StringComparison.OrdinalIgnoreCase)
        || path.StartsWith(folder.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

    /// <summary>The folder is a plain local folder on a DRIVE_FIXED volume and its owner is <paramref name="sid"/>.</summary>
    internal static bool IsOwnedOnFixedDrive(string folder, string sid)
    {
        try
        {
            if (folder.Length < 3 || Pipe.Native.PipeNative.DriveType(folder[..3]) != 3 /* DRIVE_FIXED */)
            {
                return false;
            }

            using var handle = SafeTree.Open(folder, SafeTree.InspectAccess, SafeTree.ShareAll, N.FileDirectoryFile, out _, out _);
            if (handle is null || N.TryGetSecurity(handle, N.OwnerSecurityInformation, out _) is not { } sd)
            {
                return false;
            }

            return new RawSecurityDescriptor(sd, 0).Owner is { } owner && owner.Equals(new SecurityIdentifier(sid));
        }
        catch (ArgumentException)
        {
            return false; // not a SID / not a path
        }
    }
}

/// <summary>
/// Resolves every user profile's real folders (C4), <b>read-only, from the registry only</b>, like the persistence
/// collectors (C2): profiles from <c>ProfileList</c> (+ loaded hives); for each profile the default Desktop / Downloads /
/// AppData / Local AppData / TEMP under the profile path (always), plus the user's own redirections from their
/// <c>User Shell Folders</c> and <c>Environment</c> (expanded with that user's own environment) when
/// <see cref="UserFolderPolicy"/> accepts them (review C4 M1). The machine TEMP / Public / ProgramData come from the
/// machine environment. Never the engine's own environment (that's SYSTEM's profile). A folder on a network share (UNC)
/// or that isn't a local drive path is left out with a note: the engine never contacts a server. The walk itself
/// (SafeTree) also refuses network drives, junctions and symlinks.
/// </summary>
internal sealed class RegistryProfileFolders(IRegistryView registry, int maxProfiles = 64, UserFolderPolicy? policy = null) : IProfileFolderSource
{
    /// <summary>The Downloads known-folder GUID (its value name under User Shell Folders).</summary>
    public const string DownloadsValue = "{374DE290-123F-4565-9164-39C4925E467B}";

    private const string ShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

    private readonly UserFolderPolicy _policy = policy ?? new UserFolderPolicy();

    public ProfileFolderSet Resolve()
    {
        var notes = new List<string>();
        var machine = RegistryEnvironment.Machine(registry);
        var profiles = RegistryEnvironment.Profiles(registry, machine,
            (_, _, location, reason, _) => notes.Add($"{location}: {reason}."), maxProfiles);
        var users = new List<UserFolders>();
        foreach (var user in profiles)
        {
            if (Local(user.ProfilePath, $"The profile of {user.Sid}", notes) is not { } profile)
            {
                continue;
            }

            var defaults = new UserFolders(user.Sid, profile, Path.Join(profile, "Desktop"), Path.Join(profile, "Downloads"),
                Path.Join(profile, @"AppData\Local\Temp"), Path.Join(profile, @"AppData\Roaming"), Path.Join(profile, @"AppData\Local"));
            if (!user.HiveLoaded)
            {
                users.Add(defaults);
                continue;
            }

            using var shell = TryOpen(RegistryRoot.Users, $@"{user.Sid}\{ShellFolders}");
            var redirected = new List<RedirectedFolder>();
            void Add(UserFolderKind kind, string? raw, string what)
            {
                if (Local(raw, $"{what} of {user.Sid}", notes) is not { } folder
                    || defaults.Folders(kind).Contains(folder, StringComparer.OrdinalIgnoreCase)
                    || redirected.Any(r => r.Kind == kind && string.Equals(r.Path, folder, StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }

                if (_policy.Accepts(folder, profile, user.Sid))
                {
                    redirected.Add(new RedirectedFolder(kind, folder));
                }
                else
                {
                    notes.Add($"{what} of {user.Sid} points outside that user's profile, to a folder the user doesn't own; only the default folder is walked.");
                }
            }

            Add(UserFolderKind.Desktop, Expand(shell, "Desktop", user.Environment), "Desktop");
            Add(UserFolderKind.Downloads, Expand(shell, DownloadsValue, user.Environment), "Downloads");
            Add(UserFolderKind.Temp, user.Environment.Get("TEMP"), "TEMP");
            Add(UserFolderKind.RoamingAppData, Expand(shell, "AppData", user.Environment), "AppData");
            Add(UserFolderKind.LocalAppData, Expand(shell, "Local AppData", user.Environment), "Local AppData");
            users.Add(defaults with { Redirected = redirected });
        }

        string? systemRoot = machine.SystemRoot;
        string? publicFolder = machine.Get("PUBLIC");
        return new ProfileFolderSet(
            users,
            Local(machine.Get("TEMP") ?? (systemRoot is null ? null : Path.Join(systemRoot, "Temp")), "The machine TEMP", notes),
            publicFolder is null ? null : Local(Path.Join(publicFolder, "Desktop"), "The public Desktop", notes),
            publicFolder is null ? null : Local(Path.Join(publicFolder, "Downloads"), "The public Downloads", notes),
            Local(machine.Get("ProgramData"), "ProgramData", notes),
            notes);
    }

    /// <summary>A local drive path in normalized form, or null (with a note for anything else but a missing value).</summary>
    internal static string? Local(string? path, string what, List<string> notes)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        if (path.StartsWith(@"\\", StringComparison.Ordinal) && !path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            notes.Add($"{what} is on a network share; the engine doesn't scan network locations.");
            return null;
        }

        if (path.Contains('%') || PersistenceText.NormalizeLocalPath(path) is not { } normalized)
        {
            notes.Add($"{what} isn't a local folder path; skipped.");
            return null;
        }

        return normalized.Length > 3 ? normalized.TrimEnd('\\') : normalized;
    }

    private IRegistryKeyReader? TryOpen(RegistryRoot root, string path)
    {
        try
        {
            return registry.Open(root, path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException or ArgumentException)
        {
            return null; // the default folder is used
        }
    }

    private static string? Expand(IRegistryKeyReader? key, string value, EnvironmentBlock environment)
    {
        if (key is null || PersistenceContext.ReadValue(key, value)?.AsString() is not { Length: > 0 } raw)
        {
            return null;
        }

        return environment.Expand(raw, out _);
    }
}
