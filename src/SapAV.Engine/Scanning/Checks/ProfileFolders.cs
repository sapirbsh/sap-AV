using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Scanning.Checks;

/// <summary>One user profile's high-risk folders (C4), resolved from the registry. Local drive paths, normalized.</summary>
internal sealed record UserFolders(string Sid, string Profile, string? Desktop, string? Downloads, string? Temp, string? RoamingAppData, string? LocalAppData);

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
/// Resolves every user profile's real folders (C4), <b>read-only, from the registry only</b>, like the persistence
/// collectors (C2): profiles from <c>ProfileList</c> (+ loaded hives), each user's Desktop / Downloads / AppData /
/// Local AppData from their <c>User Shell Folders</c> (expanded with that user's own environment), their TEMP from
/// <c>HKU\&lt;SID&gt;\Environment</c>, and the machine TEMP / Public / ProgramData from the machine environment. Never the
/// engine's own environment (that's SYSTEM's profile). A profile whose hive isn't loaded gets the default folders under its
/// profile path. A folder on a network share (UNC) or that isn't a local drive path is left out with a note: the
/// engine never contacts a server. The walk itself (SafeTree) also refuses network drives, junctions and symlinks, so a
/// user who points their own Downloads value somewhere else can only make the engine scan (never write) a local folder.
/// </summary>
internal sealed class RegistryProfileFolders(IRegistryView registry, int maxProfiles = 64) : IProfileFolderSource
{
    /// <summary>The Downloads known-folder GUID (its value name under User Shell Folders).</summary>
    public const string DownloadsValue = "{374DE290-123F-4565-9164-39C4925E467B}";

    private const string ShellFolders = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

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

            using var shell = user.HiveLoaded ? TryOpen(RegistryRoot.Users, $@"{user.Sid}\{ShellFolders}") : null;
            string? Folder(string value, string fallback, string what) =>
                Local(Expand(shell, value, user.Environment) ?? fallback, $"{what} of {user.Sid}", notes);

            string? local = Folder("Local AppData", Path.Join(profile, @"AppData\Local"), "Local AppData");
            users.Add(new UserFolders(
                user.Sid,
                profile,
                Folder("Desktop", Path.Join(profile, "Desktop"), "Desktop"),
                Folder(DownloadsValue, Path.Join(profile, "Downloads"), "Downloads"),
                Local((user.HiveLoaded ? user.Environment.Get("TEMP") : null) ?? (local is null ? null : Path.Join(local, "Temp")), $"TEMP of {user.Sid}", notes),
                Folder("AppData", Path.Join(profile, @"AppData\Roaming"), "AppData"),
                local));
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
