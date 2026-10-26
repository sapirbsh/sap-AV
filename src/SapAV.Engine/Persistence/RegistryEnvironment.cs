using SapAV.Core.Persistence;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Builds the environments the resolver expands with (ROADMAP C2), from the registry only, never from the engine's own
/// process environment (which is SYSTEM's: wrong for user entries and not what a machine entry sees either).
/// </summary>
/// <remarks>
/// <para><b>Machine:</b> <c>Session Manager\Environment</c> (Path, TEMP, windir, ComSpec, ...), plus the variables Windows
/// derives at boot: SystemRoot / SystemDrive (<c>Windows NT\CurrentVersion</c>), ProgramFiles* / CommonProgramFiles*
/// (<c>Windows\CurrentVersion</c>), ProgramData / ALLUSERSPROFILE / PUBLIC (<c>ProfileList</c>). User variables
/// (APPDATA, USERPROFILE...) are unknown for machine entries, so an HKLM Run value using them is reported unresolved.</para>
/// <para><b>User:</b> the machine environment, then USERPROFILE (ProfileList), the session values in
/// <c>HKU\&lt;SID&gt;\Volatile Environment</c> (APPDATA, LOCALAPPDATA, HOMEDRIVE, ...; defaults under USERPROFILE when the
/// session key is missing), then <c>HKU\&lt;SID&gt;\Environment</c>, whose Path is appended to the machine Path as
/// Windows does. A user can override any other variable there (even windir): that is what their processes and tasks
/// really see, so the resolution follows it.</para>
/// </remarks>
internal static class RegistryEnvironment
{
    public const string ProfileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private const int MaxValueLength = EnvironmentBlock.MaxExpandedLength;

    public static EnvironmentBlock Machine(IRegistryView registry)
    {
        var raw = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        CopyValues(registry, RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", raw);

        if (Read(registry, RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "SystemRoot") is { Length: >= 3 } root)
        {
            raw["SystemRoot"] = root;
            raw["SystemDrive"] = root[..2];
        }

        const string current = @"SOFTWARE\Microsoft\Windows\CurrentVersion";
        Map(registry, current, "ProgramFilesDir", raw, "ProgramFiles");
        Map(registry, current, "ProgramFilesDir (x86)", raw, "ProgramFiles(x86)");
        Map(registry, current, "ProgramW6432Dir", raw, "ProgramW6432");
        Map(registry, current, "CommonFilesDir", raw, "CommonProgramFiles");
        Map(registry, current, "CommonFilesDir (x86)", raw, "CommonProgramFiles(x86)");
        Map(registry, current, "CommonW6432Dir", raw, "CommonProgramW6432");
        Map(registry, ProfileListPath, "ProgramData", raw, "ProgramData", "ALLUSERSPROFILE");
        Map(registry, ProfileListPath, "Public", raw, "PUBLIC");
        return EnvironmentBlock.Build(raw);
    }

    /// <summary>The user's environment; with <paramref name="hiveLoaded"/> false, only machine + profile-derived values.</summary>
    public static EnvironmentBlock User(IRegistryView registry, EnvironmentBlock machine, string sid, string? profilePath, bool hiveLoaded)
    {
        var raw = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (profilePath is not null)
        {
            raw["USERPROFILE"] = profilePath;
            raw["APPDATA"] = Path.Join(profilePath, @"AppData\Roaming");
            raw["LOCALAPPDATA"] = Path.Join(profilePath, @"AppData\Local");
            if (profilePath.Length >= 3 && profilePath[1] == ':')
            {
                raw["HOMEDRIVE"] = profilePath[..2];
                raw["HOMEPATH"] = profilePath[2..];
            }
        }

        if (hiveLoaded)
        {
            CopyValues(registry, RegistryRoot.Users, sid + @"\Volatile Environment", raw);
            var userValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            CopyValues(registry, RegistryRoot.Users, sid + @"\Environment", userValues);
            foreach (var (name, value) in userValues)
            {
                raw[name] = name.Equals("Path", StringComparison.OrdinalIgnoreCase) && machine.Get("Path") is { } machinePath
                    ? machinePath.TrimEnd(';') + ";" + value
                    : value;
            }
        }

        return EnvironmentBlock.Build(raw, machine, sid);
    }

    /// <summary>
    /// The user profiles to look at: user SIDs (<c>S-1-5-21-…</c>, Entra ID <c>S-1-12-1-…</c>) from ProfileList and the
    /// loaded hives under HKEY_USERS. Service accounts (S-1-5-18/19/20) never log on interactively and are skipped.
    /// </summary>
    public static List<UserProfile> Profiles(IRegistryView registry, EnvironmentBlock machine, PersistenceContextIssues issues, int max)
    {
        var paths = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var list = registry.Open(RegistryRoot.LocalMachine, ProfileListPath);
            foreach (var sid in (list?.SubKeyNames() ?? []).Where(IsUserSid).Take(max))
            {
                using var profile = list!.OpenSubKey(sid);
                var raw = profile?.Value("ProfileImagePath")?.AsString();
                paths[sid] = raw is null ? null : machine.Expand(raw, out _);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            issues(null, null, @"HKLM\" + ProfileListPath, PersistenceIssueReason.AccessDenied, "The profile list can't be read.");
        }

        var loaded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var users = registry.Open(RegistryRoot.Users, string.Empty);
            foreach (var sid in (users?.SubKeyNames() ?? []).Where(IsUserSid).Take(max))
            {
                loaded.Add(sid);
                paths.TryAdd(sid, null);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            issues(null, null, "HKU", PersistenceIssueReason.AccessDenied, "The loaded user hives can't be listed.");
        }

        return paths.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase).Take(max)
            .Select(p => new UserProfile(p.Key, p.Value, loaded.Contains(p.Key), User(registry, machine, p.Key, p.Value, loaded.Contains(p.Key))))
            .ToList();
    }

    public static bool IsUserSid(string name) =>
        PersistenceEntry.IsSid(name) && (name.StartsWith("S-1-5-21-", StringComparison.Ordinal) || name.StartsWith("S-1-12-1-", StringComparison.Ordinal));

    private static void CopyValues(IRegistryView registry, RegistryRoot root, string path, Dictionary<string, string> into)
    {
        try
        {
            using var key = registry.Open(root, path);
            if (key is null)
            {
                return;
            }

            foreach (var name in key.ValueNames().Take(EnvironmentBlock.MaxVariables))
            {
                if (name.Length > 0 && key.Value(name)?.AsString() is { Length: <= MaxValueLength } value)
                {
                    into[name] = value;
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // A missing piece of the environment shows up as an unknown variable on the entries that need it.
        }
    }

    private static string? Read(IRegistryView registry, RegistryRoot root, string path, string name)
    {
        try
        {
            using var key = registry.Open(root, path);
            return key?.Value(name)?.AsString() is { Length: <= MaxValueLength } value ? value : null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return null;
        }
    }

    private static void Map(IRegistryView registry, string path, string valueName, Dictionary<string, string> into, params string[] names)
    {
        if (Read(registry, RegistryRoot.LocalMachine, path, valueName) is { } value)
        {
            foreach (var name in names)
            {
                into[name] = value;
            }
        }
    }
}

/// <summary>Adds an issue (the context's <see cref="PersistenceContext.AddIssue"/>).</summary>
internal delegate void PersistenceContextIssues(PersistenceKind? kind, string? userSid, string location, PersistenceIssueReason reason, string message);
