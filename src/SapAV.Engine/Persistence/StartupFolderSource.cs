using Microsoft.Win32.SafeHandles;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using CorePersistenceText = SapAV.Core.Persistence.PersistenceText;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Startup folders (ROADMAP C2): the all-users folder and each user profile's, top level only (Explorer runs only those
/// items). Listed with <see cref="SafeTree"/> (no link followed). A <c>.lnk</c> is parsed by <see cref="ShellLinkParser"/> in the sandboxed worker
/// (never through the shell); any other file (exe, bat, vbs, url...) is itself the target. A symlink or junction in the
/// folder is reported with <see cref="TargetUnresolvedReason.LinkNotFollowed"/>. Items turned off in Task Manager
/// (<c>StartupApproved\StartupFolder</c>) are reported with Enabled false.
/// </summary>
/// <remarks>
/// The folder comes from <c>User Shell Folders</c> (<c>Common Startup</c> / the user's <c>Startup</c>) when set, else the
/// default under ProgramData / the profile. A folder redirected to a network share is reported
/// (section D review H4: <see cref="PersistenceIssueReason.UncheckableStartupFolder"/>, alerted once by D4) and never opened; so is a user's folder the
/// user-folder policy refuses (outside their profile and not theirs). Profiles without a loaded hive use the default path.
/// </remarks>
/// <param name="policy">Section D review H4 (review L2): the policy a user's Startup folder must pass; null = the default (inside the
/// profile, or a local fixed-drive folder the user owns).</param>
internal sealed class StartupFolderSource(
    IReadOnlyList<(string Folder, string? UserSid)>? folderOverride = null, Scanning.Checks.UserFolderPolicy? policy = null) : IPersistenceSource
{
    public const int MaxItems = 1000;
    private readonly Scanning.Checks.UserFolderPolicy _policy = policy ?? new();
    private const string ShellFolders = @"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private const string Approved = @"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
    private const string DefaultSuffix = @"Microsoft\Windows\Start Menu\Programs\Startup";

    public string Name => "startup folders";

    public void CollectMachine(PersistenceContext context)
    {
        if (folderOverride is not null)
        {
            foreach (var (folder, sid) in folderOverride)
            {
                if (context.CanContinue)
                {
                    CollectOne(context, folder, sid);
                }
            }

            return;
        }

        if (CommonFolder(context) is { } common)
        {
            CollectOne(context, common, null);
        }
    }

    public void CollectUser(PersistenceContext context, UserProfile user)
    {
        if (folderOverride is null && UserFolder(context, user) is { } folder)
        {
            CollectOne(context, folder, user.Sid, user);
        }
    }

    /// <summary>
    /// D4: the Startup folder itself (top level only, as Explorer runs it), the User Shell Folders key that can move it, and
    /// StartupApproved (Task Manager's on / off). A folder on a network share or that isn't a local path isn't watched.
    /// </summary>
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets(PersistenceContext context, UserProfile? user)
    {
        var targets = new List<PersistenceWatchTarget>();
        void AddFolder(string? folder)
        {
            if (folder is not null && !(folder.StartsWith(@"\\", StringComparison.Ordinal) && !folder.StartsWith(@"\\?\", StringComparison.Ordinal))
                && CorePersistenceText.NormalizeLocalPath(folder) is { } local)
            {
                targets.Add(PersistenceWatchTarget.Folder(local, subtree: false));
            }
        }

        if (folderOverride is not null)
        {
            if (user is null)
            {
                folderOverride.ToList().ForEach(f => AddFolder(f.Folder));
            }

            return targets;
        }

        if (user is null)
        {
            AddFolder(CommonFolder(context));
            targets.Add(PersistenceWatchTarget.Key(RegistryRoot.LocalMachine, @"SOFTWARE\" + ShellFolders));
            targets.Add(PersistenceWatchTarget.Key(RegistryRoot.LocalMachine, @"SOFTWARE\" + Approved));
            return targets;
        }

        AddFolder(UserFolder(context, user));
        if (user.HiveLoaded)
        {
            targets.Add(PersistenceWatchTarget.Key(RegistryRoot.Users, $@"{user.Sid}\Software\{ShellFolders}"));
            targets.Add(PersistenceWatchTarget.Key(RegistryRoot.Users, $@"{user.Sid}\Software\{Approved}"));
        }

        return targets;
    }

    private static string? CommonFolder(PersistenceContext context) =>
        ShellFolder(context, RegistryRoot.LocalMachine, @"SOFTWARE\" + ShellFolders, "Common Startup", context.Machine)
            ?? (context.Machine.Get("ProgramData") is { } programData ? Path.Join(programData, DefaultSuffix) : null);

    private static string? UserFolder(PersistenceContext context, UserProfile user) =>
        (user.HiveLoaded ? ShellFolder(context, RegistryRoot.Users, $@"{user.Sid}\Software\{ShellFolders}", "Startup", user.Environment) : null)
            ?? (user.ProfilePath is { } profile ? Path.Join(profile, @"AppData\Roaming", DefaultSuffix) : null);

    private void CollectOne(PersistenceContext context, string folder, string? sid, UserProfile? user = null)
    {
        var environment = sid is null ? context.Machine : context.Users.FirstOrDefault(u => u.Sid == sid)?.Environment ?? context.Machine;
        using var approved = sid is null
            ? context.TryOpen(RegistryRoot.LocalMachine, @"SOFTWARE\" + Approved, PersistenceKind.StartupFolder, null, out _)
            : context.Users.Any(u => u.Sid == sid && u.HiveLoaded)
                ? context.TryOpen(RegistryRoot.Users, $@"{sid}\Software\{Approved}", PersistenceKind.StartupFolder, sid, out _)
                : null;
        string? profile = user?.ProfilePath is { } path ? CorePersistenceText.NormalizeLocalPath(path) : null;
        CollectFolder(context, folder, sid, environment, approved, user is null ? null : _policy, profile);
    }

    private static string? ShellFolder(PersistenceContext context, RegistryRoot root, string path, string name, EnvironmentBlock environment)
    {
        using var key = context.TryOpen(root, path, PersistenceKind.StartupFolder, environment.UserSid, out _);
        return key is not null && PersistenceContext.ReadValue(key, name)?.AsString() is { Length: > 0 } raw ? environment.Expand(raw, out _) : null;
    }

    /// <summary>Section D review H4: a Startup folder sap-AV can't check (reported, alerted once by D4; the scope isn't complete).</summary>
    private static void Uncheckable(PersistenceContext context, string folder, string? sid, string why) =>
        context.AddIssue(PersistenceKind.StartupFolder, sid, folder, PersistenceIssueReason.UncheckableStartupFolder,
            $"The {(sid is null ? "all-users" : "user's")} Startup folder {why}, so what Windows starts from it can't be checked.");

    /// <param name="policy">Review L2 / section D H4: the user-folder policy applied to a user's (redirected) Startup folder; null = none.</param>
    /// <param name="profile">The user's normalized profile folder (for <paramref name="policy"/>).</param>
    private static void CollectFolder(
        PersistenceContext context, string folder, string? sid, EnvironmentBlock environment, IRegistryKeyReader? approved,
        Scanning.Checks.UserFolderPolicy? policy = null, string? profile = null)
    {
        if (folder.StartsWith(@"\\", StringComparison.Ordinal) && !folder.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            Uncheckable(context, folder, sid, "is on a network (UNC or WebDAV) share"); // never opened
            return;
        }

        if (CorePersistenceText.NormalizeLocalPath(folder) is not { } display)
        {
            Uncheckable(context, folder, sid, "isn't a local path");
            return;
        }

        if (policy is not null && sid is not null && profile is not null && !policy.Accepts(display, profile, sid))
        {
            Uncheckable(context, display, sid, "is outside the user's profile, in a folder they don't own"); // review L2: not listed as SYSTEM
            return;
        }

        using var handle = SafeFolderReader.OpenFolder(display, out var failure);
        if (handle is null && failure == PersistenceIssueReason.NetworkLocation)
        {
            Uncheckable(context, display, sid, "is on a network drive");
            return;
        }

        if (handle is null)
        {
            if (failure is { } reason)
            {
                context.AddIssue(PersistenceKind.StartupFolder, sid, display, reason, "The Startup folder can't be listed safely.");
            }

            return;
        }

        List<SafeTreeEntry> items;
        try
        {
            items = SafeTree.List(handle, MaxItems, out bool truncated);
            if (truncated)
            {
                context.AddIssue(PersistenceKind.StartupFolder, sid, display, PersistenceIssueReason.LimitReached, $"More than {MaxItems} items; the rest were skipped.");
            }
        }
        catch (IOException)
        {
            context.AddIssue(PersistenceKind.StartupFolder, sid, display, PersistenceIssueReason.Error, "The Startup folder can't be listed.");
            return;
        }

        var wanted = items.Where(item => !((item.IsDirectory && !item.IsNameSurrogate) || item.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)));
        foreach (var chunk in wanted.Chunk(WorkerLimits.MaxParseBatch))
        {
            if (!context.CanContinue)
            {
                return;
            }

            var links = ParseLinks(context, handle, display, chunk, sid, environment);
            for (int k = 0; k < chunk.Length; k++)
            {
                if (!context.CanContinue)
                {
                    return;
                }

                var (item, link) = (chunk[k], links[k]);
                if (link.Failed)
                {
                    continue; // already reported
                }

                CollectItem(context, display, item, sid, environment, approved, link.Parsed);
            }
        }
    }

    private static bool IsShortcut(SafeTreeEntry item) => !item.IsNameSurrogate && item.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);

    /// <summary>A shortcut of a chunk: its parse result (null when it couldn't be opened), or Failed when reading it threw.</summary>
    private readonly record struct LinkParse(PersistenceParseResult? Parsed, bool Failed);

    /// <summary>C2: opens the chunk's shortcuts and has the worker parse them in one request. Open problems are reported here.</summary>
    private static LinkParse[] ParseLinks(
        PersistenceContext context, SafeFileHandle folder, string display, IReadOnlyList<SafeTreeEntry> chunk, string? sid, EnvironmentBlock environment)
    {
        var links = new LinkParse[chunk.Count]; // by position in the chunk (review L2: names may differ only in case)
        var opened = new List<(SafeFileHandle File, int At, string Path)>();
        try
        {
            for (int k = 0; k < chunk.Count; k++)
            {
                var item = chunk[k];
                if (!IsShortcut(item))
                {
                    continue;
                }

                string itemPath = SafeTree.Child(display, item.Name);
                try
                {
                    if (SafeFolderReader.OpenForParsing(folder, item.Name, ShellLinkParser.MaxSize, out var failure, out var message) is { } file)
                    {
                        opened.Add((file, k, itemPath));
                    }
                    else
                    {
                        context.AddIssue(PersistenceKind.StartupFolder, environment.UserSid, itemPath, failure, message);
                        links[k] = new LinkParse(null, Failed: false);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    ItemUnreadable(context, sid, itemPath, ex); // section C review M3: one item's problem is that item's issue
                    links[k] = new LinkParse(null, Failed: true);
                }
            }

            var results = context.ParseBatch(
                opened.Select(o => new PersistenceParseInput(o.File, WorkerParseKind.ShellLink, o.Path)).ToArray(), PersistenceKind.StartupFolder);
            for (int i = 0; i < opened.Count; i++)
            {
                links[opened[i].At] = new LinkParse(results[i], Failed: false);
            }
        }
        finally
        {
            foreach (var (file, _, _) in opened)
            {
                file.Dispose();
            }
        }

        return links;
    }

    private static void ItemUnreadable(PersistenceContext context, string? sid, string itemPath, Exception ex) =>
        context.AddIssue(PersistenceKind.StartupFolder, sid, itemPath, PersistenceIssueReason.Error, $"The item can't be read ({ex.GetType().Name}).");

    /// <summary>One item; its failure is reported and the next item is collected (section C review M3).</summary>
    private static void CollectItem(
        PersistenceContext context, string display, SafeTreeEntry item, string? sid, EnvironmentBlock environment, IRegistryKeyReader? approved,
        PersistenceParseResult? link)
    {
        try
        {
            bool enabled = approved is null || RegistryAutorunSource.IsApproved(PersistenceContext.ReadValue(approved, item.Name));
            var (command, resolution) = Resolve(context, display, item, environment, link);
            context.Add(new PersistenceEntry(PersistenceKind.StartupFolder, sid, display, item.Name, command, resolution, enabled));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            ItemUnreadable(context, sid, SafeTree.Child(display, item.Name), ex);
        }
    }

    /// <param name="parsed">A shortcut's parse result from <see cref="ParseLinks"/>; null when it couldn't be opened (already reported).</param>
    private static (string Command, ResolvedCommand Resolution) Resolve(
        PersistenceContext context, string display, SafeTreeEntry item, EnvironmentBlock environment, PersistenceParseResult? parsed)
    {
        string itemPath = SafeTree.Child(display, item.Name);
        if (item.IsNameSurrogate)
        {
            return (itemPath, ResolvedCommand.Unresolved(TargetUnresolvedReason.LinkNotFollowed));
        }

        if (!IsShortcut(item))
        {
            return (itemPath, CorePersistenceText.NormalizeLocalPath(itemPath) is { } self
                ? ResolvedCommand.Resolved(self)
                : ResolvedCommand.Unresolved(TargetUnresolvedReason.Malformed));
        }

        if (parsed is null)
        {
            return (itemPath, ResolvedCommand.Unresolved(TargetUnresolvedReason.ShortcutUnreadable));
        }

        if (parsed.Status == PersistenceParseStatus.Malformed)
        {
            context.AddIssue(PersistenceKind.StartupFolder, environment.UserSid, itemPath, PersistenceIssueReason.Malformed, parsed.Message ?? "The shortcut can't be parsed.");
        }

        if (parsed.Link is not { } info)
        {
            return (itemPath, ResolvedCommand.Unresolved(TargetUnresolvedReason.ShortcutUnreadable));
        }

        if (info.Truncated)
        {
            context.AddIssue(PersistenceKind.StartupFolder, environment.UserSid, itemPath, PersistenceIssueReason.LimitReached,
                "The shortcut holds more text than the sandboxed parser returns; the rest wasn't read.");
        }

        var target = ShellLinkTarget.Select(info, environment, display);
        string arguments = info.Arguments ?? string.Empty;
        string command = target.Path is null ? itemPath : $"\"{target.Path}\" {arguments}".TrimEnd();
        var extra = target.Mismatch ? new[] { ResolutionFlag.ShortcutTargetMismatch } : [];
        if (target.Path is null)
        {
            return (command, ResolvedCommand.Unresolved(TargetUnresolvedReason.ShortcutUnreadable, flags: extra));
        }

        ResolvedCommand One(string path) => path.StartsWith(@"\\", StringComparison.Ordinal) && !path.StartsWith(@"\\?\", StringComparison.Ordinal)
            ? ResolvedCommand.Unresolved(TargetUnresolvedReason.NetworkPath, arguments: arguments, flags: [ResolutionFlag.RemotePayload])
            : context.Resolver.ResolveProgram("\"" + path + "\"", arguments, environment, info.WorkingDirectory);

        var resolved = One(target.Path);
        if (target.Others.Count > 0)
        {
            resolved = resolved.WithAdditional(target.Others.Select(One)); // section C review H4: any of them may be what runs
        }

        if (target.UnreadableSource)
        {
            // Follow-up review H-C: the shell opens the ID list's target, which the engine can't name, so the entry stays Unverified.
            resolved = resolved.WithAdditional([ResolvedCommand.Unresolved(TargetUnresolvedReason.ShortcutUnreadable, arguments: arguments)]);
        }

        return (command, extra.Length > 0 ? resolved.WithFlags(extra) : resolved);
    }
}
