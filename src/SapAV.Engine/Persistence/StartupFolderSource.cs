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
/// (<see cref="PersistenceIssueReason.NetworkLocation"/>) and not read. Profiles without a loaded hive use the default path.
/// </remarks>
internal sealed class StartupFolderSource(IReadOnlyList<(string Folder, string? UserSid)>? folderOverride = null) : IPersistenceSource
{
    public const int MaxItems = 1000;
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

        string? common = ShellFolder(context, RegistryRoot.LocalMachine, @"SOFTWARE\" + ShellFolders, "Common Startup", context.Machine)
            ?? (context.Machine.Get("ProgramData") is { } programData ? Path.Join(programData, DefaultSuffix) : null);
        if (common is not null)
        {
            CollectOne(context, common, null);
        }
    }

    public void CollectUser(PersistenceContext context, UserProfile user)
    {
        if (folderOverride is not null)
        {
            return;
        }

        string? folder = user.HiveLoaded
            ? ShellFolder(context, RegistryRoot.Users, $@"{user.Sid}\Software\{ShellFolders}", "Startup", user.Environment)
            : null;
        folder ??= user.ProfilePath is { } profile ? Path.Join(profile, @"AppData\Roaming", DefaultSuffix) : null;
        if (folder is not null)
        {
            CollectOne(context, folder, user.Sid);
        }
    }

    private static void CollectOne(PersistenceContext context, string folder, string? sid)
    {
        var environment = sid is null ? context.Machine : context.Users.FirstOrDefault(u => u.Sid == sid)?.Environment ?? context.Machine;
        using var approved = sid is null
            ? context.TryOpen(RegistryRoot.LocalMachine, @"SOFTWARE\" + Approved, PersistenceKind.StartupFolder, null, out _)
            : context.Users.Any(u => u.Sid == sid && u.HiveLoaded)
                ? context.TryOpen(RegistryRoot.Users, $@"{sid}\Software\{Approved}", PersistenceKind.StartupFolder, sid, out _)
                : null;
        CollectFolder(context, folder, sid, environment, approved);
    }

    private static string? ShellFolder(PersistenceContext context, RegistryRoot root, string path, string name, EnvironmentBlock environment)
    {
        using var key = context.TryOpen(root, path, PersistenceKind.StartupFolder, environment.UserSid, out _);
        return key is not null && PersistenceContext.ReadValue(key, name)?.AsString() is { Length: > 0 } raw ? environment.Expand(raw, out _) : null;
    }

    private static void CollectFolder(PersistenceContext context, string folder, string? sid, EnvironmentBlock environment, IRegistryKeyReader? approved)
    {
        if (folder.StartsWith(@"\\", StringComparison.Ordinal) && !folder.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            context.AddIssue(PersistenceKind.StartupFolder, sid, folder, PersistenceIssueReason.NetworkLocation,
                "The Startup folder is on a network share; the engine doesn't read network locations.");
            return;
        }

        if (CorePersistenceText.NormalizeLocalPath(folder) is not { } display)
        {
            context.AddIssue(PersistenceKind.StartupFolder, sid, folder, PersistenceIssueReason.Malformed, "The Startup folder path isn't a local path.");
            return;
        }

        using var handle = SafeFolderReader.OpenFolder(display, out var failure);
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
