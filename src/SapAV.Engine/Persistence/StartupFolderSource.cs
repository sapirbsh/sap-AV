using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using CorePersistenceText = SapAV.Core.Persistence.PersistenceText;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Startup folders (ROADMAP C2): the all-users folder and each user profile's, top level only (Explorer runs only those
/// items). Listed with <see cref="SafeTree"/> (no link followed). A <c>.lnk</c> is resolved by <see cref="ShellLinkParser"/>
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

    public void Collect(PersistenceContext context)
    {
        foreach (var (folder, sid) in folderOverride ?? Folders(context))
        {
            if (!context.CanContinue)
            {
                return;
            }

            var environment = sid is null ? context.Machine : context.Users.FirstOrDefault(u => u.Sid == sid)?.Environment ?? context.Machine;
            using var approved = sid is null
                ? context.TryOpen(RegistryRoot.LocalMachine, @"SOFTWARE\" + Approved, PersistenceKind.StartupFolder, null, out _)
                : context.Users.Any(u => u.Sid == sid && u.HiveLoaded)
                    ? context.TryOpen(RegistryRoot.Users, $@"{sid}\Software\{Approved}", PersistenceKind.StartupFolder, sid, out _)
                    : null;
            CollectFolder(context, folder, sid, environment, approved);
        }
    }

    private static List<(string, string?)> Folders(PersistenceContext context)
    {
        var folders = new List<(string, string?)>();
        string? common = ShellFolder(context, RegistryRoot.LocalMachine, @"SOFTWARE\" + ShellFolders, "Common Startup", context.Machine)
            ?? (context.Machine.Get("ProgramData") is { } programData ? Path.Join(programData, DefaultSuffix) : null);
        if (common is not null)
        {
            folders.Add((common, null));
        }

        foreach (var user in context.Users)
        {
            string? folder = user.HiveLoaded
                ? ShellFolder(context, RegistryRoot.Users, $@"{user.Sid}\Software\{ShellFolders}", "Startup", user.Environment)
                : null;
            folder ??= user.ProfilePath is { } profile ? Path.Join(profile, @"AppData\Roaming", DefaultSuffix) : null;
            if (folder is not null)
            {
                folders.Add((folder, user.Sid));
            }
        }

        return folders;
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
            items = SafeTree.List(handle);
        }
        catch (IOException)
        {
            context.AddIssue(PersistenceKind.StartupFolder, sid, display, PersistenceIssueReason.Error, "The Startup folder can't be listed.");
            return;
        }

        if (items.Count > MaxItems)
        {
            context.AddIssue(PersistenceKind.StartupFolder, sid, display, PersistenceIssueReason.LimitReached, $"More than {MaxItems} items; the rest were skipped.");
        }

        foreach (var item in items.Take(MaxItems))
        {
            if (!context.CanContinue)
            {
                return;
            }

            if ((item.IsDirectory && !item.IsNameSurrogate) || item.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            bool enabled = approved is null || RegistryAutorunSource.IsApproved(PersistenceContext.ReadValue(approved, item.Name));
            var (command, resolution) = Resolve(context, handle, display, item, environment);
            context.Add(new PersistenceEntry(PersistenceKind.StartupFolder, sid, display, item.Name, command, resolution, enabled));
        }
    }

    private static (string Command, ResolvedCommand Resolution) Resolve(
        PersistenceContext context, SafeFileHandle folder, string display, SafeTreeEntry item, EnvironmentBlock environment)
    {
        string itemPath = SafeTree.Child(display, item.Name);
        if (item.IsNameSurrogate)
        {
            return (itemPath, ResolvedCommand.Unresolved(TargetUnresolvedReason.LinkNotFollowed));
        }

        if (!item.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return (itemPath, CorePersistenceText.NormalizeLocalPath(itemPath) is { } self
                ? ResolvedCommand.Resolved(self)
                : ResolvedCommand.Unresolved(TargetUnresolvedReason.Malformed));
        }

        var bytes = SafeFolderReader.ReadFile(folder, item.Name, ShellLinkParser.MaxSize, out var failure, out var message);
        var info = bytes is null ? null : ShellLinkParser.Parse(bytes, out var error);
        if (info is null)
        {
            if (bytes is null)
            {
                context.AddIssue(PersistenceKind.StartupFolder, environment.UserSid, itemPath, failure, message);
            }

            return (itemPath, ResolvedCommand.Unresolved(TargetUnresolvedReason.ShortcutUnreadable));
        }

        var target = ShellLinkTarget.Select(info, environment, display);
        string arguments = info.Arguments ?? string.Empty;
        string command = target.Path is null ? itemPath : $"\"{target.Path}\" {arguments}".TrimEnd();
        var extra = target.Mismatch ? new[] { ResolutionFlag.ShortcutTargetMismatch } : [];
        if (target.Network)
        {
            return (command, ResolvedCommand.Unresolved(TargetUnresolvedReason.NetworkPath, arguments: arguments, flags: [ResolutionFlag.RemotePayload, .. extra]));
        }

        if (target.Path is null)
        {
            return (command, ResolvedCommand.Unresolved(TargetUnresolvedReason.ShortcutUnreadable, flags: extra));
        }

        var resolved = context.Resolver.ResolveProgram("\"" + target.Path + "\"", arguments, environment);
        return (command, extra.Length > 0 ? resolved.WithFlags(extra) : resolved);
    }
}
