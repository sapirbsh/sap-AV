using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using CorePersistenceText = SapAV.Core.Persistence.PersistenceText;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Scheduled tasks (ROADMAP C2) from their definition files under <c>%SystemRoot%\System32\Tasks</c>, walked recursively
/// with <see cref="SafeTree"/> (no link followed, depth / count / size capped) and parsed by <see cref="TaskXml"/> (DTD
/// refused, no resolver). One entry per action: an Exec's Command + Arguments is resolved like any program; a COM
/// handler's CLSID is resolved read-only through <c>CLSID\{…}\InprocServer32</c>, with <c>taskhostw.exe</c> as the host.
/// </summary>
/// <remarks>
/// <para>A task whose principal is a user SID gets that user as its scope and is expanded with their environment; for
/// such a task the user's own <c>HKU\&lt;SID&gt;_Classes\CLSID</c> is checked first, because it overrides the machine
/// registration (COM hijacking, flagged <see cref="ResolutionFlag.UserComOverride"/>). Principals given as names or
/// groups use the machine environment: resolving a name to a SID could contact a domain controller.</para>
/// <para>Limitation: a task deleted from the folder but left in the registry TaskCache (or hidden by removing its
/// security descriptor there) isn't seen here; cross-checking TaskCache belongs to D4.</para>
/// </remarks>
internal sealed class ScheduledTaskSource(string? tasksRoot = null) : IPersistenceSource
{
    public const int MaxDepth = 16;
    public const int MaxFiles = 10_000;

    public string Name => "scheduled tasks";

    public void Collect(PersistenceContext context)
    {
        string? root = tasksRoot ?? (context.Machine.SystemRoot is { } systemRoot ? Path.Join(systemRoot, @"System32\Tasks") : null);
        if (root is null || CorePersistenceText.NormalizeLocalPath(root) is not { } folder)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, root ?? "Tasks", PersistenceIssueReason.Error, "The Tasks folder isn't known.");
            return;
        }

        var top = SafeFolderReader.OpenFolder(folder, out var failure);
        if (top is null)
        {
            if (failure is { } reason)
            {
                context.AddIssue(PersistenceKind.ScheduledTask, null, folder, reason, "The Tasks folder can't be listed safely.");
            }

            return;
        }

        int files = 0;
        var pending = new Stack<(SafeFileHandle Handle, string TaskPath, int Depth)>();
        pending.Push((top, string.Empty, 0));
        try
        {
            while (pending.TryPop(out var current))
            {
                using (current.Handle)
                {
                    if (!context.CanContinue)
                    {
                        return;
                    }

                    Walk(context, current, pending, ref files);
                }
            }
        }
        finally
        {
            while (pending.TryPop(out var left))
            {
                left.Handle.Dispose();
            }
        }
    }

    private static void Walk(
        PersistenceContext context, (SafeFileHandle Handle, string TaskPath, int Depth) folder,
        Stack<(SafeFileHandle, string, int)> pending, ref int files)
    {
        List<SafeTreeEntry> items;
        try
        {
            items = SafeTree.List(folder.Handle);
        }
        catch (IOException)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, folder.TaskPath + @"\", PersistenceIssueReason.Error, "A task folder can't be listed.");
            return;
        }

        foreach (var item in items)
        {
            string taskPath = folder.TaskPath + @"\" + item.Name;
            if (item.IsNameSurrogate)
            {
                context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.LinkNotFollowed, "A link in the Tasks folder; not followed.");
                continue;
            }

            if (item.IsDirectory)
            {
                if (folder.Depth + 1 >= MaxDepth)
                {
                    context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.LimitReached, "Task folders nested too deep; skipped.");
                }
                else if (SafeFolderReader.OpenSubfolder(folder.Handle, item.Name, out var failure) is { } sub)
                {
                    pending.Push((sub, taskPath, folder.Depth + 1));
                }
                else if (failure is { } reason)
                {
                    context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, reason, "A task folder can't be opened safely.");
                }

                continue;
            }

            if (++files > MaxFiles)
            {
                if (files == MaxFiles + 1)
                {
                    context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.LimitReached, $"More than {MaxFiles} task files; the rest were skipped.");
                }

                continue;
            }

            if (!context.CanContinue)
            {
                return;
            }

            CollectTask(context, folder.Handle, item.Name, taskPath);
        }
    }

    private static void CollectTask(PersistenceContext context, SafeFileHandle folder, string name, string taskPath)
    {
        var bytes = SafeFolderReader.ReadFile(folder, name, TaskXml.MaxBytes, out var failure, out var message);
        if (bytes is null)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, failure, message);
            return;
        }

        var task = TaskXml.Parse(bytes, out var error);
        if (task is null)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.Malformed, error ?? "The task file can't be parsed.");
            return;
        }

        var user = task.UserId is { } id && RegistryEnvironment.IsUserSid(id.Trim()) ? id.Trim() : null;
        var profile = user is null ? null : context.Users.FirstOrDefault(u => string.Equals(u.Sid, user, StringComparison.OrdinalIgnoreCase));
        var environment = profile?.Environment ?? context.Machine;
        for (int i = 0; i < task.Actions.Count; i++)
        {
            var action = task.Actions[i];
            if (action.ComClassId is { } clsid)
            {
                var resolution = ResolveComHandler(context, clsid, user, profile?.HiveLoaded == true, environment);
                context.Add(new PersistenceEntry(PersistenceKind.ScheduledTask, user, taskPath, $"ComHandler[{i}]",
                    $"{clsid:B} {action.ComData}".TrimEnd(), resolution, task.Enabled, comClassId: clsid));
            }
            else
            {
                string command = $"{action.Command} {action.Arguments}".Trim();
                context.Add(new PersistenceEntry(PersistenceKind.ScheduledTask, user, taskPath, $"Exec[{i}]", command,
                    context.Resolver.ResolveProgram(action.Command, action.Arguments, environment), task.Enabled));
            }
        }
    }

    private static ResolvedCommand ResolveComHandler(PersistenceContext context, Guid clsid, string? user, bool hiveLoaded, EnvironmentBlock environment)
    {
        string host = context.Machine.SystemRoot is { } root
            ? CorePersistenceText.NormalizeLocalPath(Path.Join(root, @"System32\taskhostw.exe")) ?? string.Empty
            : string.Empty;
        string? hostPath = host.Length > 0 ? host : null;
        string subPath = $@"CLSID\{clsid:B}\InprocServer32";
        if (user is not null && hiveLoaded && Server(context, RegistryRoot.Users, $@"{user}_Classes\{subPath}", user) is { } userDll)
        {
            return context.Resolver.ResolveLibrary(userDll, environment, hostPath).WithFlags(ResolutionFlag.UserComOverride);
        }

        if (Server(context, RegistryRoot.LocalMachine, $@"SOFTWARE\Classes\{subPath}", user) is { } dll)
        {
            return context.Resolver.ResolveLibrary(dll, environment, hostPath);
        }

        return ResolvedCommand.Unresolved(TargetUnresolvedReason.ComClassNotRegistered, hostPath);
    }

    private static string? Server(PersistenceContext context, RegistryRoot root, string path, string? user)
    {
        using var key = context.TryOpen(root, path, PersistenceKind.ScheduledTask, user, out _);
        return key is not null && PersistenceContext.ReadValue(key, string.Empty)?.AsString() is { Length: > 0 } value ? value : null;
    }
}
