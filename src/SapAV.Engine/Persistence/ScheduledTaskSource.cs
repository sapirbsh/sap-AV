using Microsoft.Win32.SafeHandles;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Persistence;
using SapAV.Engine.Scanning;
using CorePersistenceText = SapAV.Core.Persistence.PersistenceText;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Scheduled tasks (ROADMAP C2) from their definition files under <c>%SystemRoot%\System32\Tasks</c>, walked recursively
/// with <see cref="SafeTree"/> (no link followed, depth / count / size capped) and parsed by <see cref="TaskXml"/> in the sandboxed worker (DTD
/// refused, no resolver). One entry per action: an Exec's Command + Arguments is resolved like any program; a COM
/// handler's CLSID is resolved read-only through <c>CLSID\{…}\InprocServer32</c>, with <c>taskhostw.exe</c> as the host.
/// </summary>
/// <remarks>
/// <para>A task whose principal is a user SID gets that user as its scope and is expanded with their environment; for
/// such a task the user's own <c>HKU\&lt;SID&gt;_Classes\CLSID</c> is checked first, because it overrides the machine
/// registration (COM hijacking, flagged <see cref="ResolutionFlag.UserComOverride"/>). Principals given as names or
/// groups use the machine environment: resolving a name to a SID could contact a domain controller. D4 (M5 / M10): unless
/// they are service accounts, such tasks run in some user's session, so every loaded user's Classes override is checked.</para>
/// <para>Limitation: a task deleted from the folder but left in the registry TaskCache (or hidden by removing its
/// security descriptor there) isn't seen here; cross-checking TaskCache belongs to D4.</para>
/// </remarks>
/// <param name="trustedFile">
/// Test seam (D4 review H5): whether an opened task file counts as the system's own; null = by its owner (SYSTEM,
/// Administrators or TrustedInstaller).
/// </param>
internal sealed class ScheduledTaskSource(string? tasksRoot = null, Func<SafeFileHandle, string, bool>? trustedFile = null) : IPersistenceSource
{
    public const int MaxDepth = 16;
    public const int MaxFiles = 10_000;

    /// <summary>The Task Scheduler's own list of registered tasks (admin-only); a file listed there isn't a user's stray file.</summary>
    internal const string TaskCacheTree = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

    private static readonly HashSet<string> TrustedOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18", "S-1-5-32-544", AutoQuarantinePolicy.TrustedInstaller.Value,
    };

    /// <summary>
    /// D4 review H5: one walk's untrusted task files (not owned by the system, not in TaskCache), opened but parsed only after
    /// every trusted one, at most <see cref="PersistenceLimits.MaxUntrustedTaskFiles"/>.
    /// </summary>
    private sealed class WalkState
    {
        public List<(SafeFileHandle File, string TaskPath)> Deferred { get; } = [];

        public int OverCap { get; set; }
    }

    /// <summary>
    /// Section D review H3 / follow-up M3: what the last open found about each task file: "" for the system's own (trusted owner
    /// or in TaskCache), otherwise its budget owner (the file owner's SID, or <see cref="PersistenceEntry.UnregisteredBudget"/>).
    /// A file's kept parse result is reused unopened only while its entry here exists, so a file whose entry was dropped
    /// (bounded: the map starts over) is opened and checked again, never judged on the principal it names. Bounded.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _unregistered = new(StringComparer.OrdinalIgnoreCase);

    private const int MaxUnregisteredKept = 20_000;

    public string Name => "scheduled tasks";

    /// <summary>D4: the Tasks folder and its subfolders (a new, changed or deleted definition file).</summary>
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets(PersistenceContext context, UserProfile? user) =>
        user is null && Root(context) is { } root && CorePersistenceText.NormalizeLocalPath(root) is { } folder ? [PersistenceWatchTarget.Folder(folder, subtree: true)] : [];

    private string? Root(PersistenceContext context) =>
        tasksRoot ?? (context.Machine.SystemRoot is { } systemRoot ? Path.Join(systemRoot, @"System32\Tasks") : null);

    public void CollectMachine(PersistenceContext context)
    {
        string? root = Root(context);
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
        var state = new WalkState();
        var pending = new Stack<(SafeFileHandle Handle, string TaskPath, int Depth)>();
        pending.Push((top, string.Empty, 0));
        try
        {
            while (pending.TryPop(out var current))
            {
                using (current.Handle)
                {
                    if (!context.CanContinue || context.ParserDown)
                    {
                        return;
                    }

                    Walk(context, current, pending, ref files, state);
                }
            }

            CollectDeferred(context, state, path => _unregistered.GetValueOrDefault(path) ?? PersistenceEntry.UnregisteredBudget);
        }
        finally
        {
            while (pending.TryPop(out var left))
            {
                left.Handle.Dispose();
            }

            foreach (var (file, _) in state.Deferred)
            {
                file.Dispose();
            }
        }
    }

    /// <summary>D4 review H5: the untrusted task files, after all the others, then one issue for those over the cap.</summary>
    private static void CollectDeferred(PersistenceContext context, WalkState state, Func<string, string?> budgetOwner)
    {
        foreach (var chunk in state.Deferred.Chunk(WorkerLimits.MaxParseBatch))
        {
            if (!context.CanContinue || context.ParserDown)
            {
                return;
            }

            var results = context.ParseBatch(chunk.Select(o => new PersistenceParseInput(o.File, WorkerParseKind.ScheduledTask, o.TaskPath)).ToArray(), PersistenceKind.ScheduledTask);
            for (int i = 0; i < chunk.Length; i++)
            {
                try
                {
                    CollectTask(context, chunk[i].TaskPath, results[i], budgetOwner(chunk[i].TaskPath));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    TaskUnreadable(context, chunk[i].TaskPath, ex);
                }
            }
        }

        if (state.OverCap > 0)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, @"\", PersistenceIssueReason.LimitReached,
                $"{state.OverCap} task files that aren't the system's (not owned by SYSTEM, Administrators or TrustedInstaller, not registered with the Task Scheduler) "
                + $"were over the cap of {context.Limits.MaxUntrustedTaskFiles}; they were not parsed.");
        }
    }

    /// <summary>The file's owner is SYSTEM, Administrators or TrustedInstaller (the Task Scheduler writes registered tasks as SYSTEM).</summary>
    private static bool IsTrustedOwner(SafeFileHandle file) => OwnerSid(file) is { } owner && TrustedOwners.Contains(owner);

    /// <summary>The file owner's SID, or null when it can't be read.</summary>
    private static string? OwnerSid(SafeFileHandle file)
    {
        var sd = Quarantine.Native.QuarantineNative.TryGetSecurity(file, Quarantine.Native.QuarantineNative.OwnerSecurityInformation, out _);
        try
        {
            return sd is null ? null : new System.Security.AccessControl.RawSecurityDescriptor(sd, 0).Owner?.Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static bool InTaskCache(PersistenceContext context, string taskPath)
    {
        try
        {
            using var key = context.Registry.Open(RegistryRoot.LocalMachine, TaskCacheTree + taskPath);
            return key is not null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException or ArgumentException)
        {
            return false;
        }
    }

    private void Walk(
        PersistenceContext context, (SafeFileHandle Handle, string TaskPath, int Depth) folder,
        Stack<(SafeFileHandle, string, int)> pending, ref int files, WalkState state)
    {
        List<SafeTreeEntry> items;
        try
        {
            items = SafeTree.List(folder.Handle, MaxFiles, out bool truncated);
            if (truncated)
            {
                context.AddIssue(PersistenceKind.ScheduledTask, null, folder.TaskPath + @"\", PersistenceIssueReason.LimitReached, $"More than {MaxFiles} items in one task folder; the rest were skipped.");
            }
        }
        catch (IOException)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, folder.TaskPath + @"\", PersistenceIssueReason.Error, "A task folder can't be listed.");
            return;
        }

        var batch = new List<(string Name, string TaskPath)>(WorkerLimits.MaxParseBatch);
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

            batch.Add((item.Name, taskPath));
            if (batch.Count == WorkerLimits.MaxParseBatch && !CollectBatch(context, folder.Handle, batch, state))
            {
                return;
            }
        }

        CollectBatch(context, folder.Handle, batch, state);
    }

    /// <summary>
    /// C2: opens up to <see cref="WorkerLimits.MaxParseBatch"/> task files, has the worker parse them in one request and
    /// collects each. Empties <paramref name="batch"/>; false when the collection must stop (budget, caps, parser down).
    /// </summary>
    private bool CollectBatch(PersistenceContext context, SafeFileHandle folder, List<(string Name, string TaskPath)> batch, WalkState state)
    {
        if (batch.Count == 0)
        {
            return true;
        }

        if (!context.CanContinue || context.ParserDown)
        {
            batch.Clear();
            return false;
        }

        var opened = new List<(SafeFileHandle File, string TaskPath)>(batch.Count);
        try
        {
            foreach (var (name, taskPath) in batch)
            {
                try
                {
                    // Follow-up M3: reused unopened only when this file's trust is known (trusted: "", else its budget owner); on a miss
                    // (never seen, or the map started over) it is opened, so an unregistered file never falls back to its own principal.
                    if (_unregistered.TryGetValue(taskPath, out var known) && context.TryReuseUnchanged(WorkerParseKind.ScheduledTask, taskPath, out var kept))
                    {
                        CollectTask(context, taskPath, kept, known.Length == 0 ? null : known); // D4 review H5: the folder watch reported no change
                        continue;
                    }

                    if (SafeFolderReader.OpenForParsing(folder, name, TaskXml.MaxBytes, out var failure, out var message) is { } file)
                    {
                        if ((trustedFile?.Invoke(file, taskPath) ?? IsTrustedOwner(file)) || InTaskCache(context, taskPath))
                        {
                            Remember(taskPath, string.Empty); // trusted
                            opened.Add((file, taskPath));
                        }
                        else if (state.Deferred.Count < context.Limits.MaxUntrustedTaskFiles)
                        {
                            // Section D review H3: judged on the file owner's budget, never the principal it names or the engine's.
                            Remember(taskPath, OwnerSid(file) ?? PersistenceEntry.UnregisteredBudget);
                            state.Deferred.Add((file, taskPath)); // D4 review H5: after the system's own tasks
                        }
                        else
                        {
                            file.Dispose();
                            state.OverCap++;
                        }
                    }
                    else
                    {
                        context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, failure, message);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    TaskUnreadable(context, taskPath, ex); // section C review M3: one task's problem is that task's issue
                }
            }

            var results = context.ParseBatch(
                opened.Select(o => new PersistenceParseInput(o.File, WorkerParseKind.ScheduledTask, o.TaskPath)).ToArray(), PersistenceKind.ScheduledTask);
            for (int i = 0; i < opened.Count; i++)
            {
                try
                {
                    CollectTask(context, opened[i].TaskPath, results[i]);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    TaskUnreadable(context, opened[i].TaskPath, ex);
                }
            }
        }
        finally
        {
            foreach (var (file, _) in opened)
            {
                file.Dispose();
            }

            batch.Clear();
        }

        return !context.ParserDown;
    }

    private static void TaskUnreadable(PersistenceContext context, string taskPath, Exception ex) =>
        context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.Error, $"The task can't be read ({ex.GetType().Name}).");

    /// <summary>Remembers an unregistered task file's budget owner (bounded: past the cap the map starts over).</summary>
    /// <summary>Test seam (follow-up M3): as if the bounded trust map had started over.</summary>
    internal void ForgetTrust() => _unregistered.Clear();

    private void Remember(string taskPath, string owner)
    {
        if (_unregistered.Count >= MaxUnregisteredKept)
        {
            _unregistered.Clear();
        }

        _unregistered[taskPath] = owner;
    }

    /// <param name="budgetOwner">Section D review H3: set for an unregistered task file (see <see cref="PersistenceEntry.BudgetOwner"/>).</param>
    private static void CollectTask(PersistenceContext context, string taskPath, PersistenceParseResult parsed, string? budgetOwner = null)
    {
        if (parsed.Status == PersistenceParseStatus.Malformed)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.Malformed, parsed.Message ?? "The task file can't be parsed.");
            return;
        }

        if (parsed.Task is not { } task)
        {
            return; // Unavailable: reported once by the context, and the walk stops
        }

        if (task.Truncated)
        {
            context.AddIssue(PersistenceKind.ScheduledTask, null, taskPath, PersistenceIssueReason.LimitReached,
                $"The task has more than {TaskXml.MaxActions} actions or too much text; the rest wasn't read.");
        }

        var user = task.UserId is { } id && RegistryEnvironment.IsUserSid(id.Trim()) ? id.Trim() : null;
        var profile = user is null ? null : context.Users.FirstOrDefault(u => string.Equals(u.Sid, user, StringComparison.OrdinalIgnoreCase));
        var environment = profile?.Environment ?? context.Machine;
        for (int i = 0; i < task.Actions.Count; i++)
        {
            var action = task.Actions[i];
            if (action.ComClassId is { } clsid)
            {
                var resolution = user is null && RunsInAUsersSession(task.UserId)
                    ? ResolveSessionComHandler(context, clsid, environment)
                    : ResolveComHandler(context, clsid, user, profile?.HiveLoaded == true, environment);
                context.Add(new PersistenceEntry(PersistenceKind.ScheduledTask, user, taskPath, $"ComHandler[{i}]",
                    $"{clsid:B} {action.ComData}".TrimEnd(), resolution, task.Enabled, comClassId: clsid) { BudgetOwner = budgetOwner });
            }
            else
            {
                string command = $"{action.Command} {action.Arguments}".Trim();
                context.Add(new PersistenceEntry(PersistenceKind.ScheduledTask, user, taskPath, $"Exec[{i}]", command,
                    context.Resolver.ResolveProgram(action.Command, action.Arguments, environment, action.WorkingDirectory), task.Enabled) { BudgetOwner = budgetOwner });
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

    private static readonly HashSet<string> ServiceAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18", "S-1-5-19", "S-1-5-20", "SYSTEM", "LocalSystem", @"NT AUTHORITY\SYSTEM", "LOCAL SERVICE", @"NT AUTHORITY\LOCAL SERVICE",
        "LocalService", "NETWORK SERVICE", @"NT AUTHORITY\NETWORK SERVICE", "NetworkService",
    };

    /// <summary>
    /// D4 (section C follow-up M5 / M10): a principal that isn't a user SID and isn't a service account (a <c>GroupId</c>, so no
    /// UserId; a group SID; an account name) runs the task in some user's session, where that user's <c>Classes</c> override the
    /// machine's COM registration.
    /// </summary>
    internal static bool RunsInAUsersSession(string? userId) => userId?.Trim() is not { Length: > 0 } id || !ServiceAccounts.Contains(id);

    /// <summary>
    /// D4 (M5 / M10): a COM handler of a task that runs in whichever user's session: every loaded user's
    /// <c>HKU\&lt;SID&gt;_Classes</c> override counts (flagged <see cref="ResolutionFlag.UserComOverride"/>, the first as the
    /// target and the others plus the machine registration as additional commands), then the machine's registration.
    /// </summary>
    private static ResolvedCommand ResolveSessionComHandler(PersistenceContext context, Guid clsid, EnvironmentBlock environment)
    {
        string? hostPath = context.Machine.SystemRoot is { } root ? CorePersistenceText.NormalizeLocalPath(Path.Join(root, @"System32\taskhostw.exe")) : null;
        string subPath = $@"CLSID\{clsid:B}\InprocServer32";
        var overrides = new List<ResolvedCommand>();
        foreach (var user in context.Users.Where(u => u.HiveLoaded).Take(64))
        {
            if (Server(context, RegistryRoot.Users, $@"{user.Sid}_Classes\{subPath}", user.Sid) is { } dll)
            {
                overrides.Add(context.Resolver.ResolveLibrary(dll, user.Environment, hostPath).WithFlags(ResolutionFlag.UserComOverride));
            }
        }

        var machine = Server(context, RegistryRoot.LocalMachine, $@"SOFTWARE\Classes\{subPath}", null) is { } machineDll
            ? context.Resolver.ResolveLibrary(machineDll, environment, hostPath)
            : null;
        if (overrides.Count == 0)
        {
            return machine ?? ResolvedCommand.Unresolved(TargetUnresolvedReason.ComClassNotRegistered, hostPath);
        }

        var others = overrides.Skip(1).Concat(machine is null ? [] : [machine]).ToArray();
        return others.Length == 0 ? overrides[0] : overrides[0].WithAdditional(others);
    }

    private static string? Server(PersistenceContext context, RegistryRoot root, string path, string? user)
    {
        using var key = context.TryOpen(root, path, PersistenceKind.ScheduledTask, user, out _);
        return key is not null && PersistenceContext.ReadValue(key, string.Empty)?.AsString() is { Length: > 0 } value ? value : null;
    }
}
