using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Engine.Alerts;
using SapAV.Engine.Persistence.Monitoring;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Persistence.Remediation;

/// <summary>What a remediation call came to. The first four are pipe statuses; the rest map to <see cref="PersistenceActionOutcome"/>.</summary>
internal enum RemediationStatus
{
    NotFound,
    AccessDenied,
    Unavailable,
    Busy,
    Blocked,
    Restored,
    Purged,
    EntryChanged,
    NothingToDo,
    LocationChanged,
    LocationMissing,
    Redirected,
    NotSupported,
    InvalidBackup,
    QuotaExceeded,
    NeedsConfirmation,
    Failed,
}

internal sealed record RemediationResult(RemediationStatus Status, string Reason, PersistenceBackupRecord? Record = null);

/// <summary>D5: Block &amp; remove of autostart entries, with backup and restore. The pipe uses it; fake it in pipe tests.</summary>
internal interface IPersistenceRemediation
{
    bool IsAvailable { get; }

    /// <summary>Blocks the entry the engine collects now under <paramref name="entryId"/>, for <paramref name="client"/>.</summary>
    /// <param name="confirmCritical">Review M3: the user confirmed disabling a boot-critical or core Windows service.</param>
    Task<RemediationResult> BlockAsync(IClientIdentity client, string entryId, CancellationToken cancellationToken = default, bool confirmCritical = false);

    Task<RemediationResult> RestoreAsync(IClientIdentity client, string backupId, CancellationToken cancellationToken = default);

    RemediationResult Purge(IClientIdentity client, string backupId);

    /// <summary>The valid records <paramref name="client"/> may act on.</summary>
    IReadOnlyList<PersistenceBackupRecord> List(IClientIdentity client);
}

/// <summary>
/// D5: "Block &amp; remove" (ROADMAP feature 5). Only ever on an explicit user request over the pipe; nothing here runs on its own.
/// </summary>
/// <remarks>
/// <para><b>Identify, then verify (TOCTOU).</b> The client names an entry only by its <see cref="PersistenceEntryId"/>. The
/// engine collects that entry's scope again now, and acts only on an entry whose own ID is the requested one, so an entry that
/// changed since the ID was given out (another command, another target, switched on or off) is refused (EntryChanged). Right
/// before the change the stored value / state is read again and compared with what was collected (registry values are deleted
/// or rewritten only if they still hold exactly the backed-up bytes, under the same open key).</para>
/// <para><b>Who may act.</b> A machine-wide entry (HKLM, services, IFEO, machine tasks, the all-users Startup folder) needs an
/// administrator. A standard user may act only on entries of their own scope: their own hive's values, their own Startup folder
/// (and only on a file they could delete themselves), their own hive values only where they could set them, tasks whose own
/// security descriptor lets them change them (review M1). Restore and purge: a standard user only on records they created
/// themselves, never on an administrator's block (review M2); listing shows the same records.
/// The ID's own claims only choose what to collect; the decision is on the collected entry.</para>
/// <para><b>Backed up first, never deleted.</b> Every action writes its backup record (HMAC'd, <see cref="IPersistenceBackupStore"/>)
/// before it changes anything (a Startup item's backup is its quarantine item). Values are deleted only for Run / RunOnce /
/// IFEO; Winlogon Shell / Userinit are set back to the Windows default; services are disabled (and stopped), never deleted;
/// tasks are disabled through the Task Scheduler, never deleted or edited on disk; Startup items move into the quarantine.</para>
/// <para><b>Restore</b> puts back exactly what was removed, or re-enables it, and refuses (LocationChanged) when the place
/// now holds something else than what Block &amp; remove left there: nothing is overwritten.</para>
/// <para><b>No re-alerts.</b> While an action runs its keys are held from real-time judgement; afterwards the result is handed
/// to <see cref="PersistenceActionLedger"/>: only the entry's own key, plus (Winlogon, services, tasks) neighbours that D4 had judged in
/// exactly their pre-action state (review H1), so D4 neither re-alerts a blocked entry nor raises "new entry" for a restored one,
/// while anything else written into the same key or folder is still judged.</para>
/// <para>Every action is an Event Log alert: 3002 PersistenceBlocked, 3003 PersistenceRestored, with the entry kind's MITRE ID.</para>
/// <para>One action at a time (a lock), so two requests can't interleave on the same entry.</para>
/// </remarks>
internal sealed partial class PersistenceRemediator : IPersistenceRemediation
{
    /// <summary>Most active backups one standard user may have (each Block &amp; remove of theirs adds one).</summary>
    public const int MaxActivePerUser = 200;

    /// <summary>Most records (active and restored) one standard user may have; the oldest restored ones make room.</summary>
    public const int MaxRecordsPerUser = 400;

    private static readonly TimeSpan CollectionBudget = TimeSpan.FromSeconds(30);
    /// <summary>How long a request waits for the action before it to end, then gets Busy.</summary>
    internal TimeSpan LockWait { get; init; } = TimeSpan.FromSeconds(30);

    private readonly IScopedPersistenceCollector _collector;
    private readonly Lazy<IPersistenceBackupStore?> _lazyStore;
    private readonly IRegistryValueEditor _registry;
    private readonly IServiceControl _services;
    private readonly ITaskSchedulerControl _tasks;
    private readonly IQuarantineService? _quarantine;
    private readonly IAlertDispatcher? _alerts;
    private readonly PersistenceActionLedger _ledger;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _one = new(1, 1);

    public PersistenceRemediator(
        IScopedPersistenceCollector collector, Func<IPersistenceBackupStore?> store, IRegistryValueEditor registry, IServiceControl services,
        ITaskSchedulerControl tasks, IQuarantineService? quarantine, PersistenceActionLedger ledger, TimeProvider time, ILogger? logger = null,
        IAlertDispatcher? alerts = null)
    {
        _collector = collector ?? throw new ArgumentNullException(nameof(collector));
        ArgumentNullException.ThrowIfNull(store);
        _lazyStore = new Lazy<IPersistenceBackupStore?>(store, LazyThreadSafetyMode.ExecutionAndPublication);
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _tasks = tasks ?? throw new ArgumentNullException(nameof(tasks));
        _quarantine = quarantine;
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? NullLogger.Instance;
        _alerts = alerts;
    }

    /// <summary>
    /// The engine's remediation: the shared collector, the real registry / SCM / Task Scheduler, the quarantine, and the backup
    /// store in <c>%ProgramData%\sap-AV\PersistenceBackups</c>, created on first use and only when the engine runs protected
    /// (a non-elevated debug run must never create the engine's data folders; Block &amp; remove is then unavailable).
    /// </summary>
    internal static PersistenceRemediator CreateDefault(IServiceProvider services)
    {
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("SapAV.Engine.BlockAndRemove");
        var collector = services.GetRequiredService<IPersistenceCollector>() as IScopedPersistenceCollector
            ?? throw new InvalidOperationException("The registered persistence collector can't collect by scope.");
        var keys = services.GetRequiredService<IQuarantineKeyProvider>();
        IPersistenceBackupStore? Store() => EngineAccount.IsProtected()
            ? FilePersistenceBackupStore.TryCreate(Path.Combine(Scanning.EngineDataFolders.ProgramDataRoot, "PersistenceBackups"), keys, QuarantineAccessPolicy.Default, logger)
            : null;
        return new PersistenceRemediator(collector, Store, new NoFollowRegistryEditor(), ScmServiceControl.Instance, ComTaskSchedulerControl.Instance,
            services.GetService<IQuarantineService>(), services.GetRequiredService<PersistenceActionLedger>(), services.GetRequiredService<TimeProvider>(), logger,
            services.GetService<IAlertDispatcher>());
    }

    /// <summary>The engine's own service: never disabled through Block &amp; remove.</summary>
    internal string OwnServiceName { get; init; } = EngineHost.ServiceName;

    /// <summary>
    /// Section D review H2 / follow-up M1: the longest the caller waits for one action. Its thread has a watchdog that cancels its
    /// synchronous I/O from 3/4 of this on (an open stuck behind an oplock break). At this the caller gets Failed, but the lock
    /// stays held until the action's thread really ends, so a late action can't overlap the next one (they get Busy meanwhile).
    /// </summary>
    internal TimeSpan ActionTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Runs one action on its own background thread with an I/O watchdog, and waits at most <see cref="ActionTimeout"/>. The
    /// caller holds <c>_one</c> and hands it over: it is released in the action thread's own <c>finally</c>, never before.
    /// </summary>
    private async Task<RemediationResult> Guarded(Func<RemediationResult> action, CancellationToken cancellationToken)
    {
        var done = new TaskCompletionSource<RemediationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                using var watch = RealTime.ScanThreadWatch.ForCurrentThread();
                using var timer = new Timer(_ => watch.CancelIfOverdue(Environment.TickCount64), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
                watch.Arm("Block & remove", "action", ActionTimeout * 3 / 4);
                try
                {
                    done.TrySetResult(action());
                }
                finally
                {
                    watch.Disarm();
                }
            }
            catch (Exception ex)
            {
                done.TrySetException(ex);
            }
            finally
            {
                _one.Release(); // only now may the next action run
            }
        })
        {
            IsBackground = true,
            Name = "sap-AV Block & remove",
        };
        try
        {
            thread.Start();
        }
        catch
        {
            _one.Release();
            throw;
        }

        try
        {
            return await done.Task.WaitAsync(ActionTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _logger.LogError("Block & remove: an action didn't finish within {Limit}; it keeps the lock until it ends. It may still complete: check the backup list.", ActionTimeout);
            return new(RemediationStatus.Failed, "The action didn't finish in time (a file or key it needed was held). It may still complete; check the backups before trying again.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested && !done.Task.IsCompleted)
        {
            return new(RemediationStatus.Failed, "The request was cancelled while the action ran. It may still complete; check the backups before trying again.");
        }
    }


    public bool IsAvailable => _lazyStore.Value is not null;

    // ---- Block & remove ----

    public async Task<RemediationResult> BlockAsync(IClientIdentity client, string entryId, CancellationToken cancellationToken = default, bool confirmCritical = false)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (!PersistenceEntryId.TryParse(entryId, out var kind, out bool machine))
        {
            return new(RemediationStatus.NotFound, "That isn't an autostart entry ID.");
        }

        if (_lazyStore.Value is not { } store)
        {
            return Unavailable();
        }

        // Section D review M1: kinds that are only ever machine-wide are refused before anything is collected.
        if (!client.IsAdmin && (machine || kind is PersistenceKind.Service or PersistenceKind.IfeoDebugger or PersistenceKind.IfeoSilentProcessExit))
        {
            return MachineOnly();
        }

        if (!await _one.WaitAsync(LockWait, cancellationToken).ConfigureAwait(false))
        {
            return new(RemediationStatus.Busy, "Another Block & remove or restore is running; try again.");
        }

        return await Guarded(() => Block(store, client, entryId, kind, machine, confirmCritical, cancellationToken), cancellationToken).ConfigureAwait(false); // Guarded releases _one
    }

    private RemediationResult Block(
        IPersistenceBackupStore store, IClientIdentity client, string entryId, PersistenceKind kind, bool machine, bool confirmCritical, CancellationToken ct)
    {
        var scopes = ScopesFor(kind, machine, client, ct);
        var collected = _collector.CollectScoped(scopes, ct, CollectOptions(client, scopes, kind));
        int at = Enumerable.Range(0, collected.Collection.Entries.Count).FirstOrDefault(i => PersistenceEntryId.Compute(collected.Collection.Entries[i]) == entryId, -1);
        if (at < 0)
        {
            return new(RemediationStatus.EntryChanged, "That autostart entry isn't there any more as it was (it changed or was removed); refresh and try again.");
        }

        var entry = collected.Collection.Entries[at];
        var scope = collected.EntryScopes[at];
        if (!MayAct(client, entry.UserSid))
        {
            return entry.UserSid is null ? MachineOnly() : new(RemediationStatus.AccessDenied, "This autostart entry belongs to another user.");
        }

        if (MakeRoom(store, client) is { } full)
        {
            return full;
        }

        var held = HoldPrefixes(entry);
        _ledger.Hold(held);
        try
        {
            var context = new BlockContext(store, client, entry, FilePersistenceBackupStore.NewId(), _time.GetUtcNow(), ct) { ConfirmCritical = confirmCritical };
            var result = entry.Kind switch
            {
                PersistenceKind.RunKey or PersistenceKind.RunOnceKey or PersistenceKind.IfeoDebugger or PersistenceKind.IfeoSilentProcessExit => BlockValue(context),
                PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit => BlockWinlogon(context),
                PersistenceKind.Service => BlockService(context),
                PersistenceKind.ScheduledTask => BlockTask(context),
                PersistenceKind.StartupFolder => BlockStartupItem(context),
                _ => new(RemediationStatus.NotSupported, "This kind of autostart entry can't be blocked."),
            };

            if (result is { Status: RemediationStatus.Blocked, Record: { } record })
            {
                if (!HandOver(scope, collected, BlockPlan(entry), entry.Kind, entry.UserSid, entry.Location, client, ct))
                {
                    result = new(RemediationStatus.EntryChanged,
                        $"The entry was blocked (backup {record.Id}), but it came back right away: something re-created or changed it. Real-time monitoring judges it again.",
                        record);
                }

                Record(AlertType.PersistenceBlocked, record, client);
                _logger.LogInformation("Block & remove: user {User} blocked autostart entry {Location} {Value} ({Kind}) as backup {Backup}: {Reason}",
                    client.User.Value, entry.Location, entry.ValueName, entry.Kind, record.Id, result.Reason);
            }
            else
            {
                _logger.LogWarning("Block & remove: user {User} asked to block {Location} {Value} ({Kind}): {Status}, {Reason}",
                    client.User.Value, entry.Location, entry.ValueName, entry.Kind, result.Status, result.Reason);
            }

            return result;
        }
        finally
        {
            _ledger.Release(held);
        }
    }

    /// <summary>Everything one block needs.</summary>
    private sealed record BlockContext(
        IPersistenceBackupStore Store, IClientIdentity Client, PersistenceEntry Entry, string BackupId, DateTimeOffset Now, CancellationToken Cancellation)
    {
        /// <summary>Review M3: the user confirmed a boot-critical or core service.</summary>
        public bool ConfirmCritical { get; init; }

        public PersistenceBackupRecord NewRecord(PersistenceBackupAction action) => new()
        {
            Id = BackupId,
            Kind = Entry.Kind,
            UserSid = Entry.UserSid,
            Location = Entry.Location,
            ValueName = Entry.ValueName,
            CommandLine = Entry.CommandLine,
            EntryKey = Entry.Key,
            EntryId = PersistenceEntryId.Compute(Entry),
            Action = action,
            State = PersistenceBackupState.Active,
            BlockedBy = Client.User.Value,
            BlockedByAdmin = Client.IsAdmin,
            BlockedAtUtc = Now,
        };
    }

    // ---- Restore / purge / list ----

    public async Task<RemediationResult> RestoreAsync(IClientIdentity client, string backupId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (_lazyStore.Value is not { } store)
        {
            return Unavailable();
        }

        if (Authorized(store, client, backupId, out var record) is { } refused)
        {
            return refused;
        }

        if (record!.State != PersistenceBackupState.Active)
        {
            return new(RemediationStatus.InvalidBackup, "This entry was already restored.", record);
        }

        if (!await _one.WaitAsync(LockWait, cancellationToken).ConfigureAwait(false))
        {
            return new(RemediationStatus.Busy, "Another Block & remove or restore is running; try again.");
        }

        return await Guarded(() => Restore(store, client, backupId, cancellationToken), cancellationToken).ConfigureAwait(false); // Guarded releases _one
    }

    private RemediationResult Restore(IPersistenceBackupStore store, IClientIdentity client, string backupId, CancellationToken ct)
    {
        // Read again under the lock: another restore may have finished meanwhile.
        if (store.TryLoad(backupId, out var record) != BackupLoadStatus.Ok || record!.State != PersistenceBackupState.Active)
        {
            return new(RemediationStatus.InvalidBackup, "This backup is no longer restorable.", record);
        }

        var held = HoldPrefixes(record.Kind, record.UserSid, record.Location);
        _ledger.Hold(held);
        try
        {
            var scopes = ScopesFor(record.Kind, record.UserSid is null, client, ct, record.UserSid);
            var before = HasNeighbours(record.Kind) ? _collector.CollectScoped(scopes, ct, CollectOptions(client, scopes, record.Kind)) : null;
            var result = record.Action switch
            {
                PersistenceBackupAction.ValueDeleted or PersistenceBackupAction.ValueReset => RestoreValue(record, client),
                PersistenceBackupAction.ServiceDisabled => RestoreService(record),
                PersistenceBackupAction.TaskDisabled => RestoreTask(record, client),
                PersistenceBackupAction.FileQuarantined => RestoreStartupItem(record, client, ct),
                _ => new(RemediationStatus.InvalidBackup, "Unknown backup action."),
            };

            if (result.Status != RemediationStatus.Restored)
            {
                _logger.LogWarning("Block & remove: user {User} asked to restore backup {Backup} ({Location} {Value}): {Status}, {Reason}",
                    client.User.Value, record.Id, record.Location, record.ValueName, result.Status, result.Reason);
                return result with { Record = result.Record ?? record };
            }

            var restored = (result.Record ?? record) with { State = PersistenceBackupState.Restored, RestoredAtUtc = _time.GetUtcNow(), RestoredBy = client.User.Value };
            try
            {
                store.Save(restored);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException) // follow-up M1: the entry is back; never lose that
            {
                _logger.LogError("Block & remove: backup {Backup} was restored but its record couldn't be updated ({Why}).", record.Id, ex.Message);
            }

            bool asLeft = HandOver(scopes[0], before, RestorePlan(record), record.Kind, record.UserSid, record.Location, client, ct);
            Record(AlertType.PersistenceRestored, restored, client);
            _logger.LogInformation("Block & remove: user {User} restored backup {Backup} ({Location} {Value}): {Reason}",
                client.User.Value, record.Id, record.Location, record.ValueName, result.Reason);
            return asLeft
                ? result with { Record = restored }
                : new(RemediationStatus.EntryChanged,
                    "The entry was restored, but it changed again right away (or went); real-time monitoring judges what is there now.", restored);
        }
        finally
        {
            _ledger.Release(held);
        }
    }

    public RemediationResult Purge(IClientIdentity client, string backupId)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (_lazyStore.Value is not { } store)
        {
            return Unavailable();
        }

        if (store.TryLoad(backupId, out var record) == BackupLoadStatus.Invalid && client.IsAdmin)
        {
            record = null; // an administrator may drop a record that failed its integrity check
        }
        else if (Authorized(store, client, backupId, out record) is { } refused)
        {
            return refused;
        }

        try
        {
            store.Delete(backupId);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(RemediationStatus.Failed, $"The backup couldn't be removed ({ex.GetType().Name}).", record);
        }

        _logger.LogInformation("Block & remove: user {User} removed backup {Backup}.", client.User.Value, backupId);
        return new(RemediationStatus.Purged, record?.QuarantineItemId is { } item
            ? $"The backup was removed; the Startup item stays in quarantine as item {item}."
            : "The backup was removed; this entry can't be restored any more.", record);
    }

    public IReadOnlyList<PersistenceBackupRecord> List(IClientIdentity client)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (_lazyStore.Value is not { } store)
        {
            return [];
        }

        return store.List().Select(r => r.Record).OfType<PersistenceBackupRecord>().Where(r => MayActOnRecord(client, r))
            .OrderByDescending(r => r.BlockedAtUtc).ToArray();
    }

    // ---- Shared ----

    private static RemediationResult Unavailable() => new(RemediationStatus.Unavailable, "Block & remove is not available in this engine (its protected backup folder can't be used).");

    private static RemediationResult MachineOnly() =>
        new(RemediationStatus.AccessDenied, "This autostart entry is machine-wide; only an administrator may block or restore it.");

    /// <summary>An administrator may act on anything; a standard user only on entries of their own scope.</summary>
    /// <summary>
    /// Review M2: a standard user may see, restore or purge only a record of their own scope that they created themselves; an
    /// administrator's block (even of that user's entry) is undone only by an administrator.
    /// </summary>
    internal static bool MayActOnRecord(IClientIdentity client, PersistenceBackupRecord record) =>
        client.IsAdmin
        || (MayAct(client, record.UserSid) && !record.BlockedByAdmin
            && string.Equals(record.BlockedBy, client.User.Value, StringComparison.OrdinalIgnoreCase));

    internal static bool MayAct(IClientIdentity client, string? entryUserSid) =>
        client.IsAdmin || (entryUserSid is not null && string.Equals(entryUserSid, client.User.Value, StringComparison.OrdinalIgnoreCase));

    /// <summary>The record, if it is valid and the client may act on it (an invalid or foreign record is NotFound for a standard user).</summary>
    private static RemediationResult? Authorized(IPersistenceBackupStore store, IClientIdentity client, string backupId, out PersistenceBackupRecord? record)
    {
        var status = store.TryLoad(backupId, out record);
        if (status == BackupLoadStatus.Invalid)
        {
            return client.IsAdmin
                ? new(RemediationStatus.InvalidBackup, "This backup record failed its integrity check; it is never acted on.")
                : new(RemediationStatus.NotFound, "No such backup.");
        }

        if (status == BackupLoadStatus.NotFound || !MayActOnRecord(client, record!))
        {
            return new(RemediationStatus.NotFound, "No such backup.");
        }

        return null;
    }

    /// <summary>
    /// Bounds the store: a standard user has at most <see cref="MaxActivePerUser"/> active backups and
    /// <see cref="MaxRecordsPerUser"/> records in all, and the store at most <see cref="FilePersistenceBackupStore.MaxRecords"/>.
    /// Over a total cap, the oldest <b>restored</b> records (history only: their entry is back) are dropped to make room;
    /// an active backup is never dropped, so when only active ones are left the block is refused.
    /// </summary>
    private RemediationResult? MakeRoom(IPersistenceBackupStore store, IClientIdentity client)
    {
        var all = store.List();
        var mine = client.IsAdmin ? Array.Empty<PersistenceBackupRecord>() : all.Select(r => r.Record).OfType<PersistenceBackupRecord>()
            .Where(r => !r.BlockedByAdmin && string.Equals(r.BlockedBy, client.User.Value, StringComparison.OrdinalIgnoreCase)).ToArray(); // L3: what this user made
        if (mine.Count(r => r.State == PersistenceBackupState.Active) >= MaxActivePerUser)
        {
            return new(RemediationStatus.QuotaExceeded, $"You already have {MaxActivePerUser} blocked autostart entries; restore or remove some backups first.");
        }

        var restored = (client.IsAdmin ? all.Select(r => r.Record).OfType<PersistenceBackupRecord>() : mine)
            .Where(r => r.State == PersistenceBackupState.Restored).OrderBy(r => r.RestoredAtUtc ?? r.BlockedAtUtc).ToArray();
        int over = Math.Max(client.IsAdmin ? 0 : mine.Length - MaxRecordsPerUser + 1, all.Count - FilePersistenceBackupStore.MaxRecords + 1);
        foreach (var old in restored.Take(Math.Max(0, over)))
        {
            try
            {
                store.Delete(old.Id);
                over--;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning("Block & remove: the old restored backup {Backup} couldn't be removed ({Why}).", old.Id, ex.Message);
            }
        }

        return over > 0
            ? new(RemediationStatus.QuotaExceeded, "The backup store is full of backups that can still be restored; restore or remove some first.")
            : null;
    }

    /// <summary>The source collecting each kind (the collectors' own names).</summary>
    internal static string SourceOf(PersistenceKind kind) => kind switch
    {
        PersistenceKind.Service => "services",
        PersistenceKind.StartupFolder => "startup folders",
        PersistenceKind.ScheduledTask => "scheduled tasks",
        _ => "registry autoruns",
    };

    /// <summary>
    /// What to collect for an entry of <paramref name="kind"/>: services, IFEO and tasks are always collected machine-wide (a
    /// task's user comes from its principal); a user entry is collected in the client's own scope, or for an administrator in
    /// every profile's (or <paramref name="userSid"/>'s, for a restore).
    /// </summary>
    private PersistenceScope[] ScopesFor(PersistenceKind kind, bool machine, IClientIdentity client, CancellationToken ct, string? userSid = null)
    {
        string source = SourceOf(kind);
        if (machine || kind is PersistenceKind.Service or PersistenceKind.ScheduledTask or PersistenceKind.IfeoDebugger or PersistenceKind.IfeoSilentProcessExit)
        {
            return [new PersistenceScope(source, null)];
        }

        if (userSid is not null)
        {
            return [new PersistenceScope(source, userSid)];
        }

        if (!client.IsAdmin)
        {
            return [new PersistenceScope(source, client.User.Value)];
        }

        var users = _collector.Plan(ct).UserSids;
        return users.Count == 0 ? [new PersistenceScope(source, client.User.Value)] : users.Select(sid => new PersistenceScope(source, sid)).ToArray();
    }

    /// <summary>
    /// The baseline-key prefixes an action on this entry can change: the entry's key and its neighbours (a Winlogon value's other
    /// programs, a service's ServiceDll entry, a task's other actions). Holding them only delays their judgement.
    /// </summary>
    private static string[] HoldPrefixes(PersistenceEntry entry) => HoldPrefixes(entry.Kind, entry.UserSid, entry.Location);

    private static string[] HoldPrefixes(PersistenceKind kind, string? userSid, string location)
    {
        string owner = userSid ?? "machine";
        return kind == PersistenceKind.Service
            ? [string.Join('|', kind, owner, ServiceLocation(location).ToUpperInvariant())] // ...\Services\X| and ...\Services\X\PARAMETERS|
            : [string.Join('|', kind, owner, location.ToUpperInvariant()) + "|"];
    }

    /// <summary>A service entry's location without <c>\Parameters</c> (its ImagePath and ServiceDll entries belong together).</summary>
    private static string ServiceLocation(string location) =>
        location.EndsWith(@"\Parameters", StringComparison.OrdinalIgnoreCase) ? location[..^@"\Parameters".Length] : location;

    /// <summary>Whether an entry is in the same place as the acted-on one (a neighbour candidate for <see cref="HasNeighbours"/> kinds).</summary>
    private static bool Touched(PersistenceEntry e, PersistenceKind kind, string? userSid, string location) =>
        e.Kind == kind && string.Equals(e.UserSid, userSid, StringComparison.OrdinalIgnoreCase)
        && (kind == PersistenceKind.Service
            ? string.Equals(ServiceLocation(e.Location), ServiceLocation(location), StringComparison.OrdinalIgnoreCase)
            : string.Equals(e.Location, location, StringComparison.OrdinalIgnoreCase));

    /// <summary>What a key looked like after the action, compared with the state the action should have left.</summary>
    private enum AfterState
    {
        /// <summary>Not there, as expected (nothing to hand over).</summary>
        Absent,

        /// <summary>Exactly the state the action produced: handed over.</summary>
        Expected,

        /// <summary>Something else is there (it came back, or changed again): not handed over; D4 judges it.</summary>
        Unexpected,
    }

    /// <summary>
    /// Section D review H1: what the action must have left, per key. <see cref="Own"/> judges the entry's own key (null when it
    /// is gone); <see cref="Neighbour"/>, for the kinds that change neighbours, judges a neighbour against its pre-action entry.
    /// </summary>
    /// <param name="RejudgeAlways">Follow-up M2 (Block): the key is queued for judging again whatever the hand-over saw, so a value re-created
    /// after the hand-over but before D4's next pass is judged too (a no-op when D4 finds the record gone; an exact accepted state stays silent).</param>
    private sealed record HandOverPlan(
        string EntryKey, Func<PersistenceEntry?, AfterState> Own, Func<PersistenceEntry, PersistenceEntry, bool>? Neighbour, bool RejudgeAlways = false);

    /// <summary>
    /// The plan after a block. Value-type kinds (Run, RunOnce, IFEO, SilentProcessExit, Startup items): the entry must be gone.
    /// Winlogon: only the Windows default program may be there. Services and tasks: the entry and its neighbours must be the
    /// pre-action entries, field by field, now disabled.
    /// </summary>
    private HandOverPlan BlockPlan(PersistenceEntry entry) => entry.Kind switch
    {
        PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit => new(entry.Key,
            after => after is null ? AfterState.Absent : IsWinlogonDefault(after) ? AfterState.Expected : AfterState.Unexpected,
            (_, after) => IsWinlogonDefault(after), RejudgeAlways: true),
        PersistenceKind.Service or PersistenceKind.ScheduledTask => new(entry.Key,
            after => after is null ? AfterState.Absent : DisabledFrom(entry, after) ? AfterState.Expected : AfterState.Unexpected,
            DisabledFrom, RejudgeAlways: true),
        _ => new(entry.Key, after => after is null ? AfterState.Absent : AfterState.Unexpected, null, RejudgeAlways: true),
    };

    /// <summary>The plan after a restore: the entry must be exactly the backed-up one (same entry ID); neighbours unchanged but for their state.</summary>
    private static HandOverPlan RestorePlan(PersistenceBackupRecord record) => new(record.EntryKey,
        after => after is not null && record.EntryId is { } id && PersistenceEntryId.Compute(after) == id ? AfterState.Expected : AfterState.Unexpected,
        HasNeighbours(record.Kind) ? SameStored : null);

    /// <summary>Everything an entry stores apart from its on / off state is what it was before.</summary>
    private static bool SameStored(PersistenceEntry before, PersistenceEntry after) =>
        before.Kind == after.Kind && string.Equals(before.UserSid, after.UserSid, StringComparison.OrdinalIgnoreCase)
        && string.Equals(before.Location, after.Location, StringComparison.Ordinal) && string.Equals(before.ValueName, after.ValueName, StringComparison.Ordinal)
        && string.Equals(before.CommandLine, after.CommandLine, StringComparison.Ordinal) && before.ComClassId == after.ComClassId;

    /// <summary>The pre-action entry, now switched off (a service also with Start = Disabled).</summary>
    private static bool DisabledFrom(PersistenceEntry before, PersistenceEntry after) =>
        SameStored(before, after) && !after.Enabled && (after.Kind != PersistenceKind.Service || after.ServiceStart == ServiceStartType.Disabled);

    /// <summary>The first program of the value, and it is the Windows default.</summary>
    private bool IsWinlogonDefault(PersistenceEntry e) =>
        ProgramIndex(e.ValueName ?? string.Empty, e.Kind == PersistenceKind.WinlogonShell ? "Shell" : "Userinit") == 0
        && string.Equals(e.CommandLine.Trim(), WinlogonDefault(e.Kind).TrimEnd(','), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Section D review H1: collects the scope again and hands the ledger only what is exactly in the state the action produced
    /// (<paramref name="plan"/>): the entry's own key in that state, and (Winlogon, services, tasks) a neighbour that existed
    /// before, passes the plan's check, and that D4 judged in exactly its pre-action state. A key that is there in any other
    /// state (malware re-created its value right after the block, or changed it right after the restore) is not handed over:
    /// D4 judges it as usual, and the caller reports <see cref="RemediationStatus.EntryChanged"/>.
    /// </summary>
    /// <returns>False when the entry's own key isn't as the action left it.</returns>
    private bool HandOver(
        PersistenceScope scope, PersistenceScopedCollection? before, HandOverPlan plan, PersistenceKind kind, string? userSid, string location,
        IClientIdentity client, CancellationToken ct)
    {
        try
        {
            var was = new Dictionary<string, (PersistenceEntry Entry, string Fingerprint)>(StringComparer.Ordinal);
            if (plan.Neighbour is not null && before is not null)
            {
                foreach (var (key, entries) in PersistenceBaseline.Groups(before))
                {
                    if (entries.Count > 0 && Touched(entries[0], kind, userSid, location))
                    {
                        was[key] = (entries[0], PersistenceBaseline.Fingerprint(entries));
                    }
                }
            }

            var after = _collector.CollectScoped([scope], ct, CollectOptions(client, [scope], kind));
            var accepted = new Dictionary<string, LedgerAcceptance>(StringComparer.Ordinal);
            var state = AfterState.Absent;
            foreach (var (key, entries) in PersistenceBaseline.Groups(after))
            {
                if (entries.Count == 0)
                {
                    continue;
                }

                if (string.Equals(key, plan.EntryKey, StringComparison.Ordinal))
                {
                    state = entries.Count == 1 ? plan.Own(entries[0]) : AfterState.Unexpected;
                    if (state == AfterState.Expected)
                    {
                        accepted[key] = new LedgerAcceptance(PersistenceBaseline.Fingerprint(entries));
                    }
                }
                else if (plan.Neighbour is { } neighbour && was.TryGetValue(key, out var previous) && entries.Count == 1 && neighbour(previous.Entry, entries[0]))
                {
                    accepted[key] = new LedgerAcceptance(PersistenceBaseline.Fingerprint(entries), JudgedAs: previous.Fingerprint);
                }
            }

            if (state == AfterState.Absent && plan.Own(null) == AfterState.Unexpected)
            {
                state = AfterState.Unexpected; // a restored entry that is gone again right away
            }

            _ledger.Accept(accepted, scope);
            if (state == AfterState.Unexpected || plan.RejudgeAlways)
            {
                _ledger.Rejudge(plan.EntryKey, scope); // judged again even if it equals what D4 judged before
            }

            return state != AfterState.Unexpected;
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            _logger.LogWarning(ex, "Block & remove: the change was made, but the scope couldn't be collected again for real-time monitoring; it may alert once.");
            return true;
        }
    }

    /// <summary>
    /// Section D review M1: a standard user's collections, and those of user-writable places (a user's own scope, the Tasks
    /// folder), parse at Normal worker priority, behind the engine's own work.
    /// </summary>
    private static PersistenceCollectOptions CollectOptions(IClientIdentity client, IReadOnlyCollection<PersistenceScope> scopes, PersistenceKind kind) => new()
    {
        TimeBudget = CollectionBudget,
        ParsePriority = !client.IsAdmin || kind == PersistenceKind.ScheduledTask || scopes.Any(s => s.UserSid is not null) ? Sandbox.ScanPriority.Normal : null,
    };

    /// <summary>The kinds whose action changes more than the entry's own baseline key.</summary>
    private static bool HasNeighbours(PersistenceKind kind) =>
        kind is PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit or PersistenceKind.Service or PersistenceKind.ScheduledTask;

    /// <summary>The Event Log record of an action (3002 / 3003), against the requester's own alert budget.</summary>
    private void Record(AlertType type, PersistenceBackupRecord record, IClientIdentity client)
    {
        if (_alerts is null)
        {
            return;
        }

        try
        {
            var now = _time.GetUtcNow();
            string path = record.ValueName is null ? record.Location : record.Location + @"\" + record.ValueName;
            string what = type == AlertType.PersistenceBlocked
                ? $"Block & remove by {client.User.Value}: {Describe(record.Action)} (backup {record.Id})."
                : $"Restored by {client.User.Value} from backup {record.Id} ({Describe(record.Action)} undone).";
            var autostart = new AlertAutostart(record.Kind, record.Location, record.ValueName, record.UserSid, enabled: type == AlertType.PersistenceRestored);
            var alert = new Alert(Alert.ComputeAlertId(type, now, path + "\n" + record.Id, null, ScanTrigger.Persistence), now, type, Verdict.Suspicious, path,
                null, null, null, PersistenceKinds.TechniqueId(record.Kind), [], [what], null,
                type == AlertType.PersistenceBlocked ? AlertAction.Blocked : AlertAction.Restored, ScanTrigger.Persistence, EngineInfo.Version, autostart);
            _alerts.Post(alert, client.IsAdmin ? AlertBudget.ForEngine(ScanTrigger.Persistence) : AlertBudget.ForRequester(client.User));
        }
        catch (Exception ex) when (ex is ArgumentException)
        {
            _logger.LogError(ex, "Block & remove: the Event Log record for backup {Backup} couldn't be built.", record.Id);
        }
    }

    internal static string Describe(PersistenceBackupAction action) => action switch
    {
        PersistenceBackupAction.ValueDeleted => "the registry value was deleted",
        PersistenceBackupAction.ValueReset => "the Winlogon value was set back to the Windows default",
        PersistenceBackupAction.ServiceDisabled => "the service was disabled",
        PersistenceBackupAction.TaskDisabled => "the scheduled task was disabled",
        PersistenceBackupAction.FileQuarantined => "the Startup item was moved into the quarantine",
        _ => "changed",
    };

    /// <summary>Saves the record before the change; a failure means nothing is changed.</summary>
    private RemediationResult? SaveFirst(BlockContext context, PersistenceBackupRecord record)
    {
        try
        {
            context.Store.Save(record);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new(RemediationStatus.Failed, $"The backup couldn't be written ({ex.GetType().Name}), so nothing was changed.");
        }
    }

    /// <summary>The change failed after the record was written: the record goes again (nothing to restore).</summary>
    private void Discard(BlockContext context)
    {
        try
        {
            context.Store.Delete(context.BackupId);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Block & remove: the unused backup {Backup} couldn't be removed ({Why}).", context.BackupId, ex.Message);
        }
    }
}
