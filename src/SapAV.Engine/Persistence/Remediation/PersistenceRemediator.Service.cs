using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;

namespace SapAV.Engine.Persistence.Remediation;

internal sealed partial class PersistenceRemediator
{
    private const int ServiceDisabled = 4;
    private const string ServicesPrefix = @"HKLM\" + ServiceSource.ServicesKey + @"\";

    /// <summary>
    /// A service (ImagePath or ServiceDll entry): its start type is backed up, then set to Disabled through the Service Control
    /// Manager, and a running service is asked to stop. The service is never deleted, and nothing else of it changes.
    /// </summary>
    private RemediationResult BlockService(BlockContext context)
    {
        var entry = context.Entry;
        if (ServiceName(entry.Location) is not { } name)
        {
            return NotAddressable();
        }

        if (string.Equals(name, OwnServiceName, StringComparison.OrdinalIgnoreCase))
        {
            return new(RemediationStatus.NotSupported, "This is sap-AV's own service; it is never disabled by Block & remove.");
        }

        var queried = _services.Query(name, out var state);
        if (queried != ServiceControlStatus.Ok)
        {
            return queried == ServiceControlStatus.NotFound ? Changed() : new(RemediationStatus.Failed, $"The service can't be queried ({queried}).");
        }

        if (state!.StartType == ServiceDisabled)
        {
            return new(RemediationStatus.NothingToDo, "The service is already disabled.");
        }

        if (entry.ServiceStart is { } collected && collected != ServiceStartType.Unknown && (int)collected != state.StartType)
        {
            return Changed(); // its start type changed since it was collected
        }

        var record = context.NewRecord(PersistenceBackupAction.ServiceDisabled) with { ServiceName = name, OldStartType = state.StartType, WasRunning = state.Running };
        if (SaveFirst(context, record) is { } failed)
        {
            return failed;
        }

        var disabled = _services.SetStartType(name, ServiceDisabled);
        if (disabled != ServiceControlStatus.Ok)
        {
            Discard(context);
            return new(RemediationStatus.Failed, $"The service couldn't be disabled ({disabled}); nothing was changed.");
        }

        if (!state.Running)
        {
            return new(RemediationStatus.Blocked, "The service was disabled (it wasn't running). It was not deleted.", record);
        }

        var stopped = _services.Stop(name);
        string note = stopped == ServiceControlStatus.Ok
            ? "it was asked to stop"
            : $"it couldn't be stopped now ({stopped}), but it won't start again";
        record = record with { Notes = [$"The service was running; {note}."] };
        TrySave(context.Store, record);
        return new(RemediationStatus.Blocked, $"The service was disabled and {note}. It was not deleted.", record);
    }

    /// <summary>The old start type comes back only while the service is still Disabled (no one changed it since). It isn't started.</summary>
    private RemediationResult RestoreService(PersistenceBackupRecord record)
    {
        var queried = _services.Query(record.ServiceName!, out var state);
        if (queried != ServiceControlStatus.Ok)
        {
            return queried == ServiceControlStatus.NotFound
                ? new(RemediationStatus.LocationMissing, "The service doesn't exist any more.")
                : new(RemediationStatus.Failed, $"The service can't be queried ({queried}).");
        }

        if (state!.StartType != ServiceDisabled)
        {
            return new(RemediationStatus.LocationChanged, "The service's start type was changed since it was disabled; nothing was overwritten.");
        }

        var set = _services.SetStartType(record.ServiceName!, record.OldStartType!.Value);
        return set != ServiceControlStatus.Ok
            ? new(RemediationStatus.Failed, $"The service's start type couldn't be set back ({set}).")
            : new(RemediationStatus.Restored, record.WasRunning == true
                ? "The service's start type was set back. It was running before; it starts again at the next boot, or start it yourself."
                : "The service's start type was set back.");
    }

    /// <summary>The service name from <c>HKLM\SYSTEM\CurrentControlSet\Services\&lt;name&gt;[\Parameters]</c>; null if it can't be exact.</summary>
    internal static string? ServiceName(string location)
    {
        if (!location.StartsWith(ServicesPrefix, StringComparison.OrdinalIgnoreCase) || location.Contains('�'))
        {
            return null;
        }

        string rest = ServiceLocation(location)[ServicesPrefix.Length..];
        return rest.Length is > 0 and <= 256 && !rest.Contains('\\') && !rest.Contains('/') ? rest : null;
    }

    // ---- Scheduled tasks ----

    /// <summary>
    /// A scheduled task: its registered definition (the Task Scheduler's XML) is backed up and the task disabled through the
    /// Task Scheduler API (never deleted, its file never edited). A standard user may block it only if its registered principal is them.
    /// </summary>
    private RemediationResult BlockTask(BlockContext context)
    {
        var entry = context.Entry;
        string path = entry.Location;
        if (path.Contains('�') || !path.StartsWith('\\'))
        {
            return NotAddressable();
        }

        var got = _tasks.Get(path, out var state);
        if (got != TaskControlStatus.Ok)
        {
            return got == TaskControlStatus.NotFound
                ? new(RemediationStatus.LocationMissing, "The Task Scheduler has no task at this path (the file in the Tasks folder isn't a registered task).")
                : new(RemediationStatus.Failed, $"The task can't be read from the Task Scheduler ({got}).");
        }

        if (!context.Client.IsAdmin && !PrincipalIs(state!, context.Client.User))
        {
            return new(RemediationStatus.AccessDenied, "This task doesn't run as you; only an administrator may block it.");
        }

        if (!state!.Enabled)
        {
            return new(RemediationStatus.NothingToDo, "The task is already disabled.");
        }

        bool keepXml = state.Xml.Length <= ComTaskSchedulerControl.MaxXmlLength;
        var record = context.NewRecord(PersistenceBackupAction.TaskDisabled) with
        {
            TaskPath = path, TaskXml = keepXml ? state.Xml : null, DisabledXmlSha256 = Sha256(state.Xml),
            Notes = keepXml ? [] : ["The task's definition was too large to keep a copy; it can still be re-enabled."],
        };
        if (SaveFirst(context, record) is { } failed)
        {
            return failed;
        }

        var set = _tasks.SetEnabled(path, false);
        if (set != TaskControlStatus.Ok)
        {
            Discard(context);
            return new(RemediationStatus.Failed, $"The task couldn't be disabled ({set}); nothing was changed.");
        }

        // Restore re-enables only the exact definition left here (the Task Scheduler rewrites it when disabling).
        if (_tasks.Get(path, out var after) == TaskControlStatus.Ok)
        {
            record = record with { DisabledXmlSha256 = Sha256(after!.Xml) };
            TrySave(context.Store, record);
        }

        return new(RemediationStatus.Blocked, "The scheduled task was backed up and disabled. It was not deleted.", record);
    }

    /// <summary>Re-enables the task only if its definition is still exactly what disabling left; otherwise nothing is changed.</summary>
    private RemediationResult RestoreTask(PersistenceBackupRecord record)
    {
        var got = _tasks.Get(record.TaskPath!, out var state);
        if (got != TaskControlStatus.Ok)
        {
            return got == TaskControlStatus.NotFound
                ? new(RemediationStatus.LocationMissing, "The task doesn't exist any more.")
                : new(RemediationStatus.Failed, $"The task can't be read from the Task Scheduler ({got}).");
        }

        if (!string.Equals(Sha256(state!.Xml), record.DisabledXmlSha256, StringComparison.Ordinal))
        {
            return new(RemediationStatus.LocationChanged, "The task was changed since it was disabled; nothing was overwritten.");
        }

        var set = _tasks.SetEnabled(record.TaskPath!, true);
        return set == TaskControlStatus.Ok
            ? new(RemediationStatus.Restored, "The scheduled task was enabled again.")
            : new(RemediationStatus.Failed, $"The task couldn't be enabled ({set}).");
    }

    /// <summary>The task's registered principal is <paramref name="user"/> (a SID, or an account name that resolves to it); a group never is.</summary>
    internal static bool PrincipalIs(ScheduledTaskState state, SecurityIdentifier user)
    {
        if (state.PrincipalUserId is not { } id)
        {
            return false;
        }

        try
        {
            var sid = PersistenceEntry.IsSid(id) ? new SecurityIdentifier(id) : (SecurityIdentifier)new NTAccount(id).Translate(typeof(SecurityIdentifier));
            return sid == user;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or ArgumentException or SystemException)
        {
            return false;
        }
    }

    private static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>A later update of a record already written (a note, the final hash); a failure keeps the first version.</summary>
    private void TrySave(IPersistenceBackupStore store, PersistenceBackupRecord record)
    {
        try
        {
            store.Save(record);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Block & remove: backup {Backup} couldn't be updated ({Why}).", record.Id, ex.Message);
        }
    }
}
