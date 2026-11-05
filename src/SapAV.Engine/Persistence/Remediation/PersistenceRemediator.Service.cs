using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;

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

        if (!context.ConfirmCritical && CriticalReason(name, state) is { } critical)
        {
            return new(RemediationStatus.NeedsConfirmation,
                $"{critical} Disabling it can stop Windows from starting or working; confirm explicitly (ConfirmCritical) if you are sure.");
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

    /// <summary>Review M3: core Windows services that are never disabled without an explicit confirmation.</summary>
    internal static readonly HashSet<string> CoreServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "SamSs", "EventLog", "Winmgmt", "CryptSvc", "BFE", "mpssvc", "Schedule", "ProfSvc",
        "gpsvc", "Power", "BrokerInfrastructure", "CoreMessagingRegistrar", "SystemEventsBroker", "Dhcp", "Dnscache", "nsi", "LanmanWorkstation",
        "WinDefend", "WdNisSvc", "WdNisDrv", "WdFilter", "WdBoot", "SecurityHealthService", "Sense", "MDCoreSvc",
    };

    private const int ErrorControlCritical = 3;

    /// <summary>
    /// Review M3: why disabling this service could break Windows (a boot or system-start driver, an ErrorControl of Critical,
    /// a core service), or null.
    /// </summary>
    internal static string? CriticalReason(string name, ServiceState state) =>
        state.StartType is 0 or 1 ? "This is a boot or system-start driver."
        : state.ErrorControl == ErrorControlCritical ? "Windows treats a failure of this service as critical."
        : CoreServices.Contains(name) ? "This is a core Windows service."
        : null;

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

    /// <summary>FILE_WRITE_DATA: what changing a task needs in its security descriptor (task descriptors use file rights).</summary>
    private const uint TaskWriteAccess = 0x0002;

    /// <summary>
    /// A scheduled task: its registered definition (the Task Scheduler's XML) is backed up and the task disabled through the
    /// Task Scheduler API (never deleted, its file never edited). A standard user may block it only if the registered task's
    /// own security descriptor lets them change it (review M1): who it runs as is not authorization.
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

        if (ClientMayChangeTask(context.Client, state!) is { } denied)
        {
            return denied;
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

        // Restore re-enables only the exact definition left here (the Task Scheduler rewrites it when disabling). Review L2: if
        // this second save fails twice, restore still accepts a definition that differs from the backed-up one only in its
        // Settings Enabled flag.
        if (_tasks.Get(path, out var after) == TaskControlStatus.Ok)
        {
            record = record with { DisabledXmlSha256 = Sha256(after!.Xml) };
            TrySave(context.Store, record);
        }

        return new(RemediationStatus.Blocked, "The scheduled task was backed up and disabled. It was not deleted.", record);
    }

    /// <summary>
    /// Re-enables the task only if it is still disabled with the definition disabling left (or, review L2, the backed-up
    /// definition with only its Enabled flag changed); otherwise nothing is changed. Review M1: the same descriptor check as Block.
    /// </summary>
    private RemediationResult RestoreTask(PersistenceBackupRecord record, IClientIdentity client)
    {
        var got = _tasks.Get(record.TaskPath!, out var state);
        if (got != TaskControlStatus.Ok)
        {
            return got == TaskControlStatus.NotFound
                ? new(RemediationStatus.LocationMissing, "The task doesn't exist any more.")
                : new(RemediationStatus.Failed, $"The task can't be read from the Task Scheduler ({got}).");
        }

        if (ClientMayChangeTask(client, state!) is { } denied)
        {
            return denied;
        }

        bool unchanged = string.Equals(Sha256(state!.Xml), record.DisabledXmlSha256, StringComparison.Ordinal)
            || (!state.Enabled && record.TaskXml is { } original
                && string.Equals(WithoutSettingsEnabled(state.Xml), WithoutSettingsEnabled(original), StringComparison.Ordinal));
        if (!unchanged)
        {
            return new(RemediationStatus.LocationChanged, "The task was changed since it was disabled; nothing was overwritten.");
        }

        var set = _tasks.SetEnabled(record.TaskPath!, true);
        return set == TaskControlStatus.Ok
            ? new(RemediationStatus.Restored, "The scheduled task was enabled again.")
            : new(RemediationStatus.Failed, $"The task couldn't be enabled ({set}).");
    }

    /// <summary>
    /// Review M1: a standard user may change a task only if the registered task's own descriptor grants them write access
    /// (AccessCheck with their token, file generic mapping); an unreadable descriptor denies. Administrators may change any task.
    /// </summary>
    private static RemediationResult? ClientMayChangeTask(IClientIdentity client, ScheduledTaskState state) =>
        client.IsAdmin || ClientAccess.IsGrantedByStoredDescriptor(client, state.SecurityDescriptor, TaskWriteAccess)
            ? null
            : new(RemediationStatus.AccessDenied, "You may not change this task yourself; only an administrator may block or restore it.");

    /// <summary>
    /// The definition without the Settings-level <c>&lt;Enabled&gt;</c> element (the only thing disabling changes; triggers keep
    /// theirs), for the review L2 comparison.
    /// </summary>
    internal static string WithoutSettingsEnabled(string xml)
    {
        int start = xml.IndexOf("<Settings>", StringComparison.Ordinal);
        int end = start < 0 ? -1 : xml.IndexOf("</Settings>", start, StringComparison.Ordinal);
        if (end < 0)
        {
            return xml;
        }

        string settings = SettingsEnabledRegex().Replace(xml[start..end], string.Empty);
        return string.Concat(xml.AsSpan(0, start), settings, xml.AsSpan(end));
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\s*<Enabled>\s*(true|false)\s*</Enabled>", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex SettingsEnabledRegex();

    private static string Sha256(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>A later update of a record already written (a note, the final hash), tried twice (review L2); a failure keeps the first version.</summary>
    private void TrySave(IPersistenceBackupStore store, PersistenceBackupRecord record)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                store.Save(record);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (attempt >= 2)
                {
                    _logger.LogWarning("Block & remove: backup {Backup} couldn't be updated ({Why}).", record.Id, ex.Message);
                    return;
                }
            }
        }
    }
}
