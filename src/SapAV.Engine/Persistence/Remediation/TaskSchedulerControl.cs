using System.Runtime.InteropServices;

namespace SapAV.Engine.Persistence.Remediation;

/// <summary>A registered scheduled task as the Task Scheduler reports it.</summary>
/// <param name="Xml">The task's definition (the Task Scheduler's own XML, not the file in System32\Tasks).</param>
/// <param name="PrincipalUserId">The principal's UserId as registered (a SID or an account name), or null.</param>
/// <param name="PrincipalGroupId">The principal's GroupId, or null.</param>
internal sealed record ScheduledTaskState(bool Enabled, string Xml, string? PrincipalUserId, string? PrincipalGroupId);

internal enum TaskControlStatus
{
    Ok,

    /// <summary>The Task Scheduler has no task at that path (a stray file in the Tasks folder isn't a registered task).</summary>
    NotFound,

    AccessDenied,
    Failed,
}

/// <summary>
/// D5: what Block &amp; remove does to a scheduled task, through the Task Scheduler API (never by editing the task file, never
/// deleting a task). Fake it in tests: normal tests never change a real task.
/// </summary>
internal interface ITaskSchedulerControl
{
    /// <param name="taskPath">The task's full path, <c>\Folder\Name</c>.</param>
    TaskControlStatus Get(string taskPath, out ScheduledTaskState? state);

    TaskControlStatus SetEnabled(string taskPath, bool enabled);
}

/// <summary>The real Task Scheduler 2.0 (<c>Schedule.Service</c> through COM automation), connected to the local machine.</summary>
internal sealed class ComTaskSchedulerControl : ITaskSchedulerControl
{
    /// <summary>Most characters of a task definition kept in a backup.</summary>
    public const int MaxXmlLength = 512 * 1024;

    public static ComTaskSchedulerControl Instance { get; } = new();

    public TaskControlStatus Get(string taskPath, out ScheduledTaskState? state)
    {
        ScheduledTaskState? found = null;
        var status = WithTask(taskPath, task =>
        {
            string xml = (string)task.Xml;
            dynamic definition = task.Definition;
            dynamic principal = definition.Principal;
            try
            {
                found = new ScheduledTaskState((bool)task.Enabled, xml, Blank((string?)principal.UserId), Blank((string?)principal.GroupId));
            }
            finally
            {
                Release(principal);
                Release(definition);
            }
        });
        state = found;
        return status;
    }

    public TaskControlStatus SetEnabled(string taskPath, bool enabled) => WithTask(taskPath, task => task.Enabled = enabled);

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static TaskControlStatus WithTask(string taskPath, Action<dynamic> body)
    {
        if (string.IsNullOrEmpty(taskPath) || taskPath[0] != '\\' || taskPath.Contains('\0'))
        {
            return TaskControlStatus.NotFound;
        }

        dynamic? service = null, root = null, task = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
            service = Activator.CreateInstance(type)!;
            service.Connect();
            root = service.GetFolder(@"\");
            task = root.GetTask(taskPath);
            body(task);
            return TaskControlStatus.Ok;
        }
        catch (COMException ex)
        {
            return (uint)ex.HResult switch
            {
                0x80070002 or 0x80070003 => TaskControlStatus.NotFound,
                0x80070005 => TaskControlStatus.AccessDenied,
                _ => TaskControlStatus.Failed,
            };
        }
        catch (UnauthorizedAccessException)
        {
            return TaskControlStatus.AccessDenied;
        }
        catch (FileNotFoundException)
        {
            return TaskControlStatus.NotFound;
        }
        catch (Exception ex) when (ex is Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException or ArgumentException or InvalidOperationException)
        {
            return TaskControlStatus.Failed;
        }
        finally
        {
            Release(task);
            Release(root);
            Release(service);
        }
    }

    private static void Release(object? com)
    {
        if (com is not null && Marshal.IsComObject(com))
        {
            Marshal.FinalReleaseComObject(com);
        }
    }
}
