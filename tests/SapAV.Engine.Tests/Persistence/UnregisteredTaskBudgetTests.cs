using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using SapAV.Engine.Alerts;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section D review H3: a task file the system didn't write (not trusted-owned, not in TaskCache) names its own principal, so
/// judging it is charged to the file owner, never to the principal it names and never to the engine's own budget.
/// </summary>
public sealed class UnregisteredTaskBudgetTests : IDisposable
{
    private readonly MonitorHarness _m = new(trustedTask: (_, _) => false);

    public void Dispose() => _m.Dispose();

    private string WriteTask(string name, string? userId)
    {
        string principal = userId is null ? "<GroupId>S-1-5-32-545</GroupId>" : $"<UserId>{userId}</UserId>";
        string xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Principals><Principal id="Author">{principal}</Principal></Principals>
              <Settings><Enabled>true</Enabled></Settings>
              <Actions Context="Author"><Exec><Command>"{_m.Target("malware-" + name + ".exe")}"</Command></Exec></Actions>
            </Task>
            """;
        string path = Path.Combine(_m.Tasks, name);
        File.WriteAllBytes(path, [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(xml)]);
        return path;
    }

    private static string OwnerOf(string path) => new FileInfo(path).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))!.Value;

    private AlertBudget? BudgetOf(string taskName) =>
        Assert.Single(_m.Alerts.Posts, p => p.Alert.Autostart?.Location == @"\" + taskName).Budget;

    [Fact]
    public void AStrayTaskNamingAnotherUser_IsChargedToTheFileOwner()
    {
        string file = WriteTask("ClaimsBob", MonitorHarness.Bob);

        _m.Baseline();

        string owner = OwnerOf(file); // whoever this run's files belong to (the user, or Administrators when elevated)
        Assert.Equal($"engine:Persistence:{owner}", BudgetOf("ClaimsBob")!.Key);
        Assert.DoesNotContain(MonitorHarness.Bob, BudgetOf("ClaimsBob")!.Key, StringComparison.Ordinal);
    }

    [Fact]
    public void AReusedUnchangedStrayTask_AfterTheTrustMapStartedOver_KeepsItsFileOwnersBudget()
    {
        // Follow-up M3: with a "nothing changed" hint the kept parse result is reused only while the file's trust is known;
        // otherwise it is opened again, so it never falls back to the principal it names.
        string file = WriteTask("ClaimsBob", MonitorHarness.Bob);
        var source = new Engine.Persistence.ScheduledTaskSource(_m.Tasks, (_, _) => false);
        var collector = new Engine.Persistence.PersistenceCollector(_m.Registry.View, new Engine.Persistence.SafePathProbe(), [source],
            parser: WireTestParser.Instance, parsedFiles: new Engine.Persistence.ParsedFileCache());
        collector.Collect();
        source.ForgetTrust();

        var again = collector.Collect(options: new Engine.Persistence.PersistenceCollectOptions { ChangedTaskFiles = new HashSet<string>() });

        Assert.Equal(OwnerOf(file), Assert.Single(again.Entries).BudgetOwner);
    }

    [Fact]
    public void AStrayTaskWithNoUser_DoesntTouchTheEnginesBudget()
    {
        string file = WriteTask("NoUser", userId: null);

        _m.Baseline();

        Assert.NotEqual(AlertBudget.ForEngine(Core.Models.ScanTrigger.Persistence).Key, BudgetOf("NoUser")!.Key);
        Assert.Equal($"engine:Persistence:{OwnerOf(file)}", BudgetOf("NoUser")!.Key);
    }
}
