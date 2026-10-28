using System.Text;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>Scheduled task collection (ROADMAP C2) from a temp "Tasks" tree; COM classes in a throwaway HKCU key.</summary>
public sealed class ScheduledTaskCollectorTests : IDisposable
{
    private const string Sid = RegistryTestRoot.UserSid;
    private const string Clsid = "{0F0E0D0C-0B0A-0908-0706-050403020100}";
    private readonly RegistryTestRoot _root = new();
    private readonly TempDir _tasks = new();
    private readonly SetProbe _probe = new(@"C:\Windows\System32\rundll32.exe", @"C:\Windows\System32\shell32.dll");

    public void Dispose()
    {
        _root.Dispose();
        _tasks.Dispose();
    }

    private static string Task(string actions, bool enabled = true, string userId = "S-1-5-18") => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Principals><Principal id="Author"><UserId>{userId}</UserId></Principal></Principals>
          <Settings><Enabled>{(enabled ? "true" : "false")}</Enabled></Settings>
          <Actions Context="Author">{actions}</Actions>
        </Task>
        """;

    private void Write(string relative, string xml)
    {
        var path = Path.Combine(_tasks.Path, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(xml)]);
    }

    private PersistenceCollection Collect() => _root.Collect(_probe, new ScheduledTaskSource(_tasks.Path));

    [Fact]
    public void ExecActions_InNestedFolders_AreResolved()
    {
        Write(@"Vendor\Updates\Daily", Task("""
            <Exec><Command>"C:\Program Files\Vendor\upd.exe"</Command><Arguments>/silent</Arguments></Exec>
            <Exec><Command>%windir%\system32\rundll32.exe</Command><Arguments>shell32.dll,Control_RunDLL</Arguments></Exec>
            """, enabled: false));

        var result = Collect();

        var first = result.Single("Exec[0]");
        Assert.Equal(PersistenceKind.ScheduledTask, first.Kind);
        Assert.Equal(@"\Vendor\Updates\Daily", first.Location);
        Assert.Equal(@"C:\Program Files\Vendor\upd.exe", first.Resolution.TargetPath);
        Assert.Equal("/silent", first.Resolution.Arguments);
        Assert.False(first.Enabled);
        Assert.Equal("T1053.005", first.TechniqueId);
        Assert.Equal(@"C:\Windows\System32\shell32.dll", result.Single("Exec[1]").Resolution.TargetPath);
    }

    [Fact]
    public void ComHandler_IsResolvedThroughInprocServer32_WithTaskhostAsHost()
    {
        _root.Machine($@"SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32").SetValue("", @"%SystemRoot%\System32\handler.dll", Microsoft.Win32.RegistryValueKind.ExpandString);
        Write("Com", Task($"<ComHandler><ClassId>{Clsid}</ClassId></ComHandler>"));
        Write("Unregistered", Task("<ComHandler><ClassId>{11111111-2222-3333-4444-555555555555}</ClassId></ComHandler>"));

        var entries = Collect().Entries.ToDictionary(e => e.Location);

        var com = entries[@"\Com"];
        Assert.Equal(new Guid(Clsid), com.ComClassId);
        Assert.Equal(@"C:\Windows\System32\handler.dll", com.Resolution.TargetPath);
        Assert.Equal(@"C:\Windows\System32\taskhostw.exe", com.Resolution.HostPath);
        Assert.Equal(TargetUnresolvedReason.ComClassNotRegistered, entries[@"\Unregistered"].Resolution.UnresolvedReason);
    }

    [Fact]
    public void UserTask_UsesTheUsersEnvironment_AndTheirClassesOverride()
    {
        _root.AddUser(Sid, @"C:\Users\alice", loaded: true);
        _root.Machine($@"SOFTWARE\Classes\CLSID\{Clsid}\InprocServer32").SetValue("", @"C:\Windows\System32\handler.dll");
        _root.Users($@"{Sid}_Classes\CLSID\{Clsid}\InprocServer32").SetValue("", @"C:\Users\alice\AppData\Roaming\hijack.dll");
        Write("UserTask", Task($"""
            <Exec><Command>%APPDATA%\tool.exe</Command></Exec>
            <ComHandler><ClassId>{Clsid}</ClassId></ComHandler>
            """, userId: Sid));

        var result = Collect();

        var exec = result.Single("Exec[0]");
        Assert.Equal(Sid, exec.UserSid);
        Assert.Equal(@"C:\Users\alice\AppData\Roaming\tool.exe", exec.Resolution.TargetPath);
        var com = result.Single("ComHandler[1]");
        Assert.Equal(@"C:\Users\alice\AppData\Roaming\hijack.dll", com.Resolution.TargetPath);
        Assert.Contains(ResolutionFlag.UserComOverride, com.Resolution.Flags);
    }

    [Fact]
    public void MalformedAndXxeTasks_BecomeIssues_AndTheRestIsCollected()
    {
        Write("Good", Task("<Exec><Command>C:\\Tools\\ok.exe</Command></Exec>"));
        Write("Broken", "<Task><Actions><Exec>");
        Write("Xxe", """<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><Task><Actions><Exec><Command>&x;</Command></Exec></Actions></Task>""");

        var result = Collect();

        Assert.Equal(@"C:\Tools\ok.exe", Assert.Single(result.Entries).Resolution.TargetPath);
        Assert.Contains(result.Issues, i => i.Location == @"\Broken" && i.Reason == PersistenceIssueReason.Malformed);
        var xxe = Assert.Single(result.Issues, i => i.Location == @"\Xxe");
        Assert.Equal(PersistenceIssueReason.Malformed, xxe.Reason);
        Assert.Contains("DTD", xxe.Message);
    }

    [Fact]
    public void OversizedTaskFile_IsSkippedWithAnIssue()
    {
        File.WriteAllBytes(Path.Combine(_tasks.Path, "Huge"), new byte[TaskXml.MaxBytes + 1]);

        var result = Collect();

        Assert.Empty(result.Entries);
        Assert.Contains(result.Issues, i => i.Location == @"\Huge" && i.Reason == PersistenceIssueReason.TooLarge);
    }

    [RequiresFact(Requires.Junctions)]
    public void AJunctionInTheTasksFolder_IsNotFollowed()
    {
        var outside = new TempDir();
        try
        {
            File.WriteAllBytes(Path.Combine(outside.Path, "Planted"), Encoding.UTF8.GetBytes(Task("<Exec><Command>C:\\x.exe</Command></Exec>")));
            var link = Directory.CreateDirectory(Path.Combine(_tasks.Path, "Link")).FullName;
            Assert.Null(RawJunction.TryCreate(link, @"\??\" + outside.Path));

            var result = Collect();

            Assert.Empty(result.Entries);
            Assert.Contains(result.Issues, i => i.Location == @"\Link" && i.Reason == PersistenceIssueReason.LinkNotFollowed);
        }
        finally
        {
            Directory.Delete(Path.Combine(_tasks.Path, "Link"));
            outside.Dispose();
        }
    }
}
