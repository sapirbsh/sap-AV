using System.Text;
using SapAV.Core.Persistence;

namespace SapAV.Core.Tests.Persistence;

/// <summary>The hardened task definition reader (ROADMAP C2).</summary>
public class TaskXmlTests
{
    private const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    internal static byte[] Utf16(string xml) => [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(xml)];

    internal static string Task(string actions, bool enabled = true, string userId = "S-1-5-18") => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="{Ns}">
          <Principals><Principal id="Author"><UserId>{userId}</UserId></Principal></Principals>
          <Settings><Enabled>{(enabled ? "true" : "false")}</Enabled></Settings>
          <Actions Context="Author">{actions}</Actions>
        </Task>
        """;

    [Fact]
    public void ExecAndComHandlerActions_AreRead()
    {
        var xml = Task("""
            <Exec><Command>%windir%\system32\cleanmgr.exe</Command><Arguments>/autoclean /d %systemdrive%</Arguments></Exec>
            <ComHandler><ClassId>{12345678-1234-1234-1234-1234567890AB}</ClassId><Data><![CDATA[payload]]></Data></ComHandler>
            """);

        var task = TaskXml.Parse(Utf16(xml), out var error);

        Assert.Null(error);
        Assert.True(task!.Enabled);
        Assert.Equal("S-1-5-18", task.UserId);
        Assert.Equal(2, task.Actions.Count);
        Assert.Equal(@"%windir%\system32\cleanmgr.exe", task.Actions[0].Command);
        Assert.Equal("/autoclean /d %systemdrive%", task.Actions[0].Arguments);
        Assert.Equal(new Guid("12345678-1234-1234-1234-1234567890AB"), task.Actions[1].ComClassId);
        Assert.Equal("payload", task.Actions[1].ComData);
    }

    [Fact]
    public void DisabledTask_AndUtf8WithoutNamespace_Parse()
    {
        var disabled = TaskXml.Parse(Utf16(Task("<Exec><Command>a.exe</Command></Exec>", enabled: false)), out _);
        var plain = TaskXml.Parse("<Task><Actions><Exec><Command>b.exe</Command></Exec></Actions></Task>"u8.ToArray(), out _);

        Assert.False(disabled!.Enabled);
        Assert.Equal("b.exe", Assert.Single(plain!.Actions).Command);
    }

    [Theory]
    [InlineData("""<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><Task><Actions><Exec><Command>&xxe;</Command></Exec></Actions></Task>""")]
    [InlineData("""<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">]><Task><Actions><Exec><Command>&c;</Command></Exec></Actions></Task>""")]
    public void Dtds_AreRefused_NoEntityIsExpanded(string xml)
    {
        Assert.Null(TaskXml.Parse(Encoding.UTF8.GetBytes(xml), out var error));
        Assert.Contains("DTD", error);
    }

    [Fact]
    public void DeepNesting_IsRejected_WithoutBuildingATree()
    {
        // Review C H2: 140,000 levels fit under the 1 MiB cap and overflowed XElement.Value. Rejected at the depth cap, even
        // on a small stack: this isn't a recursive parse.
        string xml = "<Task>" + string.Concat(Enumerable.Repeat("<a>", 140_000)) + string.Concat(Enumerable.Repeat("</a>", 140_000)) + "</Task>";
        TaskDefinitionInfo? task = new(true, null, []);
        string? error = null;
        var thread = new Thread(() => task = TaskXml.Parse(Encoding.UTF8.GetBytes(xml), out error), maxStackSize: 256 * 1024);

        thread.Start();
        thread.Join();

        Assert.Null(task);
        Assert.Contains("nested", error);
    }

    [Fact]
    public void AtTheDepthCap_TheDocumentStillParses_AndOnlyTheFirstOfEachSectionCounts()
    {
        string padding = string.Concat(Enumerable.Repeat("<a>", TaskXml.MaxDepth - 2)) + string.Concat(Enumerable.Repeat("</a>", TaskXml.MaxDepth - 2));
        string xml = $"""
            <Task>
              <x>{padding}</x>
              <Settings><Enabled> false </Enabled><Enabled>true</Enabled></Settings>
              <Principals><Principal><UserId>first</UserId></Principal><Principal><UserId>second</UserId></Principal></Principals>
              <Actions><Exec><Command>a.exe</Command><Command>ignored.exe</Command></Exec></Actions>
              <Actions><Exec><Command>second-section.exe</Command></Exec></Actions>
            </Task>
            """;

        var task = TaskXml.Parse(Encoding.UTF8.GetBytes(xml), out var error);

        Assert.Null(error);
        Assert.False(task!.Enabled);
        Assert.Equal("first", task.UserId);
        Assert.Equal("a.exe", Assert.Single(task.Actions).Command);
    }

    [Fact]
    public void TooManyActionsOrTooMuchText_SetTruncated()
    {
        string many = string.Concat(Enumerable.Repeat("<Exec><Command>a.exe</Command></Exec>", TaskXml.MaxActions + 1));
        string long1 = $"<Exec><Command>a.exe</Command><Arguments>{new string('x', TaskXml.MaxTotalCharacters + 1)}</Arguments></Exec>";

        var capped = TaskXml.Parse(Utf16(Task(many)), out _)!;
        var cut = TaskXml.Parse(Utf16(Task(long1)), out _)!;

        Assert.Equal(TaskXml.MaxActions, capped.Actions.Count);
        Assert.True(capped.Truncated);
        Assert.True(cut.Truncated);
        Assert.True(cut.Actions[0].Arguments!.Length < TaskXml.MaxTotalCharacters);
    }

    [Fact]
    public void MalformedWrongRootAndOversized_AreRejectedWithAReason()
    {
        Assert.Null(TaskXml.Parse("<Task><Actions><Exec>"u8.ToArray(), out var broken));
        Assert.Null(TaskXml.Parse("<NotATask/>"u8.ToArray(), out var wrongRoot));
        Assert.Null(TaskXml.Parse(new byte[TaskXml.MaxBytes + 1], out var tooBig));
        Assert.NotNull(broken);
        Assert.NotNull(wrongRoot);
        Assert.NotNull(tooBig);
    }
}
