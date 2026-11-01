using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.Core.Tests.Persistence;

/// <summary>Review C H2: what the engine accepts from the worker's shortcut and task parsers (untrusted input).</summary>
public class WireParsedFileCodecTests
{
    private static WireParsedFile Task(params WireTaskAction[] actions) => new()
    {
        Kind = WorkerParseKind.ScheduledTask,
        Error = null,
        Task = new WireTaskDefinition { Enabled = true, UserId = null, Truncated = false, Actions = actions },
        Link = null,
    };

    private static WireTaskAction Exec(string? command = "a.exe") =>
        new() { Command = command, Arguments = null, WorkingDirectory = null, ComClassId = null, ComData = null };

    [Fact]
    public void AValidAnswer_SurvivesStrictJson_AndIsRebuilt()
    {
        var wire = WireParsedFileCodec.ParseInWorker(WorkerParseKind.ScheduledTask,
            TaskXmlTests.Utf16(TaskXmlTests.Task("<Exec><Command>a.exe</Command><WorkingDirectory>C:\\w</WorkingDirectory></Exec>")));

        var parsed = WireParsedFileCodec.FromWire(
            WorkerJson.Deserialize<WireParsedFile>(WorkerJson.Serialize(wire, WorkerLimits.MaxResponseBytes)), WorkerParseKind.ScheduledTask);

        Assert.Null(parsed.Error);
        var action = Assert.Single(parsed.Task!.Actions);
        Assert.Equal("a.exe", action.Command);
        Assert.Equal(@"C:\w", action.WorkingDirectory);
    }

    [Fact]
    public void MalformedInput_IsAnError_NotAnException()
    {
        var wire = WireParsedFileCodec.ParseInWorker(WorkerParseKind.ShellLink, new byte[8]);

        var parsed = WireParsedFileCodec.FromWire(wire, WorkerParseKind.ShellLink);

        Assert.NotNull(parsed.Error);
        Assert.Null(parsed.Link);
    }

    [Fact]
    public void TheLargestAnswer_FitsTheResponseCap_EvenFullyEscaped()
    {
        string escaped = new('\u00e9', WireParsedFileCodec.MaxTotalCharacters / 8);
        var wire = new WireParsedFile
        {
            Kind = WorkerParseKind.ShellLink,
            Error = null,
            Task = null,
            Link = new WireShellLink
            {
                IdListPath = escaped, IdListUnsupported = false, LinkInfoPath = escaped, LinkInfoNetworkShare = escaped,
                EnvironmentTarget = escaped, RelativePath = escaped, WorkingDirectory = escaped, Arguments = escaped, Truncated = false,
            },
        };

        Assert.InRange(WorkerJson.Serialize(wire, WorkerLimits.MaxResponseBytes).Length, 1, WorkerLimits.MaxResponseBytes);
    }

    [Fact]
    public void BrokenAnswers_AreProtocolViolations()
    {
        WireParsedFile[] broken =
        [
            Task() with { Kind = WorkerParseKind.ShellLink }, // the wrong kind for the request
            Task() with { Error = "and an error" }, // two bodies
            Task() with { Task = null }, // no body
            Task() with { Task = null, Error = new string('x', WorkerLimits.MaxTextLength + 1) },
            Task(Enumerable.Repeat(Exec(), TaskXml.MaxActions + 1).ToArray()),
            Task(Exec(new string('x', WireParsedFileCodec.MaxTotalCharacters + 1))),
            Task(Enumerable.Repeat(Exec(new string('x', 10_000)), 4).ToArray()), // each fits, the sum doesn't
            Task(Exec() with { ComClassId = Guid.NewGuid() }), // both Exec and COM
            Task(Exec() with { ComData = "data" }),
        ];

        foreach (var wire in broken)
        {
            Assert.Throws<WorkerProtocolException>(() => WireParsedFileCodec.FromWire(wire, WorkerParseKind.ScheduledTask));
        }
    }

    [Fact]
    public void AShortcutUnderTheCap_IsCarriedWhole()
    {
        var builder = new TestSupport.ShellLinkBuilder { IdListPath = @"C:\Tools\a.exe", Arguments = new string('x', 8000) };

        var wire = WireParsedFileCodec.ParseInWorker(WorkerParseKind.ShellLink, builder.Build());

        Assert.False(wire.Link!.Truncated); // under the cap: nothing cut
        Assert.Equal(8000, wire.Link.Arguments!.Length);
    }
}
