using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// Section C review H2: shortcuts and task definitions are parsed only in the scan worker. These go through the real broker
/// and the real worker exe (test-only unsandboxed isolation: same pipes, Job Object and protocol, so they run on every machine).
/// </summary>
public sealed class PersistenceParsingInWorkerTests : IDisposable
{
    private readonly RegistryTestRoot _root = new();
    private readonly TempDir _folder = new();
    private readonly SetProbe _probe = new();
    private readonly List<SandboxedScanBroker> _brokers = [];

    public void Dispose()
    {
        foreach (var broker in _brokers)
        {
            broker.Dispose();
        }

        _root.Dispose();
        _folder.Dispose();
    }

    private SandboxedScanBroker Broker(Func<string, WorkerTestFault>? faults = null, int maxFailures = 2, TimeSpan? parseTimeout = null)
    {
        var broker = new SandboxedScanBroker(new SandboxOptions
        {
            WorkerPath = TestAppContainer.WorkerExe,
            WorkerCount = 1,
            EnableWorkerTestHooks = true,
            Isolation = WorkerIsolation.UnsandboxedForTests,
            RequestTimeout = TimeSpan.FromSeconds(30),
            ParseTimeout = parseTimeout ?? TimeSpan.FromSeconds(5),
            RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
            RestartBackoffMax = TimeSpan.FromMilliseconds(100),
            MaxFailuresPerFile = maxFailures,
        }, new FakeRulesSource(), NullLogger.Instance) { ParseFaultInjector = faults };
        _brokers.Add(broker);
        return broker;
    }

    private PersistenceCollection Collect(IPersistenceFileParser parser, params IPersistenceSource[] sources) =>
        new PersistenceCollector(_root.View, _probe, sources, parser: parser).Collect();

    private void WriteTask(string name, string xml) => File.WriteAllBytes(Path.Combine(_folder.Path, name), Encoding.UTF8.GetBytes(xml));

    private const string GoodTask = """
        <Task><Principals><Principal><UserId>S-1-5-18</UserId></Principal></Principals>
        <Actions><Exec><Command>C:\Tools\ok.exe</Command><Arguments>/x</Arguments></Exec></Actions></Task>
        """;

    private static string Deep(int levels) =>
        "<Task>" + string.Concat(Enumerable.Repeat("<a>", levels)) + string.Concat(Enumerable.Repeat("</a>", levels)) + "</Task>";

    [Fact]
    public void ATaskAndAShortcut_AreParsedThroughTheWorker()
    {
        WriteTask("Daily", GoodTask);
        File.WriteAllBytes(Path.Combine(_folder.Path, "app.lnk"), new ShellLinkBuilder { IdListPath = @"C:\Tools\app.exe", Arguments = "/bg" }.Build());
        var broker = Broker();

        var result = Collect(broker, new ScheduledTaskSource(_folder.Path), new StartupFolderSource([(_folder.Path, null)]));

        var task = result.Single("Exec[0]");
        Assert.Equal(@"C:\Tools\ok.exe", task.Resolution.TargetPath);
        Assert.Equal("/x", task.Resolution.Arguments);
        var link = result.Single("app.lnk");
        Assert.Equal(@"C:\Tools\app.exe", link.Resolution.TargetPath);
        Assert.Equal("/bg", link.Resolution.Arguments);
        Assert.True(broker.Status.WorkersRunning >= 1); // it really went through a worker
    }

    [Fact]
    public void DeeplyNestedTaskXml_IsMalformed_AndNothingCrashes()
    {
        WriteTask("Deep", Deep(140_000));
        WriteTask("Good", GoodTask);
        var broker = Broker();

        var result = Collect(broker, new ScheduledTaskSource(_folder.Path));

        Assert.Equal(@"C:\Tools\ok.exe", Assert.Single(result.Entries).Resolution.TargetPath);
        var issue = Assert.Single(result.Issues, i => i.Location == @"\Deep");
        Assert.Equal(PersistenceIssueReason.Malformed, issue.Reason);
        Assert.Contains("nested", issue.Message);
        Assert.Equal(0, broker.Status.WorkerRestarts); // handled by the parser itself: the worker survived too
    }

    [Fact]
    public void AWorkerCrashOnAFile_IsAMalformedIssue_TheOthersAreCollected_AndRepeatOffendersArentSentAgain()
    {
        WriteTask("Crash", GoodTask);
        WriteTask("Good", GoodTask.Replace("ok.exe", "fine.exe", StringComparison.Ordinal));
        int crashes = 0;
        var broker = Broker(path =>
        {
            if (path.EndsWith("Crash", StringComparison.Ordinal))
            {
                crashes++;
                return WorkerTestFault.Crash;
            }

            return WorkerTestFault.None;
        }, maxFailures: 2);
        var source = new ScheduledTaskSource(_folder.Path);

        var first = Collect(broker, source);

        Assert.Equal(@"C:\Tools\fine.exe", Assert.Single(first.Entries).Resolution.TargetPath);
        Assert.Contains(first.Issues, i => i.Location == @"\Crash" && i.Reason == PersistenceIssueReason.Malformed && i.Message.Contains("Crashed"));
        Assert.True(broker.Status.WorkerRestarts >= 1);

        Collect(broker, source);
        var third = Collect(broker, source); // two strikes: not sent to a worker again

        Assert.Equal(2, crashes);
        Assert.Contains(third.Issues, i => i.Location == @"\Crash" && i.Reason == PersistenceIssueReason.Malformed && i.Message.Contains("not sent"));
    }

    [Fact]
    public void AHangingParse_StopsAtTheShortParseTimeout_NotTheScanRequestTimeout()
    {
        // Follow-up review M2: one hanging parse used to hold the collection for the 60 s scan RequestTimeout (30 s here).
        WriteTask("Hang", GoodTask);
        WriteTask("Good", GoodTask.Replace("ok.exe", "fine.exe", StringComparison.Ordinal));
        var broker = Broker(path => path.EndsWith("Hang", StringComparison.Ordinal) ? WorkerTestFault.Hang : WorkerTestFault.None,
            parseTimeout: TimeSpan.FromSeconds(1));
        var clock = System.Diagnostics.Stopwatch.StartNew();

        var result = Collect(broker, new ScheduledTaskSource(_folder.Path));

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20), $"took {clock.Elapsed}");
        Assert.Equal(@"C:\Tools\fine.exe", Assert.Single(result.Entries).Resolution.TargetPath);
        Assert.Contains(result.Issues, i => i.Location == @"\Hang" && i.Reason == PersistenceIssueReason.Malformed);
    }

    [Theory]
    [InlineData(nameof(WorkerTestFault.MalformedResponse))]
    [InlineData(nameof(WorkerTestFault.WrongSchemaResponse))]
    public void ABrokenWorkerAnswer_IsMalformed_AndTheWorkerIsReplaced(string fault)
    {
        WriteTask("Bad", GoodTask);
        var broker = Broker(_ => Enum.Parse<WorkerTestFault>(fault));

        var result = Collect(broker, new ScheduledTaskSource(_folder.Path));

        Assert.Empty(result.Entries);
        Assert.Contains(result.Issues, i => i.Location == @"\Bad" && i.Reason == PersistenceIssueReason.Malformed);
        Assert.Equal(1, broker.Status.WorkerRestarts);
    }

    [Fact]
    public void WithoutASandbox_TasksAndShortcutsAreNotCollected_AndTheRestKeepsWorking()
    {
        WriteTask("Daily", GoodTask);
        File.WriteAllBytes(Path.Combine(_folder.Path, "app.lnk"), new ShellLinkBuilder { IdListPath = @"C:\Tools\app.exe" }.Build());
        File.WriteAllText(Path.Combine(_folder.Path, "run.bat"), "x");

        var result = Collect(UnavailablePersistenceParser.NoSandbox, new StartupFolderSource([(_folder.Path, null)]), new ScheduledTaskSource(_folder.Path));

        Assert.DoesNotContain(result.Entries, e => e.Kind == PersistenceKind.ScheduledTask);
        Assert.Equal(TargetUnresolvedReason.ShortcutUnreadable, result.Single("app.lnk").Resolution.UnresolvedReason);
        Assert.NotNull(result.Single("run.bat").Resolution.TargetPath); // needs no parsing
        Assert.Single(result.Issues, i => i.Reason == PersistenceIssueReason.ParserUnavailable); // once, not per file
    }

    [Fact]
    public void AWorkerThatCantStart_IsReportedAsUnavailable_NeverParsedInProcess()
    {
        WriteTask("Daily", GoodTask);
        var broker = new SandboxedScanBroker(new SandboxOptions
        {
            WorkerPath = Path.Combine(_folder.Path, "no-such-worker.exe"),
            WorkerCount = 1,
            Isolation = WorkerIsolation.UnsandboxedForTests,
            RestartBackoffInitial = TimeSpan.FromMilliseconds(1),
            RestartBackoffMax = TimeSpan.FromMilliseconds(1),
        }, new FakeRulesSource(), NullLogger.Instance);
        _brokers.Add(broker);

        var result = Collect(broker, new ScheduledTaskSource(_folder.Path));

        Assert.Empty(result.Entries);
        Assert.Single(result.Issues, i => i.Reason == PersistenceIssueReason.ParserUnavailable);
    }

    [Fact]
    public void TheEngineAssembly_NeverCallsTheFileParsers()
    {
        // The rule of review C H2, checked on the compiled IL: no method in SapAV.Engine references a parser entry point
        // (the engine has InternalsVisibleTo on Core, so the compiler alone can't enforce this).
        MethodBase[] parsers =
        [
            typeof(TaskXml).GetMethod(nameof(TaskXml.Parse))!,
            typeof(ShellLinkParser).GetMethod(nameof(ShellLinkParser.Parse))!,
            typeof(WireParsedFileCodec).GetMethod(nameof(WireParsedFileCodec.ParseInWorker))!,
        ];
        var engine = typeof(PersistenceCollector).Assembly;
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        int methods = 0;
        foreach (var type in engine.GetTypes())
        {
            foreach (var method in type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all)))
            {
                var il = method.GetMethodBody()?.GetILAsByteArray();
                if (il is null)
                {
                    continue;
                }

                methods++;
                foreach (var called in CallTargets(engine.ManifestModule, il, type, method))
                {
                    Assert.DoesNotContain(called, parsers);
                }
            }
        }

        Assert.True(methods > 1000, $"Only {methods} method bodies were checked.");

        // Positive control: the same scan does see the call in the test stand-in, so an empty result above means something.
        var standIn = typeof(WireTestParser).GetMethod(nameof(WireTestParser.ParseAsync))!;
        Assert.Contains(parsers[2], CallTargets(standIn.Module, standIn.GetMethodBody()!.GetILAsByteArray()!, typeof(WireTestParser), standIn));
    }

    /// <summary>Every call / callvirt / ldftn operand in the IL that resolves to a method (a stray match is harmless: it must equal a parser).</summary>
    private static IEnumerable<MethodBase> CallTargets(Module module, byte[] il, Type type, MethodBase method)
    {
        Type[]? typeArguments = type.IsGenericType ? type.GetGenericArguments() : null;
        Type[]? methodArguments = method.IsGenericMethod ? method.GetGenericArguments() : null;
        for (int i = 0; i + 4 < il.Length; i++)
        {
            bool call = il[i] == OpCodes.Call.Value || il[i] == OpCodes.Callvirt.Value || il[i] == OpCodes.Newobj.Value;
            bool ldftn = il[i] == 0xFE && il[i + 1] == (OpCodes.Ldftn.Value & 0xFF);
            if (!call && !ldftn)
            {
                continue;
            }

            int at = i + (ldftn ? 2 : 1);
            if (at + 4 > il.Length)
            {
                continue;
            }

            int token = BitConverter.ToInt32(il, at);
            MethodBase? target = null;
            try
            {
                target = module.ResolveMethod(token, typeArguments, methodArguments);
            }
            catch (Exception ex) when (ex is ArgumentException or BadImageFormatException or TypeLoadException or MissingMethodException)
            {
                // not a method token at this offset
            }

            if (target is not null)
            {
                yield return target;
            }
        }
    }
}
