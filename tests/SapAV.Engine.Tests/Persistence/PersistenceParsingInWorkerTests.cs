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
            ParseTimeout = parseTimeout ?? TimeSpan.FromSeconds(30), // section D tester: a slow worker start under full-suite load once ate the 5 s default; only the hang tests pass a short one
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
        int sent = crashes; // C2: per collection it crashes its batch, then again alone (counted once: only alone is it to blame)
        var third = Collect(broker, source); // two strikes: not sent to a worker again

        Assert.Equal(sent, crashes);
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

    /// <summary>Opens files of the temp folder like the collectors do and keeps them open for one batch.</summary>
    private sealed class OpenFiles : IDisposable
    {
        private readonly SafeFileHandle _folder;
        private readonly List<SafeFileHandle> _files = [];

        public OpenFiles(string folder) => _folder = SafeFolderReader.OpenFolder(folder, out _)!;

        public List<PersistenceParseInput> Inputs { get; } = [];

        public OpenFiles Add(string name, WorkerParseKind kind)
        {
            var file = SafeFolderReader.OpenForParsing(_folder, name, TaskXml.MaxBytes, out _, out _)!;
            _files.Add(file);
            Inputs.Add(new PersistenceParseInput(file, kind, @"\" + name));
            return this;
        }

        public void Dispose()
        {
            _files.ForEach(f => f.Dispose());
            _folder.Dispose();
        }
    }

    private static string TaskFor(string exe) => GoodTask.Replace("ok.exe", exe, StringComparison.Ordinal);

    [Fact]
    public async Task ABatch_OfTasksAndShortcuts_RoundTripsInOrder_AcrossSeveralRequests()
    {
        const int Tasks = WorkerLimits.MaxParseBatch + 8; // more than one request
        using var files = new OpenFiles(_folder.Path);
        for (int i = 0; i < Tasks; i++)
        {
            WriteTask($"T{i:D2}", TaskFor($"t{i}.exe"));
            files.Add($"T{i:D2}", WorkerParseKind.ScheduledTask);
            if (i % 10 == 0)
            {
                File.WriteAllBytes(Path.Combine(_folder.Path, $"L{i}.lnk"), new ShellLinkBuilder { IdListPath = $@"C:\Tools\l{i}.exe" }.Build());
                files.Add($"L{i}.lnk", WorkerParseKind.ShellLink);
            }
        }

        var broker = Broker();

        var results = await broker.ParseBatchAsync(files.Inputs, null, CancellationToken.None);

        Assert.Equal(files.Inputs.Count, results.Count);
        for (int k = 0; k < results.Count; k++)
        {
            string name = files.Inputs[k].DisplayPath.TrimStart('\\');
            Assert.Equal(PersistenceParseStatus.Parsed, results[k].Status);
            if (name.StartsWith('T'))
            {
                Assert.Equal($@"C:\Tools\t{int.Parse(name[1..])}.exe", results[k].Task!.Actions[0].Command);
            }
            else
            {
                Assert.Equal($@"C:\Tools\l{name[1..^4]}.exe", results[k].Link!.IdListPath);
            }
        }

        Assert.Equal(Tasks + 4, results.Count(r => r.Status == PersistenceParseStatus.Parsed));
        Assert.Equal(0, broker.Status.WorkerRestarts); // one worker did it all
    }

    [Theory]
    [InlineData(nameof(WorkerTestFault.Crash), "Crashed")]
    [InlineData(nameof(WorkerTestFault.MalformedResponse), "ProtocolViolation")]
    [InlineData(nameof(WorkerTestFault.KeepHandleCopy), "kept a copy")] // the kept-handle check covers every handle of the batch
    public async Task OneBadFileInABatch_IsMalformed_AndTheOthersStillParse(string fault, string expected)
    {
        using var files = new OpenFiles(_folder.Path);
        foreach (var name in (string[])["A", "Bad", "B", "C"])
        {
            WriteTask(name, TaskFor(name + ".exe"));
            files.Add(name, WorkerParseKind.ScheduledTask);
        }

        var broker = Broker(path => path.EndsWith("Bad", StringComparison.Ordinal) ? Enum.Parse<WorkerTestFault>(fault) : WorkerTestFault.None);

        var results = await broker.ParseBatchAsync(files.Inputs, null, CancellationToken.None);

        Assert.Equal(PersistenceParseStatus.Malformed, results[1].Status);
        Assert.Contains(expected, results[1].Message);
        foreach (int k in (int[])[0, 2, 3])
        {
            Assert.Equal(PersistenceParseStatus.Parsed, results[k].Status);
            Assert.EndsWith(".exe", results[k].Task!.Actions[0].Command);
        }

        Assert.True(broker.Status.WorkerRestarts >= 2); // the batch's worker and the one the file broke alone
    }

    [Fact]
    public void ABatchOfHangingFiles_StopsAtTheBudget_AndBlamesNoFileItDidntRetry()
    {
        // Review H1: 32 hanging files used to cost the batch timeout plus a timeout, a restart and a backoff per solo retry.
        for (int i = 0; i < WorkerLimits.MaxParseBatch; i++)
        {
            WriteTask($"Hang{i:D2}", GoodTask);
        }

        var broker = Broker(_ => WorkerTestFault.Hang, parseTimeout: TimeSpan.FromSeconds(1));
        var limits = new PersistenceLimits { TimeBudget = TimeSpan.FromSeconds(1) };
        var clock = System.Diagnostics.Stopwatch.StartNew();

        var result = new PersistenceCollector(_root.View, _probe, [new ScheduledTaskSource(_folder.Path)], limits, parser: broker).Collect();

        // The budget runs out during the batch (3 x ParseTimeout); no solo retry starts after that.
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"took {clock.Elapsed}");
        Assert.Contains(result.Issues, i => i.Reason == PersistenceIssueReason.TimeBudgetExceeded);
        Assert.Empty(result.Entries);
        Assert.Equal(0, broker.RecordedFailures);
    }

    [Fact]
    public async Task TheSoloRetries_StopAfterTwoFailures_AndTheRestAreNotCollectedNorBlamed()
    {
        using var files = new OpenFiles(_folder.Path);
        for (int i = 0; i < 6; i++)
        {
            WriteTask($"Hang{i}", GoodTask);
            files.Add($"Hang{i}", WorkerParseKind.ScheduledTask);
        }

        var broker = Broker(_ => WorkerTestFault.Hang, parseTimeout: TimeSpan.FromSeconds(1));

        var results = await broker.ParseBatchAsync(files.Inputs, null, CancellationToken.None);

        Assert.All(results.Take(SandboxedScanBroker.MaxSoloFailuresPerBatch), r => Assert.Contains("TimedOut", r.Message));
        Assert.All(results.Skip(SandboxedScanBroker.MaxSoloFailuresPerBatch), r =>
        {
            Assert.Equal(PersistenceParseStatus.NotCollected, r.Status);
            Assert.False(r.IsOverBudget);
        });
        Assert.Equal(SandboxedScanBroker.MaxSoloFailuresPerBatch, broker.RecordedFailures);
    }

    [Fact]
    public async Task Exchanges_RunOnTheWorkersOneIoThread_AndFailAfterDispose()
    {
        // Review M1: one long-lived thread per worker, not a new thread per request (and not a pool thread).
        WriteTask("A", GoodTask);
        using var files = new OpenFiles(_folder.Path).Add("A", WorkerParseKind.ScheduledTask);
        var broker = Broker();
        await broker.ParseBatchAsync(files.Inputs, null, CancellationToken.None);
        var worker = broker.Slots[0].Worker!;

        int first = await worker.RunOnIoThread(() => Environment.CurrentManagedThreadId);
        int second = await worker.RunOnIoThread(() => Environment.CurrentManagedThreadId);
        bool pool = await worker.RunOnIoThread(() => Thread.CurrentThread.IsThreadPoolThread);
        worker.Dispose();

        Assert.Equal(first, second);
        Assert.False(pool);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => worker.RunOnIoThread(() => 0));
    }

    [Fact]
    public void TheCollector_SendsTaskFiles_InBatchesOfAtMostTheCap()
    {
        const int Tasks = 2 * WorkerLimits.MaxParseBatch + 5;
        for (int i = 0; i < Tasks; i++)
        {
            WriteTask($"T{i:D3}", TaskFor($"t{i}.exe"));
        }

        var parser = new BatchRecorder();

        var result = Collect(parser, new ScheduledTaskSource(_folder.Path));

        Assert.Equal(Tasks, result.Entries.Count);
        Assert.Equal(Tasks, parser.Sizes.Sum());
        Assert.All(parser.Sizes, size => Assert.InRange(size, 1, WorkerLimits.MaxParseBatch));
        Assert.Equal(3, parser.Sizes.Count);
    }

    private sealed class BatchRecorder : IPersistenceFileParser
    {
        public List<int> Sizes { get; } = [];

        public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken) =>
            WireTestParser.Instance.ParseAsync(file, kind, displayPath, cancellationToken);

        public async Task<IReadOnlyList<PersistenceParseResult>> ParseBatchAsync(IReadOnlyList<PersistenceParseInput> files, Func<bool>? canContinue, CancellationToken cancellationToken)
        {
            Sizes.Add(files.Count);
            var results = new List<PersistenceParseResult>();
            foreach (var f in files)
            {
                results.Add(await ParseAsync(f.File, f.Kind, f.DisplayPath, cancellationToken));
            }

            return results;
        }
    }

    [Fact]
    public async Task TheWorker_RefusesABatchOverTheCap()
    {
        WriteTask("A", GoodTask);
        using var files = new OpenFiles(_folder.Path).Add("A", WorkerParseKind.ScheduledTask);
        var broker = Broker();
        Assert.Equal(PersistenceParseStatus.Parsed, (await broker.ParseBatchAsync(files.Inputs, null, CancellationToken.None))[0].Status); // a running worker
        var slot = broker.Slots[0];
        var worker = slot.Worker!;
        IntPtr remote = worker.DuplicateInto(files.Inputs[0].File, WorkerProcess.ReadOnlyFileAccess);
        try
        {
            var tooMany = Enumerable.Repeat(new WorkerParseFile { Kind = WorkerParseKind.ScheduledTask, FileHandle = remote, TestFault = WorkerTestFault.None },
                WorkerLimits.MaxParseBatch + 1).ToArray();

            var response = await slot.ParseAsync(new WorkerParseRequest { Files = tooMany }, CancellationToken.None);

            Assert.Equal(WorkerResponseKind.Failed, response.Kind);
            Assert.Contains($"1 to {WorkerLimits.MaxParseBatch}", response.Error);
        }
        finally
        {
            worker.CloseInWorker(remote);
        }
    }

    [Fact]
    public void TheBatchTimeout_ScalesWithTheBatch_AndIsBounded()
    {
        var options = new SandboxOptions { ParseTimeout = TimeSpan.FromSeconds(4) };

        Assert.Equal(TimeSpan.FromSeconds(4), options.ParseBatchTimeout(1));
        Assert.Equal(TimeSpan.FromSeconds(5), options.ParseBatchTimeout(3));
        Assert.Equal(TimeSpan.FromSeconds(12), options.ParseBatchTimeout(WorkerLimits.MaxParseBatch)); // 3 x ParseTimeout at most
        Assert.Equal(TimeSpan.FromSeconds(12), options.ParseBatchTimeout(int.MaxValue));
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
