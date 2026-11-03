using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Tests.TestSupport;
using SapAV.Engine.Persistence;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.Sandbox;
using SapAV.Engine.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// C2 benchmark (opt-in, <c>SAPAV_TEST_SLOW=1</c>): 200 synthetic task files through the real worker, with the per-request
/// stages timed, then the whole scheduled-task collection one file per request and batched, on an idle machine, with every
/// core busy at normal priority (a combined test run: the worker runs at BelowNormal), and with the thread pool starved.
/// It prints the numbers; it asserts only that the batched collection got everything.
/// </summary>
public sealed class ParseBenchmarkTests(ITestOutputHelper output) : IDisposable
{
    private const int Files = 200;
    private readonly TempDir _folder = new();
    private readonly RegistryTestRoot _root = new();

    public void Dispose()
    {
        _folder.Dispose();
        _root.Dispose();
    }

    [RequiresFact(Requires.SlowTests)]
    public void Benchmark_Unsandboxed() => Run(new SandboxOptions
    {
        WorkerPath = TestAppContainer.WorkerExe,
        WorkerCount = 1,
        Isolation = WorkerIsolation.UnsandboxedForTests,
    });

    [RequiresFact(Requires.SlowTests, Requires.AppContainer)]
    public void Benchmark_AppContainer()
    {
        using var container = new TestAppContainer("Bench");
        Run(container.Options(o => o.EnableWorkerTestHooks = false));
    }

    private void Run(SandboxOptions options)
    {
        for (int i = 0; i < Files; i++)
        {
            File.WriteAllBytes(Path.Combine(_folder.Path, $"Task{i:D3}"), [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(TaskXmlText(i))]);
        }

        // No planned recycle mid-benchmark: a cold worker start under the CPU load would be timed instead of the parsing.
        options.MaxFilesPerWorker = 100_000;
        using var broker = new SandboxedScanBroker(options, new FakeRulesSource(), NullLogger.Instance);
        output.WriteLine(Stages(broker));

        var batched = new PersistenceCollector(_root.View, new SetProbe(), [new ScheduledTaskSource(_folder.Path)], parser: broker);
        var perFile = new PersistenceCollector(_root.View, new SetProbe(), [new ScheduledTaskSource(_folder.Path)], parser: new OneByOne(broker));
        Collect("idle, one file per request", perFile);
        var idle = Collect("idle, batched", batched);
        Assert.Equal(Files, idle.Entries.Count);

        using (Saturate(out int threads))
        {
            Collect($"{threads} busy normal-priority threads, batched", batched);
        }

        using (Starve(out int blocked))
        {
            Collect($"thread pool starved ({blocked} blocked items), one file per request", perFile, onOwnThread: true);
            Collect($"thread pool starved ({blocked} blocked items), batched", batched, onOwnThread: true);
        }
    }

    /// <summary>One file through each stage of a request (a batch of one), summed over all files.</summary>
    private string Stages(SandboxedScanBroker broker)
    {
        using var dir = SafeFolderReader.OpenFolder(_folder.Path, out _)!;
        using (var first = Open(dir, 0))
        {
            Assert.Equal(PersistenceParseStatus.Parsed, broker.ParseAsync(first, WorkerParseKind.ScheduledTask, "warm-up", CancellationToken.None).GetAwaiter().GetResult().Status);
        }

        var slot = broker.Slots[0];
        var worker = slot.Worker!;
        var t = new long[6];
        for (int i = 0; i < Files; i++)
        {
            long s0 = Stopwatch.GetTimestamp();
            using var file = Open(dir, i);
            long s1 = Stopwatch.GetTimestamp();
            _ = FileIdentity.TryCapture(file);
            _ = RandomAccess.GetLength(file);
            _ = File.GetLastWriteTimeUtc(file);
            long s2 = Stopwatch.GetTimestamp();
            var remote = worker.DuplicateInto(file, WorkerProcess.ReadOnlyFileAccess);
            long s3 = Stopwatch.GetTimestamp();
            var response = slot.ParseAsync(new WorkerParseRequest
            {
                Files = [new WorkerParseFile { Kind = WorkerParseKind.ScheduledTask, FileHandle = remote, TestFault = WorkerTestFault.None }],
            }, CancellationToken.None).GetAwaiter().GetResult();
            long s4 = Stopwatch.GetTimestamp();
            worker.CloseInWorker(remote);
            long s5 = Stopwatch.GetTimestamp();
            Assert.Equal(BrokeredHandleState.Released, BrokeredHandles.Check(file));
            long s6 = Stopwatch.GetTimestamp();
            Assert.Equal(WorkerResponseKind.Parsed, response.Kind);
            long[] at = [s0, s1, s2, s3, s4, s5, s6];
            for (int k = 0; k < t.Length; k++)
            {
                t[k] += at[k + 1] - at[k];
            }
        }

        static string Ms(long ticks) => $"{ticks * 1000.0 / Stopwatch.Frequency:0.0} ms";
        return $"Stages over {Files} files (one per request, idle): open {Ms(t[0])}, identity + failure key {Ms(t[1])}, duplicate {Ms(t[2])}, " +
            $"exchange (pipe + JSON + worker) {Ms(t[3])}, close in worker {Ms(t[4])}, kept-handle check {Ms(t[5])}";
    }

    private PersistenceCollection Collect(string label, PersistenceCollector collector, bool onOwnThread = false)
    {
        PersistenceCollection? result = null;
        var thread = new Thread(() => result = collector.Collect());
        if (onOwnThread)
        {
            thread.Start();
            thread.Join();
        }
        else
        {
            result = collector.Collect();
        }

        var tasks = result!.SourceTimings!.Single();
        output.WriteLine($"{label}: {tasks.Duration.TotalMilliseconds:0} ms, {tasks.Entries} entries, {tasks.Issues} issues, {tasks.ParsedFiles} parsed ({tasks.ParseTime.TotalMilliseconds:0} ms parsing)");
        return result;
    }

    private static SafeFileHandle Open(SafeFileHandle dir, int i) =>
        SafeFolderReader.OpenForParsing(dir, $"Task{i:D3}", TaskXml.MaxBytes, out _, out _)!;

    private static IDisposable Saturate(out int threads)
    {
        var stop = new CancellationTokenSource();
        var spinners = Enumerable.Range(0, Environment.ProcessorCount).Select(_ => new Thread(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                Thread.SpinWait(1000);
            }
        }) { IsBackground = true }).ToList();
        spinners.ForEach(s => s.Start());
        threads = spinners.Count;
        return new Done(() =>
        {
            stop.Cancel();
            spinners.ForEach(s => s.Join());
            stop.Dispose();
        });
    }

    private static IDisposable Starve(out int blocked)
    {
        var release = new ManualResetEventSlim();
        ThreadPool.GetMinThreads(out int min, out _);
        blocked = min * 2;
        for (int i = 0; i < blocked; i++)
        {
            ThreadPool.QueueUserWorkItem(_ => release.Wait());
        }

        Thread.Sleep(200);
        return new Done(release.Set);
    }

    private sealed class Done(Action action) : IDisposable
    {
        public void Dispose() => action();
    }

    /// <summary>The broker, but one request per file (the interface's default batch), for the comparison.</summary>
    private sealed class OneByOne(SandboxedScanBroker broker) : IPersistenceFileParser
    {
        public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken) =>
            broker.ParseAsync(file, kind, displayPath, cancellationToken);
    }

    private static string TaskXmlText(int i) => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Author>Contoso</Author><URI>\Bench\Task{i}</URI></RegistrationInfo>
          <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
          <Settings><Enabled>true</Enabled><Hidden>false</Hidden>{string.Concat(Enumerable.Repeat("<!-- padding -->", 100))}</Settings>
          <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
          <Actions Context="Author"><Exec><Command>C:\Tools\app{i}.exe</Command><Arguments>/run {i}</Arguments></Exec></Actions>
        </Task>
        """;
}
