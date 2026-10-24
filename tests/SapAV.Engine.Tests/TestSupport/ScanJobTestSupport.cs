using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// An in-memory <see cref="IScanBroker"/> (no worker process). It hashes the brokered handle itself and judges by file
/// name: <c>mal*</c> = Malicious, <c>sus*</c> = Suspicious, anything else Clean. <see cref="OnScan"/> runs first and may
/// block, throw or return its own report.
/// </summary>
internal sealed class FakeScanBroker : IScanBroker
{
    private int _calls;

    public FakeScanBroker(TimeProvider? time = null) => Time = time ?? TimeProvider.System;

    public TimeProvider Time { get; }

    public int Calls => Volatile.Read(ref _calls);

    /// <summary>Called on the scanning thread before the report is built; return a report to use it instead.</summary>
    public Func<ScanItem, OpenedScanFile, CancellationToken, Task<FileScanReport?>>? OnScan { get; set; }

    /// <summary>What <see cref="SandboxStatus.Rules"/> reports (null = not loaded yet).</summary>
    public RulesLoadSummary? Rules { get; set; } = new(5, [], 0, "fp", 1, 0);

    /// <summary>What <see cref="ReloadRulesAsync"/> returns.</summary>
    public RulesLoadSummary? ReloadResult { get; set; } = new(5, [], 0, "fp", 1, 0);

    public List<bool> BackgroundModeSeen { get; } = [];

    public List<bool> ThreadPoolSeen { get; } = [];

    public SandboxStatus Status => new(SandboxMode.AppContainer, 1, 0, Rules, null);

    public Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Scan jobs call ScanOpenedAsync.");

    public async Task<FileScanReport> ScanOpenedAsync(
        ScanItem item, OpenedScanFile file, IReadOnlyList<ScanNote> openNotes, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _calls);
        lock (BackgroundModeSeen)
        {
            BackgroundModeSeen.Add(BackgroundThread.IsCurrentInBackgroundMode);
            ThreadPoolSeen.Add(Thread.CurrentThread.IsThreadPoolThread);
        }

        if (OnScan is not null && await OnScan(item, file, cancellationToken).ConfigureAwait(false) is { } custom)
        {
            return custom;
        }

        return Judge(item, file, Time);
    }

    /// <summary>Thrown by <see cref="ReloadRulesAsync"/> when set.</summary>
    public Exception? ReloadFailure { get; set; }

    public Task<RulesLoadSummary?> ReloadRulesAsync(CancellationToken cancellationToken = default)
    {
        if (ReloadFailure is not null)
        {
            return Task.FromException<RulesLoadSummary?>(ReloadFailure);
        }

        Rules = ReloadResult;
        return Task.FromResult(ReloadResult);
    }

    /// <summary>The default report: SHA-256 from the handle, verdict from the file name, identity from the handle.</summary>
    public static FileScanReport Judge(ScanItem item, OpenedScanFile file, TimeProvider time)
    {
        long length = RandomAccess.GetLength(file.Handle);
        var bytes = new byte[length];
        RandomAccess.Read(file.Handle, bytes, 0);
        string sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        string name = Path.GetFileName(item.Path);
        Detection? detection =
            name.StartsWith("mal", StringComparison.OrdinalIgnoreCase)
                ? new Detection(Verdict.Malicious, "YARA rule Test_Malicious matched (test.yar)", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara)
            : name.StartsWith("sus", StringComparison.OrdinalIgnoreCase)
                ? new Detection(Verdict.Suspicious, "Heuristic score 70: test", MitreTechniqueIds.DoubleFileExtension, DetectionSource.Heuristic)
            : null;
        var result = new ScanResult(item, detection is null ? [] : [detection], time.GetUtcNow(), sha);
        return new FileScanReport(result, HashResult.Hashed(sha, length), null, null, null, null, []) { Identity = file.Identity };
    }
}

/// <summary>Builds a job service around a fake broker for one test; a temp tree of files under <see cref="Root"/>.</summary>
internal sealed class ScanJobHarness : IDisposable
{
    private readonly TempDir _temp = new();

    public ScanJobHarness(TimeProvider? time = null)
    {
        Time = time ?? TimeProvider.System;
        Broker = new FakeScanBroker(Time);
        Root = Directory.CreateDirectory(Path.Combine(_temp.Path, "tree")).FullName;
    }

    public TimeProvider Time { get; }

    public FakeScanBroker Broker { get; }

    public string Root { get; }

    public string Base => _temp.Path;

    public ScanJobOptions Options { get; } = new() { ThreadsPerJob = 1, QueueCapacity = 4 };

    public List<string> Excluded { get; } = [];

    /// <summary>Replaces <see cref="Excluded"/> with a real exclusion set (verified engine folders).</summary>
    public ExclusionSet? Exclusions { get; set; }

    public IScanVerdictHandler? Handler { get; set; }

    public IScanJobPreflight? Preflight { get; set; }

    public Func<string, uint?>? ReparseTag { get; set; }

    private ScanJobService? _service;

    public ScanJobService Service => _service ??= new ScanJobService(
        Options, Broker, Exclusions ?? ExclusionSet.Always(new FolderSet(Excluded)), Handler, Preflight, Time, NullLogger.Instance, ReparseTag);

    public string Write(string relative, string content = "plain test content")
    {
        var path = Path.Combine(Root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    /// <summary>Creates, subscribes a state recorder, starts.</summary>
    public (ScanJob Job, List<ScanJobStateChange> States) Start(params string[] paths)
    {
        var job = Service.Create(new ScanJobRequest(paths.Length == 0 ? [Root] : paths, ScanTrigger.CustomScan));
        var states = new List<ScanJobStateChange>();
        job.StateChanged += change =>
        {
            lock (states)
            {
                states.Add(change);
            }
        };
        Assert.Equal(ScanJobStartResult.Started, Service.Start(job.Id));
        return (job, states);
    }

    public void Dispose()
    {
        _service?.Dispose();
        foreach (var job in _service?.List() ?? [])
        {
            job.Completion.Wait(TimeSpan.FromSeconds(30)); // threads gone before the temp folder goes
        }

        _temp.Dispose();
    }
}

/// <summary>Waits for a job event without sleeping.</summary>
internal static class JobWait
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    /// <summary>Completes when the job reaches <paramref name="state"/> (already there counts).</summary>
    public static Task ForState(ScanJob job, ScanJobState state)
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        job.StateChanged += change =>
        {
            if (change.To == state)
            {
                reached.TrySetResult();
            }
        };
        if (job.State == state)
        {
            reached.TrySetResult();
        }

        return reached.Task.WaitAsync(Timeout);
    }

    public static Task Done(ScanJob job) => job.Completion.WaitAsync(Timeout);
}
