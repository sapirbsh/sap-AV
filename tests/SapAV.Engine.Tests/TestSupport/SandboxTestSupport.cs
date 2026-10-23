using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Models;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// A throwaway AppContainer profile (<c>sap-AV.ScanWorker.Test.&lt;guid&gt;</c>) and, if needed, the read/execute grant
/// for it on the test output's <c>ScanWorker\</c> folder. Both are removed on dispose, so tests leave no profile and no
/// ACL entry behind.
/// </summary>
internal sealed class TestAppContainer : IDisposable
{
    public TestAppContainer(string purpose = "Test")
    {
        Name = $"sap-AV.ScanWorker.{purpose}.{Guid.NewGuid():N}";
        Sid = AppContainerProfile.Ensure(Name);
        try
        {
            Grant = WorkerFolderAccess.Ensure(WorkerExe, Sid);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public static string WorkerExe => Path.Combine(AppContext.BaseDirectory, "ScanWorker", "SapAV.ScanWorker.exe");

    public string Name { get; }

    public SecurityIdentifier Sid { get; }

    public FolderGrantResult Grant { get; }

    /// <summary>Sandbox options for this container (test hooks on; tests may change the rest).</summary>
    public SandboxOptions Options(Action<SandboxOptions>? configure = null)
    {
        var options = new SandboxOptions
        {
            AppContainerName = Name,
            WorkerPath = WorkerExe,
            WorkerCount = 1,
            EnableWorkerTestHooks = true,
            RestartBackoffInitial = TimeSpan.FromMilliseconds(10),
            RestartBackoffMax = TimeSpan.FromMilliseconds(100),
        };
        configure?.Invoke(options);
        return options;
    }

    public WorkerProcess Start(WorkerMitigations? mitigations = null, bool testHooks = true) =>
        WorkerProcess.Start(new WorkerLaunchSpec(WorkerExe, WorkerIsolation.AppContainer, Sid, 1024L * 1024 * 1024, 0,
            mitigations ?? WorkerMitigations.Default, testHooks));

    public void Dispose()
    {
        try
        {
            if (Grant == FolderGrantResult.Granted)
            {
                WorkerFolderAccess.Revoke(WorkerExe, Sid);
            }
        }
        finally
        {
            AppContainerProfile.Delete(Name);
        }
    }
}

/// <summary>Raw requests to a <see cref="WorkerProcess"/>, for tests that drive the worker without the broker.</summary>
internal static class WorkerTestClient
{
    private static long s_id;

    public static Task<WorkerResponse> LoadRulesAsync(WorkerProcess worker, string? ruleText = null, byte[]? blocklist = null) =>
        WorkerChannel.ExchangeAsync(worker, new WorkerRequest
        {
            Id = Interlocked.Increment(ref s_id),
            Kind = WorkerRequestKind.LoadRules,
            LoadRules = new WorkerLoadRules
            {
                RuleFiles = ruleText is null ? [] : [new WorkerRuleFile { Name = "test.yar", Content = System.Text.Encoding.UTF8.GetBytes(ruleText) }],
                ReadErrors = [],
                Blocklist = blocklist ?? [],
            },
            Scan = null,
            Probe = null,
        }, WorkerLimits.MaxRulesRequestBytes, TimeSpan.FromSeconds(60), CancellationToken.None);

    public static Task<WorkerResponse> ProbeAsync(WorkerProcess worker, WorkerProbeKind kind, string? path = null, int port = 0, long handle = 0) =>
        WorkerChannel.ExchangeAsync(worker, new WorkerRequest
        {
            Id = Interlocked.Increment(ref s_id),
            Kind = WorkerRequestKind.Probe,
            LoadRules = null,
            Scan = null,
            Probe = new WorkerProbeRequest { Kind = kind, Path = path, Port = port, Handle = handle },
        }, WorkerLimits.MaxRequestBytes, TimeSpan.FromSeconds(30), CancellationToken.None);

    /// <summary>Opens <paramref name="path"/> here, duplicates it read-only into the worker, scans, closes it there.</summary>
    public static async Task<WorkerResponse> ScanAsync(WorkerProcess worker, string path, WorkerTestFault fault = WorkerTestFault.None, TimeSpan? timeout = null)
    {
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        IntPtr remote = worker.DuplicateInto(file, WorkerProcess.ReadOnlyFileAccess);
        try
        {
            return await WorkerChannel.ExchangeAsync(worker, new WorkerRequest
            {
                Id = Interlocked.Increment(ref s_id),
                Kind = WorkerRequestKind.Scan,
                LoadRules = null,
                Scan = new WorkerScanRequest
                {
                    Item = new ScanItem(path, ScanTrigger.CustomScan),
                    FileHandle = remote,
                    StreamHandle = null,
                    StreamOpenError = 2,
                    TestFault = fault,
                },
                Probe = null,
            }, WorkerLimits.MaxRequestBytes, timeout ?? TimeSpan.FromSeconds(60), CancellationToken.None);
        }
        finally
        {
            worker.CloseInWorker(remote);
        }
    }

    public static SafeFileHandle OpenRead(string path) =>
        File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);

    public static Microsoft.Extensions.Logging.ILogger Logger => NullLogger.Instance;
}
