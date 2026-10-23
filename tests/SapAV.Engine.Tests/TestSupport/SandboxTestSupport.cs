using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Models;
using SapAV.Core.Scanning.Isolation;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// A throwaway AppContainer profile (<c>sap-AV.ScanWorker.Test.&lt;pid&gt;.&lt;purpose&gt;.&lt;12 hex&gt;</c>) and, if needed,
/// the read/execute grant for it on the test output's <c>ScanWorker\</c> folder. Both are removed on dispose; profiles and
/// ACEs left by a test process that died are purged once per process (<see cref="StaleTestProfiles"/>).
/// </summary>
internal sealed class TestAppContainer : IDisposable
{
    public const string NamePrefix = "sap-AV.ScanWorker.Test.";

    public TestAppContainer(string purpose = "Run")
    {
        StaleTestProfiles.PurgeOnce();
        Name = $"{NamePrefix}{Environment.ProcessId}.{purpose}.{Guid.NewGuid().ToString("N")[..12]}";
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

    private int _disposed;

    /// <summary>Removes the grant and the profile. Idempotent.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

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

/// <summary>
/// Cleans up after test processes that died before their fixtures were disposed (killed runner, debugger stop):
/// <list type="bullet">
/// <item>deletes AppContainer profiles named <c>sap-AV.ScanWorker.Test.&lt;pid&gt;.*</c> whose process is gone, and older
/// test profile names (<c>sap-AV.ScanWorker.&lt;anything that is not a per-install name&gt;</c>);</item>
/// <item>removes S-1-15-2-* entries from the test output's <c>ScanWorker\</c> folder that belong to no live test profile,
/// keeping ALL APPLICATION PACKAGES (S-1-15-2-1) and ALL RESTRICTED APPLICATION PACKAGES (S-1-15-2-2).</item>
/// </list>
/// Never touches the engine's per-install profile (<c>sap-AV.ScanWorker.&lt;32 hex&gt;</c>) or other software's profiles.
/// </summary>
internal static class StaleTestProfiles
{
    private const string MappingsKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings";
    private static readonly Lazy<bool> Purged = new(Purge);

    public static void PurgeOnce() => _ = Purged.Value;

    private static bool Purge()
    {
        try
        {
            var live = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var mappings = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(MappingsKey);
            foreach (var sid in mappings?.GetSubKeyNames() ?? [])
            {
                using var key = mappings!.OpenSubKey(sid);
                if (key?.GetValue("Moniker") is not string moniker || !moniker.StartsWith("sap-AV.ScanWorker", StringComparison.Ordinal))
                {
                    continue; // not ours
                }

                if (AppContainerName.IsValidName(moniker) || OwnerIsAlive(moniker))
                {
                    live.Add(sid);
                }
                else
                {
                    AppContainerProfile.Delete(moniker);
                }
            }

            var folder = new DirectoryInfo(Path.GetDirectoryName(TestAppContainer.WorkerExe)!);
            if (folder.Exists)
            {
                var stale = folder.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access)
                    .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                    .Cast<System.Security.AccessControl.FileSystemAccessRule>()
                    .Select(r => (SecurityIdentifier)r.IdentityReference)
                    .Where(s => s.Value.StartsWith("S-1-15-2-", StringComparison.Ordinal) && s.Value is not ("S-1-15-2-1" or "S-1-15-2-2"))
                    .Where(s => !live.Contains(s.Value))
                    .Distinct()
                    .ToArray();
                foreach (var sid in stale)
                {
                    WorkerFolderAccess.Revoke(TestAppContainer.WorkerExe, sid);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or SandboxUnavailableException)
        {
            // Best effort: a failed cleanup must not fail the tests that need a fresh container.
        }

        return true;
    }

    /// <summary>True for <c>sap-AV.ScanWorker.Test.&lt;pid&gt;.…</c> names whose process still runs.</summary>
    private static bool OwnerIsAlive(string moniker)
    {
        if (!moniker.StartsWith(TestAppContainer.NamePrefix, StringComparison.Ordinal))
        {
            return false; // an older test name format: stale by definition
        }

        var rest = moniker[TestAppContainer.NamePrefix.Length..];
        int dot = rest.IndexOf('.');
        if (dot <= 0 || !int.TryParse(rest[..dot], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int pid))
        {
            return false;
        }

        if (pid == Environment.ProcessId)
        {
            return true;
        }

        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return ex is System.ComponentModel.Win32Exception; // exists but can't be queried: assume alive
        }
    }
}
