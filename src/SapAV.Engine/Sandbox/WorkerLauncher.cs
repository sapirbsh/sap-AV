using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// Prepares the sandbox once (AppContainer profile, read/execute on the worker folder) and starts workers from it.
/// Preparation is retried on the next start if it failed.
/// </summary>
internal sealed class WorkerLauncher(SandboxOptions options, ILogger logger)
{
    private readonly object _gate = new();
    private SecurityIdentifier? _sid;
    private bool _prepared;

    /// <exception cref="SandboxUnavailableException">The sandbox can't be prepared or the worker can't be started.</exception>
    public WorkerProcess Start()
    {
        string exe = options.ResolvedWorkerPath;
        var sid = Prepare(exe);
        return WorkerProcess.Start(new WorkerLaunchSpec(
            exe,
            options.Isolation,
            sid,
            options.WorkerMemoryLimitMegabytes * 1024L * 1024L,
            options.WorkerCpuRatePercent,
            options.Mitigations,
            options.EnableWorkerTestHooks));
    }

    /// <summary>The AppContainer SID, once prepared (null in the test-only unsandboxed mode).</summary>
    public SecurityIdentifier? AppContainerSid
    {
        get
        {
            lock (_gate)
            {
                return _sid;
            }
        }
    }

    private SecurityIdentifier? Prepare(string exe)
    {
        lock (_gate)
        {
            if (_prepared)
            {
                return _sid;
            }

            if (!File.Exists(exe))
            {
                throw new SandboxUnavailableException($"The scan worker is missing: {exe}");
            }

            if (options.Isolation == WorkerIsolation.AppContainer)
            {
                var sid = AppContainerProfile.Ensure(options.AppContainerName);
                var grant = WorkerFolderAccess.Ensure(exe, sid);
                logger.LogInformation("Scan worker sandbox: AppContainer {Name} ({Sid}); worker folder access {Grant}.",
                    options.AppContainerName, sid.Value, grant);
                _sid = sid;
            }

            _prepared = true;
            return _sid;
        }
    }
}
