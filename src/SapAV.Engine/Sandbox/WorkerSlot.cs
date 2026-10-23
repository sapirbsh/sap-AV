using Microsoft.Extensions.Logging;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.Engine.Sandbox;

/// <summary>The rule package the broker wants every worker to have, with a generation number per reload.</summary>
internal sealed record RulePackage(int Generation, WorkerLoadRules Rules);

/// <summary>
/// One place in the worker pool. Used by one request at a time (<see cref="Lock"/>). Starts its worker on demand,
/// loads the current rule package into it before it scans, and after any failure kills it and waits an exponential
/// backoff before the next start, so a crash loop can't spin the CPU. A worker's death never escapes as an exception
/// other than <see cref="WorkerRequestException"/>.
/// </summary>
internal sealed class WorkerSlot(int index, WorkerLauncher launcher, SandboxOptions options, TimeProvider time, ILogger logger) : IDisposable
{
    private WorkerProcess? _worker;
    private int _generation = -1;
    private int _consecutiveFailures;
    private DateTimeOffset _notBefore = DateTimeOffset.MinValue;

    public SemaphoreSlim Lock { get; } = new(1, 1);

    public int Index { get; } = index;

    public bool IsRunning => _worker is { HasExited: false };

    /// <summary>Called whenever a worker in this slot died or was killed (for status counters).</summary>
    public Action<string>? OnWorkerLost { get; init; }

    /// <summary>The summary of the last rule load in this slot's worker.</summary>
    public WorkerRulesSummary? LastRules { get; private set; }

    /// <summary>Test seam: the running worker (null when stopped).</summary>
    internal WorkerProcess? Worker => _worker;

    /// <summary>Ensures a live worker with rule package <paramref name="package"/>. Caller holds <see cref="Lock"/>.</summary>
    /// <exception cref="WorkerRequestException">Unavailable (can't start), or the rule load failed.</exception>
    public async Task<WorkerProcess> EnsureReadyAsync(RulePackage package, CancellationToken cancellationToken)
    {
        if (_worker is { } existing && existing.HasExited)
        {
            Lost($"worker {Index} (pid {existing.ProcessId}) exited with 0x{existing.ExitCode ?? 0:X8}");
        }
        else if (_worker is { } chatty && chatty.HasUnsolicitedOutput)
        {
            // Review L3: a frame queued before the request could be taken as its answer. Replace the worker first;
            // the file about to be scanned is not blamed.
            Lost($"worker {Index} (pid {chatty.ProcessId}) wrote data nobody asked for");
        }

        if (_worker is null)
        {
            var wait = _notBefore - time.GetUtcNow();
            if (wait > TimeSpan.Zero)
            {
                await Task.Delay(wait, time, cancellationToken).ConfigureAwait(false);
            }

            try
            {
                _worker = launcher.Start();
                _generation = -1;
                logger.LogDebug("Scan worker {Index} started (pid {Pid}).", Index, _worker.ProcessId);
            }
            catch (SandboxUnavailableException ex)
            {
                Failed();
                throw new WorkerRequestException(WorkerFailureKind.Unavailable, ex.Message, ex);
            }
        }

        if (_generation != package.Generation)
        {
            var response = await ExchangeAsync(WorkerRequestKind.LoadRules, package.Rules, null,
                WorkerLimits.MaxRulesRequestBytes, options.RulesLoadTimeout, cancellationToken).ConfigureAwait(false);
            if (response.Kind != WorkerResponseKind.RulesLoaded)
            {
                Kill();
                Failed();
                throw new WorkerRequestException(WorkerFailureKind.Unavailable, $"The scan worker could not load the rules: {response.Error}");
            }

            LastRules = response.Rules;
            _generation = package.Generation;
        }

        return _worker!;
    }

    /// <summary>Sends a scan request to the ready worker. Failures kill the worker and start the backoff.</summary>
    public Task<WorkerResponse> ScanAsync(WorkerScanRequest scan, CancellationToken cancellationToken) =>
        ExchangeAsync(WorkerRequestKind.Scan, null, scan, WorkerLimits.MaxRequestBytes, options.RequestTimeout, cancellationToken);

    /// <summary>A request completed normally: the backoff starts over.</summary>
    public void Succeeded() => _consecutiveFailures = 0;

    public void Kill()
    {
        if (_worker is { } worker)
        {
            _worker = null;
            _generation = -1;
            worker.Dispose();
        }
    }

    public void Dispose()
    {
        Kill();
        Lock.Dispose();
    }

    private async Task<WorkerResponse> ExchangeAsync(
        WorkerRequestKind kind, WorkerLoadRules? rules, WorkerScanRequest? scan, int maxBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var worker = _worker ?? throw new WorkerRequestException(WorkerFailureKind.Unavailable, "No scan worker is running.");
        // Random request IDs (review L3): a frame the worker queued in advance can't guess the ID it must echo.
        var request = new WorkerRequest { Id = NewRequestId(), Kind = kind, LoadRules = rules, Scan = scan, Probe = null };
        try
        {
            return await WorkerChannel.ExchangeAsync(worker, request, maxBytes, timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (WorkerRequestException ex)
        {
            Lost($"worker {Index} (pid {worker.ProcessId}): {ex.Message}");
            throw;
        }
        catch (OperationCanceledException)
        {
            Kill(); // the exchange was abandoned mid-request; never reuse that pipe
            throw;
        }
    }

    private static long NewRequestId() =>
        BitConverter.ToInt64(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)) & long.MaxValue; // 63 random bits

    private void Lost(string why)
    {
        Kill();
        Failed();
        logger.LogWarning("Scan worker lost: {Reason}. Next start in {Delay} ms.", why, (int)(_notBefore - time.GetUtcNow()).TotalMilliseconds);
        OnWorkerLost?.Invoke(why);
    }

    private void Failed()
    {
        _consecutiveFailures++;
        double factor = Math.Pow(2, Math.Min(_consecutiveFailures - 1, 16));
        var delay = TimeSpan.FromTicks((long)Math.Min(options.RestartBackoffInitial.Ticks * factor, options.RestartBackoffMax.Ticks));
        _notBefore = time.GetUtcNow() + delay;
    }
}
