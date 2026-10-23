using SapAV.Core.Scanning.Isolation;

namespace SapAV.Engine.Sandbox;

/// <summary>Why a request to the worker didn't produce a response.</summary>
internal enum WorkerFailureKind
{
    /// <summary>The worker exited or its pipe broke (a parser crash, the memory limit, a kill).</summary>
    Crashed,

    /// <summary>No response within the request timeout; the worker was killed.</summary>
    TimedOut,

    /// <summary>The response broke the protocol (framing, size cap, schema, content, request ID); the worker was killed.</summary>
    ProtocolViolation,

    /// <summary>The worker could not be started (or restarted) at all.</summary>
    Unavailable,
}

/// <summary>A request to the worker failed; the worker has been killed unless <see cref="Kind"/> is Unavailable.</summary>
internal sealed class WorkerRequestException(WorkerFailureKind kind, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public WorkerFailureKind Kind { get; } = kind;
}

/// <summary>
/// One request/response exchange with a <see cref="WorkerProcess"/>. The pipes are synchronous (anonymous pipes), so the
/// exchange runs on a pool thread; on timeout or cancellation the worker is killed, which breaks the pipe and frees it.
/// Every response is read with the <see cref="WorkerLimits.MaxResponseBytes"/> cap and parsed strictly.
/// </summary>
internal static class WorkerChannel
{
    /// <exception cref="WorkerRequestException">Crashed, TimedOut or ProtocolViolation (the worker is killed).</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled (the worker is killed).</exception>
    public static async Task<WorkerResponse> ExchangeAsync(
        WorkerProcess worker, WorkerRequest request, int maxRequestBytes, TimeSpan timeout, CancellationToken cancellationToken)
    {
        byte[] payload = WorkerJson.Serialize(request, maxRequestBytes);
        var exchange = Task.Run(() =>
        {
            WorkerFraming.Write(worker.Requests, payload, maxRequestBytes);
            return WorkerFraming.Read(worker.Responses, WorkerLimits.MaxResponseBytes);
        }, CancellationToken.None);

        byte[]? frame;
        try
        {
            frame = await exchange.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            Abandon(worker, exchange);
            throw new WorkerRequestException(WorkerFailureKind.TimedOut, $"The scan worker did not answer within {timeout.TotalSeconds:0.#} s; it was killed.");
        }
        catch (OperationCanceledException)
        {
            Abandon(worker, exchange);
            throw;
        }
        catch (WorkerProtocolException ex)
        {
            worker.Kill();
            throw new WorkerRequestException(WorkerFailureKind.ProtocolViolation, $"The scan worker broke the protocol: {ex.Message}", ex);
        }
        catch (IOException ex)
        {
            worker.Kill();
            throw new WorkerRequestException(WorkerFailureKind.Crashed, $"The scan worker's pipe broke ({DescribeExit(worker)}).", ex);
        }
        catch (ObjectDisposedException ex)
        {
            throw new WorkerRequestException(WorkerFailureKind.Crashed, "The scan worker was shut down.", ex);
        }

        if (frame is null)
        {
            worker.WaitForExit(TimeSpan.FromSeconds(2));
            worker.Kill();
            throw new WorkerRequestException(WorkerFailureKind.Crashed, $"The scan worker exited without answering ({DescribeExit(worker)}).");
        }

        WorkerResponse response;
        try
        {
            response = WorkerJson.Deserialize<WorkerResponse>(frame);
            ValidateEnvelope(request, response);
        }
        catch (WorkerProtocolException ex)
        {
            worker.Kill();
            throw new WorkerRequestException(WorkerFailureKind.ProtocolViolation, $"The scan worker sent an invalid response: {ex.Message}", ex);
        }

        return response;
    }

    /// <summary>The ID must match, and exactly the body for the kind must be present.</summary>
    internal static void ValidateEnvelope(WorkerRequest request, WorkerResponse response)
    {
        if (response.Id != request.Id)
        {
            throw new WorkerProtocolException($"Response ID {response.Id} doesn't match request ID {request.Id}.");
        }

        bool shapeOk = response.Kind switch
        {
            WorkerResponseKind.RulesLoaded => request.Kind == WorkerRequestKind.LoadRules && response.Rules is not null
                && response.Report is null && response.Probe is null && response.Error is null,
            WorkerResponseKind.Scanned => request.Kind == WorkerRequestKind.Scan && response.Report is not null
                && response.Rules is null && response.Probe is null && response.Error is null,
            WorkerResponseKind.Probed => request.Kind == WorkerRequestKind.Probe && response.Probe is not null
                && response.Rules is null && response.Report is null && response.Error is null,
            WorkerResponseKind.Failed => response.Error is not null && response.Error.Length <= WorkerLimits.MaxTextLength
                && response.Rules is null && response.Report is null && response.Probe is null,
            _ => false,
        };

        if (!shapeOk)
        {
            throw new WorkerProtocolException($"A {response.Kind} response doesn't fit a {request.Kind} request.");
        }
    }

    private static void Abandon(WorkerProcess worker, Task exchange)
    {
        worker.Kill();
        _ = exchange.ContinueWith(t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
    }

    private static string DescribeExit(WorkerProcess worker) =>
        worker.ExitCode is { } code ? $"exit code 0x{code:X8}" : "still running";
}
