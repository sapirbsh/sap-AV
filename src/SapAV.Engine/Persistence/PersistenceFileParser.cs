using Microsoft.Win32.SafeHandles;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;

namespace SapAV.Engine.Persistence;

/// <summary>What became of one autostart definition file sent to the scan worker.</summary>
internal enum PersistenceParseStatus
{
    /// <summary><see cref="PersistenceParseResult.Task"/> or <see cref="PersistenceParseResult.Link"/> is set (validated worker output).</summary>
    Parsed,

    /// <summary>The file isn't well-formed, or the worker failed or broke the protocol on it.</summary>
    Malformed,

    /// <summary>The worker can't be reached at all (the file isn't to blame): nothing can be parsed for now.</summary>
    Unavailable,

    /// <summary>
    /// Review H1: not sent to the worker (the collection's budget ran out, or too many files of its batch broke the
    /// parser). The file isn't blamed and nothing is recorded against it.
    /// </summary>
    NotCollected,
}

/// <param name="Message">Why, for anything but Parsed.</param>
internal sealed record PersistenceParseResult(PersistenceParseStatus Status, TaskDefinitionInfo? Task, ShellLinkInfo? Link, string? Message)
{
    /// <summary>Not collected because the collection's budget said stop (that is reported once, by the budget check itself).</summary>
    public static PersistenceParseResult OverBudget { get; } =
        new(PersistenceParseStatus.NotCollected, null, null, "Not parsed: the collection's time budget ran out.") { IsOverBudget = true };

    /// <summary>For <see cref="PersistenceParseStatus.NotCollected"/>: the budget was the reason (no issue of its own is needed).</summary>
    public bool IsOverBudget { get; init; }

    public static PersistenceParseResult Malformed(string message) => new(PersistenceParseStatus.Malformed, null, null, message);

    public static PersistenceParseResult Unavailable(string message) => new(PersistenceParseStatus.Unavailable, null, null, message);

    public static PersistenceParseResult NotCollected(string message) => new(PersistenceParseStatus.NotCollected, null, null, message);
}

/// <summary>
/// Section C review H2: where the engine gets shortcuts and task definitions parsed. Never the engine itself: a real
/// implementation brokers the read-only handle to the sandboxed worker and validates what comes back
/// (<see cref="WireParsedFileCodec.FromWire(WireParsedFile, WorkerParseKind)"/>). A worker crash is a Malformed result here,
/// never an engine crash. Fake it in tests.
/// </summary>
internal interface IPersistenceFileParser
{
    /// <param name="file">The file, already opened with the hardened open (a regular local file under the size cap). Not closed here.</param>
    /// <param name="displayPath">For the crash tracking and the log only.</param>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken);

    /// <summary>
    /// C2: several files at once, one result per file in order (the sandboxed broker sends them to the worker in batches).
    /// One file's failure is that file's Malformed result. By default each file goes through <see cref="ParseAsync"/>.
    /// </summary>
    /// <param name="canContinue">The collection's budget check (review H1), asked before each request; once false, the remaining
    /// files are <see cref="PersistenceParseResult.OverBudget"/>. Null = no budget.</param>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    async Task<IReadOnlyList<PersistenceParseResult>> ParseBatchAsync(
        IReadOnlyList<PersistenceParseInput> files, Func<bool>? canContinue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(files);
        var results = new PersistenceParseResult[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            if (canContinue is not null && !canContinue())
            {
                Array.Fill(results, PersistenceParseResult.OverBudget, i, files.Count - i);
                break;
            }

            try
            {
                results[i] = await ParseAsync(files[i].File, files[i].Kind, files[i].DisplayPath, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
            {
                results[i] = PersistenceParseResult.Malformed($"The sandboxed parser failed on this file ({ex.GetType().Name})."); // review C M3
            }
        }

        return results;
    }
}

/// <summary>One file for <see cref="IPersistenceFileParser.ParseBatchAsync"/>; the caller keeps <paramref name="File"/> open and closes it.</summary>
internal sealed record PersistenceParseInput(SafeFileHandle File, WorkerParseKind Kind, string DisplayPath);

/// <summary>
/// No sandbox (InProcess debugging mode, a refused configuration, or nothing registered): nothing is parsed, so the tasks and
/// shortcuts are reported as not collected. The parsers are never called in the engine's process instead.
/// </summary>
internal sealed class UnavailablePersistenceParser(string reason) : IPersistenceFileParser
{
    public static UnavailablePersistenceParser NoSandbox { get; } =
        new("The sandboxed scan worker isn't available, so shortcuts and task definitions weren't parsed.");

    public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(PersistenceParseResult.Unavailable(reason));
    }
}
