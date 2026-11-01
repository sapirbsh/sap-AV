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
}

/// <param name="Message">Why, for anything but Parsed.</param>
internal sealed record PersistenceParseResult(PersistenceParseStatus Status, TaskDefinitionInfo? Task, ShellLinkInfo? Link, string? Message)
{
    public static PersistenceParseResult Malformed(string message) => new(PersistenceParseStatus.Malformed, null, null, message);

    public static PersistenceParseResult Unavailable(string message) => new(PersistenceParseStatus.Unavailable, null, null, message);
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
}

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
