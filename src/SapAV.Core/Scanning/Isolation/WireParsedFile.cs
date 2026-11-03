using System.Text.Json.Serialization;
using SapAV.Core.Persistence;
using SapAV.Core.Serialization;

namespace SapAV.Core.Scanning.Isolation;

/// <summary>Which parser a <see cref="WorkerParseRequest"/> asks for.</summary>
[JsonConverter(typeof(StrictEnumConverter<WorkerParseKind>))]
public enum WorkerParseKind
{
    /// <summary>A task definition file (<see cref="TaskXml"/>).</summary>
    ScheduledTask,

    /// <summary>A shell link (<see cref="ShellLinkParser"/>).</summary>
    ShellLink,
}

/// <summary>
/// Section C review H2: parse a batch of autostart definition files in the worker (C2: up to
/// <see cref="WorkerLimits.MaxParseBatch"/> files per request, so a collection pays one round trip per batch, not per
/// file). The answer is one <see cref="WireParsedFile"/> per file, in order. The engine never parses these files itself.
/// </summary>
public sealed record WorkerParseRequest
{
    /// <summary>1 to <see cref="WorkerLimits.MaxParseBatch"/> files.</summary>
    public required IReadOnlyList<WorkerParseFile> Files { get; init; }
}

/// <summary>One file of a <see cref="WorkerParseRequest"/>. The handle is a value in the worker's handle table, duplicated there read-only by the broker.</summary>
public sealed record WorkerParseFile
{
    public required WorkerParseKind Kind { get; init; }

    /// <summary>Read-only file handle (see <see cref="WorkerScanRequest.FileHandle"/>). Not owned by the worker.</summary>
    public required long FileHandle { get; init; }

    public required WorkerTestFault TestFault { get; init; }
}

/// <summary>A parsed autostart definition, worker to engine. <b>Untrusted</b>: rebuilt by <see cref="WireParsedFileCodec.FromWire"/>.</summary>
public sealed record WireParsedFile
{
    public required WorkerParseKind Kind { get; init; }

    /// <summary>Why the file isn't well-formed; then <see cref="Task"/> and <see cref="Link"/> are null.</summary>
    public required string? Error { get; init; }

    public required WireTaskDefinition? Task { get; init; }

    public required WireShellLink? Link { get; init; }
}

public sealed record WireTaskDefinition
{
    public required bool Enabled { get; init; }

    public required string? UserId { get; init; }

    public required bool Truncated { get; init; }

    public required IReadOnlyList<WireTaskAction> Actions { get; init; }
}

public sealed record WireTaskAction
{
    public required string? Command { get; init; }

    public required string? Arguments { get; init; }

    public required string? WorkingDirectory { get; init; }

    public required Guid? ComClassId { get; init; }

    public required string? ComData { get; init; }
}

public sealed record WireShellLink
{
    public required string? IdListPath { get; init; }

    public required bool IdListUnsupported { get; init; }

    public required string? LinkInfoPath { get; init; }

    public required string? LinkInfoNetworkShare { get; init; }

    public required string? EnvironmentTarget { get; init; }

    public required string? RelativePath { get; init; }

    public required string? WorkingDirectory { get; init; }

    public required string? Arguments { get; init; }

    /// <summary>A string was cut to fit the response cap, so the link can't be judged as written.</summary>
    public required bool Truncated { get; init; }
}

/// <summary>The checked result of <see cref="WireParsedFileCodec.FromWire"/>: exactly one of the three is set.</summary>
public sealed record ParsedPersistenceFile(TaskDefinitionInfo? Task, ShellLinkInfo? Link, string? Error);

/// <summary>
/// The worker's parse entry point and the engine's check of its answer. <see cref="ParseInWorker"/> runs the file parsers,
/// so <b>only the scan worker (and tests) may call it</b>. <see cref="FromWire(WireParsedFile, WorkerParseKind)"/> treats its
/// input like any worker output: kinds, counts and lengths are enforced, and anything else is a
/// <see cref="WorkerProtocolException"/> (the worker is replaced).
/// </summary>
public static class WireParsedFileCodec
{
    /// <summary>Most text in one answer: even if every character is escaped to six bytes it fits <see cref="WorkerLimits.MaxResponseBytes"/>.</summary>
    public const int MaxTotalCharacters = 32_767;

    /// <summary>Most bytes the file may have for <paramref name="kind"/>.</summary>
    public static int MaxFileBytes(WorkerParseKind kind) => kind == WorkerParseKind.ScheduledTask ? TaskXml.MaxBytes : ShellLinkParser.MaxSize;

    /// <summary>Runs the parser. Malformed input comes back as <see cref="WireParsedFile.Error"/>, not an exception.</summary>
    public static WireParsedFile ParseInWorker(WorkerParseKind kind, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        string? error;
        if (kind == WorkerParseKind.ScheduledTask)
        {
            var task = TaskXml.Parse(content, out error);
            return new WireParsedFile
            {
                Kind = kind,
                Error = task is null ? error ?? "The task file can't be parsed." : null,
                Task = task is null ? null : ToWire(task),
                Link = null,
            };
        }

        var link = ShellLinkParser.Parse(content, out error);
        return new WireParsedFile
        {
            Kind = kind,
            Error = link is null ? error ?? "The shortcut can't be parsed." : null,
            Task = null,
            Link = link is null ? null : ToWire(link),
        };
    }

    /// <summary>
    /// Rebuilds a worker's answer to a batch: exactly one answer per requested file, in order, each checked like a single
    /// answer (its kind and its own text caps). The batch's total text is therefore at most <c>files x</c>
    /// <see cref="MaxTotalCharacters"/>, which is what the batch's frame cap (<see cref="WorkerLimits.MaxParseResponseBytes"/>) allows.
    /// </summary>
    /// <exception cref="WorkerProtocolException">Any answer breaks the protocol (the whole batch is discarded).</exception>
    public static IReadOnlyList<ParsedPersistenceFile> FromWire(IReadOnlyList<WireParsedFile?> wire, IReadOnlyList<WorkerParseKind> expected)
    {
        ArgumentNullException.ThrowIfNull(wire);
        ArgumentNullException.ThrowIfNull(expected);
        Require(wire.Count == expected.Count, $"{wire.Count} answers for {expected.Count} files");
        var parsed = new ParsedPersistenceFile[wire.Count];
        for (int i = 0; i < wire.Count; i++)
        {
            Require(wire[i] is not null, "a null answer");
            parsed[i] = FromWire(wire[i]!, expected[i]);
        }

        return parsed;
    }

    /// <summary>Rebuilds a worker's answer to a <paramref name="expected"/> request.</summary>
    /// <exception cref="WorkerProtocolException">The answer breaks the protocol.</exception>
    public static ParsedPersistenceFile FromWire(WireParsedFile wire, WorkerParseKind expected)
    {
        ArgumentNullException.ThrowIfNull(wire);
        Require(wire.Kind == expected, $"a {wire.Kind} answer to a {expected} request");
        Require((wire.Error is null ? 0 : 1) + (wire.Task is null ? 0 : 1) + (wire.Link is null ? 0 : 1) == 1, "not exactly one of error, task and link");
        if (wire.Error is { } error)
        {
            Require(error.Length is > 0 and <= WorkerLimits.MaxTextLength, "an error text outside its length");
            return new ParsedPersistenceFile(null, null, error);
        }

        return wire.Task is { } task
            ? new ParsedPersistenceFile(FromWire(task), null, null)
            : new ParsedPersistenceFile(null, FromWire(wire.Link!), null);
    }

    private static WireTaskDefinition ToWire(TaskDefinitionInfo task) => new()
    {
        Enabled = task.Enabled,
        UserId = task.UserId,
        Truncated = task.Truncated,
        Actions = task.Actions.Select(a => new WireTaskAction
        {
            Command = a.Command,
            Arguments = a.Arguments,
            WorkingDirectory = a.WorkingDirectory,
            ComClassId = a.ComClassId,
            ComData = a.ComData,
        }).ToArray(),
    };

    private static WireShellLink ToWire(ShellLinkInfo link)
    {
        int left = MaxTotalCharacters;
        bool truncated = link.Truncated;
        string? Fit(string? text)
        {
            if (text is null)
            {
                return null;
            }

            int taken = Math.Min(text.Length, left);
            left -= taken;
            truncated |= taken < text.Length;
            return text[..taken];
        }

        // The fields that name the program first: arguments are what a cut may reach.
        string? environment = Fit(link.EnvironmentTarget), idList = Fit(link.IdListPath), linkInfo = Fit(link.LinkInfoPath), share = Fit(link.LinkInfoNetworkShare);
        string? relative = Fit(link.RelativePath), workingDirectory = Fit(link.WorkingDirectory), arguments = Fit(link.Arguments);
        return new WireShellLink
        {
            IdListPath = idList,
            IdListUnsupported = link.IdListUnsupported,
            LinkInfoPath = linkInfo,
            LinkInfoNetworkShare = share,
            EnvironmentTarget = environment,
            RelativePath = relative,
            WorkingDirectory = workingDirectory,
            Arguments = arguments,
            Truncated = truncated,
        };
    }

    private static TaskDefinitionInfo FromWire(WireTaskDefinition task)
    {
        Require(task.Actions.Count <= TaskXml.MaxActions, $"{task.Actions.Count} task actions");
        int total = 0;
        string? Check(string? text)
        {
            total += text?.Length ?? 0;
            Require((text?.Length ?? 0) <= TaskXml.MaxFieldLength && total <= MaxTotalCharacters, "too much task text");
            return text;
        }

        var actions = new List<TaskAction>(task.Actions.Count);
        foreach (var a in task.Actions)
        {
            Require(a is not null, "a null task action");
            Require(a!.ComClassId is null || (a.Command is null && a.Arguments is null && a.WorkingDirectory is null), "an action that is both Exec and COM");
            Require(a.ComClassId is not null || a.ComData is null, "COM data on an Exec action");
            actions.Add(new TaskAction(Check(a.Command), Check(a.Arguments), Check(a.WorkingDirectory), a.ComClassId, Check(a.ComData)));
        }

        return new TaskDefinitionInfo(task.Enabled, Check(task.UserId), actions, task.Truncated);
    }

    private static ShellLinkInfo FromWire(WireShellLink link)
    {
        int total = 0;
        string? Check(string? text)
        {
            total += text?.Length ?? 0;
            Require(total <= MaxTotalCharacters, "too much shortcut text");
            return text;
        }

        return new ShellLinkInfo(Check(link.IdListPath), link.IdListUnsupported, Check(link.LinkInfoPath), Check(link.LinkInfoNetworkShare),
            Check(link.EnvironmentTarget), Check(link.RelativePath), Check(link.WorkingDirectory), Check(link.Arguments), link.Truncated);
    }

    private static void Require(bool condition, string what)
    {
        if (!condition)
        {
            throw new WorkerProtocolException($"The parsed file has {what}.");
        }
    }
}
