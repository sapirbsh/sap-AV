using System.Text.Json.Serialization;
using SapAV.Core.Models;
using SapAV.Core.Serialization;

namespace SapAV.Core.Scanning.Isolation;

/// <summary>What a <see cref="WorkerRequest"/> asks for.</summary>
[JsonConverter(typeof(StrictEnumConverter<WorkerRequestKind>))]
public enum WorkerRequestKind
{
    /// <summary>Compile the rule files and load the blocklist in <see cref="WorkerRequest.LoadRules"/> (start and reload).</summary>
    LoadRules,

    /// <summary>Scan the file behind the handle in <see cref="WorkerRequest.Scan"/>.</summary>
    Scan,

    /// <summary>Test only: try an operation the sandbox must block (<see cref="WorkerRequest.Probe"/>).</summary>
    Probe,
}

/// <summary>One message from the broker (engine) to the worker. Exactly the body that matches <see cref="Kind"/> is set.</summary>
public sealed record WorkerRequest
{
    /// <summary>Echoed in the response, so a late or replayed response can't be matched to another request.</summary>
    public required long Id { get; init; }

    public required WorkerRequestKind Kind { get; init; }

    public required WorkerLoadRules? LoadRules { get; init; }

    public required WorkerScanRequest? Scan { get; init; }

    public required WorkerProbeRequest? Probe { get; init; }
}

/// <summary>The rule package: YARA rule files (bytes, compiled in the worker) and the blocklist file's bytes.</summary>
public sealed record WorkerLoadRules
{
    public required IReadOnlyList<WorkerRuleFile> RuleFiles { get; init; }

    /// <summary>Errors the engine hit while reading the rules directory, carried into the rule set's file errors.</summary>
    public required IReadOnlyList<string> ReadErrors { get; init; }

    /// <summary>The blocklist file content (one SHA-256 per line), or empty for no blocklist.</summary>
    public required byte[] Blocklist { get; init; }
}

/// <summary>One rule file: its name relative to the rules directory and its raw bytes.</summary>
public sealed record WorkerRuleFile
{
    public required string Name { get; init; }

    public required byte[] Content { get; init; }
}

/// <summary>Test-only faults the worker injects when its test hooks are enabled (the engine never enables them in production).</summary>
[JsonConverter(typeof(StrictEnumConverter<WorkerTestFault>))]
public enum WorkerTestFault
{
    None,

    /// <summary>The parser "crashes": the worker process fails fast.</summary>
    Crash,

    /// <summary>The parser hangs forever.</summary>
    Hang,

    /// <summary>The worker answers with bytes that aren't JSON.</summary>
    MalformedResponse,

    /// <summary>The worker answers with a frame over the response cap.</summary>
    OversizedResponse,

    /// <summary>The worker answers with valid JSON of the wrong shape.</summary>
    WrongSchemaResponse,

    /// <summary>The worker answers with a response for another request ID.</summary>
    WrongIdResponse,

    /// <summary>The worker answers normally, then writes an extra frame nobody asked for (review L3).</summary>
    TrailingFrame,
}

/// <summary>Scan one file. The handles are values <b>in the worker's handle table</b>, duplicated there by the broker.</summary>
public sealed record WorkerScanRequest
{
    /// <summary>The file as the engine scans it (the path is for names, heuristics and messages; the worker never opens it).</summary>
    public required ScanItem Item { get; init; }

    /// <summary>Read-only file handle (FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE). Not owned by the worker.</summary>
    public required long FileHandle { get; init; }

    /// <summary>Read-only <c>Zone.Identifier</c> stream handle, or null if the broker couldn't open it.</summary>
    public required long? StreamHandle { get; init; }

    /// <summary>The broker's Win32 error for the stream open when <see cref="StreamHandle"/> is null (2 = no stream).</summary>
    public required int StreamOpenError { get; init; }

    public required WorkerTestFault TestFault { get; init; }
}

/// <summary>Test-only sandbox probes (each must fail inside the sandbox).</summary>
[JsonConverter(typeof(StrictEnumConverter<WorkerProbeKind>))]
public enum WorkerProbeKind
{
    /// <summary>TCP connect to 127.0.0.1:<see cref="WorkerProbeRequest.Port"/>.</summary>
    ConnectTcp,

    /// <summary>Open <see cref="WorkerProbeRequest.Path"/> for reading by path.</summary>
    OpenPath,

    /// <summary>Write one byte through <see cref="WorkerProbeRequest.Handle"/>.</summary>
    WriteHandle,

    /// <summary>Mark the file behind <see cref="WorkerProbeRequest.Handle"/> for deletion.</summary>
    DeleteViaHandle,

    /// <summary>Start a child process (<c>cmd.exe /c exit</c>).</summary>
    SpawnProcess,

    /// <summary>Create a file in <see cref="WorkerProbeRequest.Path"/> (a directory).</summary>
    CreateFileIn,
}

public sealed record WorkerProbeRequest
{
    public required WorkerProbeKind Kind { get; init; }

    public required string? Path { get; init; }

    public required int Port { get; init; }

    public required long Handle { get; init; }
}

/// <summary>What a <see cref="WorkerResponse"/> carries.</summary>
[JsonConverter(typeof(StrictEnumConverter<WorkerResponseKind>))]
public enum WorkerResponseKind
{
    RulesLoaded,
    Scanned,
    Probed,

    /// <summary>The worker could not handle the request (<see cref="WorkerResponse.Error"/>); the file is NotScanned.</summary>
    Failed,
}

/// <summary>One message from the worker to the broker. <b>Untrusted</b>: the engine validates every field.</summary>
public sealed record WorkerResponse
{
    public required long Id { get; init; }

    public required WorkerResponseKind Kind { get; init; }

    public required WorkerRulesSummary? Rules { get; init; }

    public required WireScanReport? Report { get; init; }

    public required WorkerProbeResult? Probe { get; init; }

    public required string? Error { get; init; }
}

/// <summary>What the worker loaded (for the engine's log and its "no rules loaded" warning, B3 M5).</summary>
public sealed record WorkerRulesSummary
{
    public required int RuleCount { get; init; }

    public required int FileErrorCount { get; init; }

    public required int WarningCount { get; init; }

    public required string Fingerprint { get; init; }

    public required int BlocklistCount { get; init; }

    public required int BlocklistErrorCount { get; init; }

    /// <summary>The first <see cref="WorkerLimits.MaxRuleErrors"/> file errors, one line each.</summary>
    public required IReadOnlyList<string> FileErrors { get; init; }
}

public sealed record WorkerProbeResult
{
    public required bool Succeeded { get; init; }

    public required int Win32Error { get; init; }

    public required string Detail { get; init; }
}
