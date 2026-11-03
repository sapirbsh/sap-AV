using Microsoft.Win32.SafeHandles;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Signatures;
using SapAV.Core.Text;
using SapAV.Core.Yara;

namespace SapAV.ScanWorker;

/// <summary>
/// Handles one request at a time: loads the rule package, scans a brokered file handle through the real
/// <see cref="FileScanner"/> pipeline, or (test hooks only) runs a sandbox probe.
/// </summary>
internal sealed class WorkerService(bool testHooksEnabled) : IDisposable
{
    private readonly Sha256Hasher _hasher = new();
    private readonly AuthenticodeVerifier _signatures = new();
    private readonly FileHeuristics _heuristics = new();
    private YaraScanner? _yara;
    private HashBlocklist _blocklist = HashBlocklist.Empty;

    public bool TestHooksEnabled { get; } = testHooksEnabled;

    public async Task<WorkerResponse> HandleAsync(WorkerRequest request)
    {
        try
        {
            return request.Kind switch
            {
                WorkerRequestKind.LoadRules when request.LoadRules is { } rules => await LoadRulesAsync(request.Id, rules).ConfigureAwait(false),
                WorkerRequestKind.Scan when request.Scan is { } scan => await ScanAsync(request.Id, scan).ConfigureAwait(false),
                WorkerRequestKind.Parse when request.Parse is { } parse => Parse(request.Id, parse),
                WorkerRequestKind.Probe when request.Probe is { } probe => Probe(request.Id, probe),
                _ => Failed(request.Id, $"The {request.Kind} request has no matching body."),
            };
        }
        catch (Exception ex)
        {
            // Any parser exception: the file is NotScanned (Error) on the engine side. A native crash kills the process.
            return Failed(request.Id, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    public static WorkerResponse Failed(long id, string error) => new()
    {
        Id = id,
        Kind = WorkerResponseKind.Failed,
        Rules = null,
        Report = null,
        Probe = null,
        Parsed = null,
        Error = SafeText.SingleLine(error, WorkerLimits.MaxTextLength) is { Length: > 0 } e ? e : "error",
    };

    private async Task<WorkerResponse> LoadRulesAsync(long id, WorkerLoadRules package)
    {
        var readErrors = package.ReadErrors.Select(e => new YaraRuleFileError("(engine)", [e]));
        var rules = YaraRuleSet.FromFiles(package.RuleFiles.Select(f => new YaraRuleFile(f.Name, f.Content)), readErrors);
        var blocklist = package.Blocklist.Length == 0
            ? HashBlocklist.Empty
            : await HashBlocklist.LoadAsync(new MemoryStream(package.Blocklist, writable: false)).ConfigureAwait(false);

        if (_yara is null)
        {
            _yara = new YaraScanner(rules);
        }
        else
        {
            _yara.SwapRules(rules).Dispose();
        }

        _blocklist = blocklist;
        return new WorkerResponse
        {
            Id = id,
            Kind = WorkerResponseKind.RulesLoaded,
            Rules = new WorkerRulesSummary
            {
                RuleCount = rules.Rules.Count,
                FileErrorCount = rules.FileErrors.Count,
                WarningCount = rules.Warnings.Count,
                Fingerprint = rules.Fingerprint,
                BlocklistCount = blocklist.Count,
                BlocklistErrorCount = blocklist.TotalErrorCount,
                FileErrors = rules.FileErrors.Take(WorkerLimits.MaxRuleErrors)
                    .Select(e => SafeText.SingleLine(e.ToString(), WorkerLimits.MaxTextLength)).ToArray(),
            },
            Report = null,
            Probe = null,
            Parsed = null,
            Error = null,
        };
    }

    private async Task<WorkerResponse> ScanAsync(long id, WorkerScanRequest scan)
    {
        if (scan.TestFault != WorkerTestFault.None)
        {
            if (!TestHooksEnabled)
            {
                return Failed(id, "Test faults are disabled in this worker.");
            }

            TestHooks.Inject(scan.TestFault);
            if (scan.TestFault == WorkerTestFault.KeepHandleCopy)
            {
                TestHooks.KeepCopy(scan.FileHandle);
            }
            else if (scan.TestFault == WorkerTestFault.KeepHandleCopyCloseDummy)
            {
                TestHooks.KeepCopyCloseDummy(scan.FileHandle);
            }
        }

        if (_yara is null)
        {
            return Failed(id, "No rules are loaded yet.");
        }

        // The broker owns these handle values (it closes them in this process after the response): not owned here.
        using var file = new SafeFileHandle((IntPtr)scan.FileHandle, ownsHandle: false);
        using var stream = scan.StreamHandle is { } s ? new SafeFileHandle((IntPtr)s, ownsHandle: false) : null;
        var blocklist = _blocklist;
        var scanner = new FileScanner(_hasher, () => blocklist, _signatures, _yara,
            new Core.Motw.BrokeredMarkOfTheWebReader(stream, scan.StreamOpenError), _heuristics);

        var report = await scanner.ScanHandleAsync(scan.Item, file).ConfigureAwait(false);
        return new WorkerResponse
        {
            Id = id,
            Kind = WorkerResponseKind.Scanned,
            Rules = null,
            Report = WireReportCodec.ToWire(report),
            Probe = null,
            Parsed = null,
            Error = null,
        };
    }

    /// <summary>
    /// Review C H2: parses brokered shortcuts and task definitions here, never in the engine. C2: a batch, one answer per
    /// file in order; one file's problem (over the cap, a read error, a parser exception) is that file's error answer.
    /// </summary>
    private WorkerResponse Parse(long id, WorkerParseRequest parse)
    {
        if (parse.Files is not { Count: > 0 and <= WorkerLimits.MaxParseBatch } files)
        {
            return Failed(id, $"A parse request needs 1 to {WorkerLimits.MaxParseBatch} files.");
        }

        if (files.Any(f => f is null))
        {
            return Failed(id, "A parse request has a null file.");
        }

        if (!TestHooksEnabled && files.Any(f => f.TestFault != WorkerTestFault.None))
        {
            return Failed(id, "Test faults are disabled in this worker.");
        }

        var answers = new WireParsedFile?[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            answers[i] = ParseOne(files[i]);
        }

        return new WorkerResponse
        {
            Id = id,
            Kind = WorkerResponseKind.Parsed,
            Rules = null,
            Report = null,
            Probe = null,
            Parsed = answers,
            Error = null,
        };
    }

    private static WireParsedFile ParseOne(WorkerParseFile parse)
    {
        if (parse.TestFault != WorkerTestFault.None)
        {
            TestHooks.Inject(parse.TestFault);
            if (parse.TestFault == WorkerTestFault.KeepHandleCopy)
            {
                TestHooks.KeepCopy(parse.FileHandle);
            }
        }

        try
        {
            return Read(parse) is { } content
                ? WireParsedFileCodec.ParseInWorker(parse.Kind, content)
                : ParseError(parse.Kind, $"The file is over the {WireParsedFileCodec.MaxFileBytes(parse.Kind)}-byte cap.");
        }
        catch (Exception ex)
        {
            return ParseError(parse.Kind, $"The sandboxed parser refused the file: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static WireParsedFile ParseError(WorkerParseKind kind, string error) => new()
    {
        Kind = kind,
        Error = SafeText.SingleLine(error, WorkerLimits.MaxTextLength) is { Length: > 0 } e ? e : "error",
        Task = null,
        Link = null,
    };

    /// <summary>The file's bytes, or null when it is over the cap for its kind.</summary>
    private static byte[]? Read(WorkerParseFile parse)
    {
        // Not owned here: the broker closes this handle value in this process after the response.
        using var file = new SafeFileHandle((IntPtr)parse.FileHandle, ownsHandle: false);
        long length = RandomAccess.GetLength(file);
        if (length > WireParsedFileCodec.MaxFileBytes(parse.Kind))
        {
            return null;
        }

        var content = new byte[length];
        int read = 0;
        while (read < content.Length)
        {
            int n = RandomAccess.Read(file, content.AsSpan(read), read);
            if (n <= 0)
            {
                break;
            }

            read += n;
        }

        return read == content.Length ? content : content[..read];
    }

    private WorkerResponse Probe(long id, WorkerProbeRequest probe)
    {
        if (!TestHooksEnabled)
        {
            return Failed(id, "Probes are disabled in this worker.");
        }

        return new WorkerResponse
        {
            Id = id,
            Kind = WorkerResponseKind.Probed,
            Rules = null,
            Report = null,
            Probe = SandboxProbes.Run(probe),
            Parsed = null,
            Error = null,
        };
    }

    public void Dispose() => _yara?.Rules.Dispose();
}
