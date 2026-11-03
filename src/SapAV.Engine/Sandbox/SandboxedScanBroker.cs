using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Persistence;
using Microsoft.Extensions.Logging;
using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Text;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// The B5 broker: the engine side of privilege separation. For each file it
/// <list type="number">
/// <item>opens the file itself with the hardened open (<see cref="ScanFileOpener"/>: writers denied, USN fallback),
/// captures its <see cref="FileIdentity"/>, and opens the <c>Zone.Identifier</c> stream relative to that handle;</item>
/// <item>duplicates both handles <b>read-only</b> into a sandboxed worker and sends a small scan request;</item>
/// <item>reads the response with the size cap, rebuilds the report with <see cref="WireReportCodec.FromWire"/> (untrusted
/// input: strict schema, caps, cross-checks), and sets Identity, item and timestamp from its own data;</item>
/// <item>closes the handles in the worker again, and runs the shared-fallback change-journal check.</item>
/// </list>
/// The engine never reads file content. Supervision: a crash, hang (request timeout) or protocol violation kills that
/// worker (it restarts with backoff) and the file is NotScanned (Error); a file version that does that
/// <see cref="SandboxOptions.MaxFailuresPerFile"/> times is reported Suspicious (T1211) and not sent to a worker again.
/// Worker death never throws out of <see cref="ScanAsync"/>; only the caller's own cancellation does.
/// </summary>
internal sealed class SandboxedScanBroker : IScanBroker, Persistence.IPersistenceFileParser, IDisposable
{
    private readonly SandboxOptions _options;
    private readonly IScanRulesSource _rulesSource;
    private readonly IOnlineHashLookup? _online;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly WorkerSlot[] _slots;
    private readonly PrioritySlotPool<WorkerSlot> _idle;
    private readonly FileFailureTracker _failures;
    private readonly SemaphoreSlim _packageLock = new(1, 1);
    private RulePackage? _package;
    private RulesLoadSummary? _rules;
    private string? _lastError;
    private int _restarts;

    public SandboxedScanBroker(SandboxOptions options, IScanRulesSource rulesSource, ILogger logger, TimeProvider? time = null, IOnlineHashLookup? online = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _rulesSource = rulesSource ?? throw new ArgumentNullException(nameof(rulesSource));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = time ?? TimeProvider.System;
        _online = online;
        _failures = new FileFailureTracker(_time);

        var launcher = new WorkerLauncher(options, logger);
        _slots = Enumerable.Range(0, options.WorkerCount).Select(i => new WorkerSlot(i, launcher, options, _time, logger)
        {
            OnWorkerLost = why =>
            {
                Interlocked.Increment(ref _restarts);
                _lastError = why;
            },
        }).ToArray();
        _idle = new PrioritySlotPool<WorkerSlot>(_slots); // review B H3: engine work first, one worker kept from user jobs

        if (options.Isolation != WorkerIsolation.AppContainer)
        {
            logger.LogWarning("Scan workers run WITHOUT the AppContainer (test-only isolation mode).");
        }
    }

    /// <summary>Test seam: a fault for the worker to inject while scanning this item (honored only with worker test hooks).</summary>
    internal Func<ScanItem, WorkerTestFault>? FaultInjector { get; set; }

    /// <summary>Test seam: a fault for the worker to inject while parsing this path (honored only with worker test hooks).</summary>
    internal Func<string, WorkerTestFault>? ParseFaultInjector { get; set; }

    /// <summary>Test seam: failures recorded against files (scans and parses).</summary>
    internal int RecordedFailures => _failures.Total;

    /// <summary>Test seam: the pool.</summary>
    internal IReadOnlyList<WorkerSlot> Slots => _slots;

    public SandboxStatus Status =>
        new(SandboxMode.AppContainer, _slots.Count(s => s.IsRunning), Volatile.Read(ref _restarts), _rules, _lastError);

    public async Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<ScanNote>();

        using var opened = Scanning.SafeScanOpen.Open(item, notes, _time, out var failureReport); // review B H2: never a following open
        if (opened is null)
        {
            return failureReport!;
        }

        return await ScanOpenedAsync(item, opened, notes, cancellationToken).ConfigureAwait(false);
    }

    public Task<FileScanReport> ScanOpenedAsync(
        ScanItem item, OpenedScanFile opened, IReadOnlyList<ScanNote> openNotes, CancellationToken cancellationToken = default) =>
        ScanOpenedAsync(item, opened, openNotes, ScanPriority.Normal, cancellationToken);

    public async Task<FileScanReport> ScanOpenedAsync(
        ScanItem item, OpenedScanFile opened, IReadOnlyList<ScanNote> openNotes, ScanPriority priority, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(opened);
        ArgumentNullException.ThrowIfNull(openNotes);
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<ScanNote>(openNotes);

        string key = FailureKey(item.Path, opened.Handle, opened.Identity);
        if (_failures.Count(key) is var previous && previous >= _options.MaxFailuresPerFile)
        {
            return CrashedTheEngine(item, opened, notes, previous, "seen before; not sent to a worker again");
        }

        var package = await CurrentPackageAsync(cancellationToken).ConfigureAwait(false);
        var slot = await RentAsync(priority, cancellationToken).ConfigureAwait(false);
        try
        {
            WorkerProcess worker;
            try
            {
                worker = await slot.EnsureReadyAsync(package, cancellationToken).ConfigureAwait(false);
            }
            catch (WorkerRequestException ex)
            {
                _lastError = ex.Message;
                return NotScanned(item, opened, notes, $"The sandboxed scan worker is unavailable: {ex.Message}");
            }

            WorkerResponse response;
            try
            {
                response = await ScanInWorkerAsync(slot, worker, item, opened, cancellationToken).ConfigureAwait(false);
            }
            catch (WorkerRequestException ex) when (ex.Kind == WorkerFailureKind.Unavailable)
            {
                _lastError = ex.Message; // the worker is to blame (or unknown), not the file: not counted
                return NotScanned(item, opened, notes, ex.Message);
            }
            catch (WorkerRequestException ex)
            {
                return FileFailed(item, opened, notes, key, ex.Kind.ToString(), ex.Message);
            }
            catch (Win32Exception ex)
            {
                // The worker went away between the start check and the handle duplication: not the file's fault.
                slot.Kill();
                return NotScanned(item, opened, notes, $"The scan worker could not receive the file handle: {ex.Message}");
            }

            if (response.Kind == WorkerResponseKind.Failed)
            {
                slot.Succeeded(); // the worker survived and said so
                slot.CountFileAndMaybeRecycle();
                return NotScanned(item, opened, notes, $"The scan worker could not scan the file: {SafeText.SingleLine(response.Error ?? "?", WorkerLimits.MaxTextLength)}");
            }

            FileScanReport report;
            try
            {
                report = WireReportCodec.FromWire(response.Report!, item, _time.GetUtcNow());
            }
            catch (WorkerProtocolException ex)
            {
                slot.Kill(); // never reuse a worker that sent bad content
                return FileFailed(item, opened, notes, key, "ProtocolViolation", ex.Message);
            }

            slot.Succeeded();
            slot.CountFileAndMaybeRecycle();
            notes.AddRange(report.Notes);
            report = report with { Identity = opened.Identity, Notes = notes.AsReadOnly() };
            report = await OnlineLookupAsync(report, cancellationToken).ConfigureAwait(false);
            return ScanFileOpener.VerifyUnchanged(opened, report, notes, _time);
        }
        finally
        {
            slot.Lock.Release();
            _idle.Return(slot, priority);
        }
    }

    /// <summary>One file: a batch of one (see <see cref="ParseBatchAsync"/>).</summary>
    public async Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken) =>
        (await ParseBatchAsync([new PersistenceParseInput(file, kind, displayPath)], null, cancellationToken).ConfigureAwait(false))[0];

    /// <summary>A batch whose request failed retries its files alone, but stops after this many of them failed too.</summary>
    internal const int MaxSoloFailuresPerBatch = 2;

    /// <summary>
    /// Section C review H2 + C2: shortcuts and task definitions through the worker, up to <see cref="WorkerLimits.MaxParseBatch"/>
    /// per request, each on a read-only duplicate of its handle. The answers are validated like any worker output, and the
    /// kept-handle check runs once per request over all of its handles. A crash, hang or broken answer replaces the worker;
    /// a batch that does that is retried one file at a time, so only the file to blame gets a Malformed result, and a
    /// file version that fails alone <see cref="SandboxOptions.MaxFailuresPerFile"/> times isn't sent again. Only "no
    /// worker at all" is Unavailable (the files aren't to blame).
    /// </summary>
    /// <remarks>
    /// Review H1: <paramref name="canContinue"/> (the collection's budgets) is asked before every request, solo retries
    /// included, and the solo pass of one batch stops after <see cref="MaxSoloFailuresPerBatch"/> failures. Files that aren't
    /// sent for either reason are <see cref="PersistenceParseStatus.NotCollected"/>, never counted as failures.
    /// </remarks>
    public async Task<IReadOnlyList<PersistenceParseResult>> ParseBatchAsync(
        IReadOnlyList<PersistenceParseInput> files, Func<bool>? canContinue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(files);
        cancellationToken.ThrowIfCancellationRequested();
        var results = new PersistenceParseResult?[files.Count];
        var send = new List<ParseItem>(files.Count);
        for (int i = 0; i < files.Count; i++)
        {
            var input = files[i];
            if (input?.File is null || input.DisplayPath is null)
            {
                throw new ArgumentException($"File {i} of the batch has no handle or no path.", nameof(files));
            }

            string key = "parse:" + FailureKey(input.DisplayPath, input.File, FileIdentity.TryCapture(input.File));
            if (_failures.Count(key) is var previous && previous >= _options.MaxFailuresPerFile)
            {
                results[i] = PersistenceParseResult.Malformed($"This file crashed or hung the sandboxed parser {previous} times; it is not sent to a worker again.");
            }
            else
            {
                send.Add(new ParseItem(i, input, key));
            }
        }

        var gate = new BudgetGate(canContinue);
        foreach (var chunk in send.Chunk(WorkerLimits.MaxParseBatch))
        {
            await ParseChunkAsync(chunk, results, gate, cancellationToken).ConfigureAwait(false);
        }

        return results!;
    }

    /// <summary>A file of a parse batch: its place in the caller's list, the input, and its failure-tracking key.</summary>
    private sealed record ParseItem(int Index, PersistenceParseInput Input, string Key);

    /// <summary>What one parse request came to: per-file results, or why the whole request failed.</summary>
    private sealed record BatchOutcome(IReadOnlyList<PersistenceParseResult>? Results, string? Unavailable, string? Refused, WorkerRequestException? Failure);

    /// <summary>The caller's budget check; once it said no, it stays no for this call.</summary>
    private sealed class BudgetGate(Func<bool>? canContinue)
    {
        private bool _closed;

        public bool Open
        {
            get
            {
                if (!_closed && canContinue is not null && !canContinue())
                {
                    _closed = true;
                }

                return !_closed;
            }
        }
    }

    /// <returns>How many of the chunk's files were recorded as failures.</returns>
    private async Task<int> ParseChunkAsync(IReadOnlyList<ParseItem> chunk, PersistenceParseResult?[] results, BudgetGate gate, CancellationToken cancellationToken)
    {
        if (!gate.Open)
        {
            NotCollected(chunk, 0, results, PersistenceParseResult.OverBudget);
            return 0;
        }

        var outcome = await SendBatchAsync(chunk, cancellationToken).ConfigureAwait(false);
        if (outcome.Results is { } parsed)
        {
            for (int k = 0; k < chunk.Count; k++)
            {
                results[chunk[k].Index] = parsed[k];
            }

            return 0;
        }

        if (outcome.Unavailable is { } why)
        {
            NotCollected(chunk, 0, results, PersistenceParseResult.Unavailable(why));
            return 0;
        }

        if (chunk.Count == 1)
        {
            var item = chunk[0];
            if (outcome.Failure is { } failure)
            {
                results[item.Index] = ParseFailed(item.Key, item.Input.DisplayPath, failure.Kind.ToString(), failure.Message);
                return 1;
            }

            results[item.Index] = PersistenceParseResult.Malformed($"The sandboxed parser refused the file: {outcome.Refused}");
            return 0;
        }

        // The batch can't say which file was to blame: each file again on its own, so only that one is a Malformed result.
        _logger.LogWarning("A batch of {Count} definition files failed in the sandboxed parser ({Why}); parsing them one at a time.",
            chunk.Count, outcome.Failure?.Message ?? outcome.Refused);
        int failed = 0;
        for (int k = 0; k < chunk.Count; k++)
        {
            if (failed >= MaxSoloFailuresPerBatch)
            {
                NotCollected(chunk, k, results, PersistenceParseResult.NotCollected(
                    $"Not parsed: {failed} other files of its batch broke the sandboxed parser, so the rest of the batch was skipped."));
                break;
            }

            failed += await ParseChunkAsync([chunk[k]], results, gate, cancellationToken).ConfigureAwait(false);
            if (results[chunk[k].Index]!.Status is PersistenceParseStatus.Unavailable or PersistenceParseStatus.NotCollected)
            {
                NotCollected(chunk, k + 1, results, results[chunk[k].Index]!);
                break;
            }
        }

        return failed;
    }

    private static void NotCollected(IReadOnlyList<ParseItem> chunk, int from, PersistenceParseResult?[] results, PersistenceParseResult result)
    {
        for (int k = from; k < chunk.Count; k++)
        {
            results[chunk[k].Index] = result;
        }
    }

    private async Task<BatchOutcome> SendBatchAsync(IReadOnlyList<ParseItem> chunk, CancellationToken cancellationToken)
    {
        RulePackage package;
        try
        {
            package = await CurrentPackageAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            _lastError = ex.Message;
            return new(null, $"The scan worker's rules can't be loaded ({ex.GetType().Name}).", null, null);
        }

        var slot = await RentAsync(ScanPriority.High, cancellationToken).ConfigureAwait(false);
        try
        {
            WorkerProcess worker;
            try
            {
                worker = await slot.EnsureReadyAsync(package, cancellationToken).ConfigureAwait(false);
            }
            catch (WorkerRequestException ex)
            {
                _lastError = ex.Message;
                return new(null, $"The sandboxed scan worker is unavailable: {ex.Message}", null, null);
            }

            return await ParseInWorkerAsync(slot, worker, chunk, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            slot.Lock.Release();
            _idle.Return(slot, ScanPriority.High);
        }
    }

    private async Task<BatchOutcome> ParseInWorkerAsync(WorkerSlot slot, WorkerProcess worker, IReadOnlyList<ParseItem> chunk, CancellationToken cancellationToken)
    {
        var remotes = new IntPtr[chunk.Count];
        try
        {
            WorkerResponse response;
            try
            {
                var files = new WorkerParseFile[chunk.Count];
                for (int k = 0; k < chunk.Count; k++)
                {
                    remotes[k] = worker.DuplicateInto(chunk[k].Input.File, WorkerProcess.ReadOnlyFileAccess);
                    files[k] = new WorkerParseFile
                    {
                        Kind = chunk[k].Input.Kind,
                        FileHandle = remotes[k],
                        TestFault = ParseFaultInjector?.Invoke(chunk[k].Input.DisplayPath) ?? WorkerTestFault.None,
                    };
                }

                response = await slot.ParseAsync(new WorkerParseRequest { Files = files }, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (!worker.HasExited)
                {
                    foreach (var remote in remotes)
                    {
                        worker.CloseInWorker(remote);
                    }
                }
            }

            // Review M-A, once per request: every brokered handle must be back to the broker's own one.
            switch (BrokeredHandles.Check(chunk.Select(c => (SafeHandle?)c.Input.File).ToArray()))
            {
                case BrokeredHandleState.StillHeld:
                    slot.Discard($"worker {slot.Index} kept a copy of a brokered file handle");
                    throw new WorkerRequestException(WorkerFailureKind.ProtocolViolation, "The scan worker kept a copy of a file handle; its answer was discarded.");

                case BrokeredHandleState.Unknown:
                    slot.Discard($"worker {slot.Index}: the brokered handles could not be checked");
                    throw new WorkerRequestException(WorkerFailureKind.Unavailable, "The brokered file handles could not be checked; the worker's answer was discarded.");
            }

            if (response.Kind == WorkerResponseKind.Failed)
            {
                slot.Succeeded(); // the worker survived and said so
                slot.CountFileAndMaybeRecycle(chunk.Count);
                return new(null, null, SafeText.SingleLine(response.Error ?? "?", WorkerLimits.MaxTextLength), null);
            }

            IReadOnlyList<ParsedPersistenceFile> parsed;
            try
            {
                parsed = WireParsedFileCodec.FromWire(response.Parsed!, chunk.Select(c => c.Input.Kind).ToArray());
            }
            catch (WorkerProtocolException ex)
            {
                slot.Kill(); // never reuse a worker that sent bad content
                return new(null, null, null, new WorkerRequestException(WorkerFailureKind.ProtocolViolation, ex.Message, ex));
            }

            slot.Succeeded();
            slot.CountFileAndMaybeRecycle(chunk.Count);
            return new(parsed.Select(p => p.Error is { } error
                ? PersistenceParseResult.Malformed(SafeText.SingleLine(error, WorkerLimits.MaxTextLength))
                : new PersistenceParseResult(PersistenceParseStatus.Parsed, p.Task, p.Link, null)).ToArray(), null, null, null);
        }
        catch (WorkerRequestException ex) when (ex.Kind == WorkerFailureKind.Unavailable)
        {
            _lastError = ex.Message; // the worker is to blame (or unknown), not the files
            return new(null, ex.Message, null, null);
        }
        catch (WorkerRequestException ex)
        {
            return new(null, null, null, ex);
        }
        catch (Win32Exception ex)
        {
            slot.Kill(); // the worker went away between the start check and the duplication: not the files' fault
            return new(null, $"The scan worker could not receive the file handle: {ex.Message}", null, null);
        }
    }

    private PersistenceParseResult ParseFailed(string key, string displayPath, string kind, string message)
    {
        int count = _failures.Record(key);
        _lastError = message;
        _logger.LogWarning("Parsing {Path} failed in the sandboxed worker ({Kind}, {Count}/{Max}): {Message}", displayPath, kind, count, _options.MaxFailuresPerFile, message);
        return PersistenceParseResult.Malformed($"The sandboxed parser failed on this file ({kind}, {count} time(s)): {message}");
    }

    public async Task<RulesLoadSummary?> ReloadRulesAsync(CancellationToken cancellationToken = default)
    {
        var rules = await _rulesSource.LoadAsync(cancellationToken).ConfigureAwait(false);
        RulePackage package;
        await _packageLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            package = new RulePackage((_package?.Generation ?? 0) + 1, rules);
            _package = package;
        }
        finally
        {
            _packageLock.Release();
        }

        // Every worker gets the new package now (busy ones right after their current file).
        RulesLoadSummary? summary = null;
        foreach (var slot in _slots)
        {
            await slot.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await slot.EnsureReadyAsync(package, cancellationToken).ConfigureAwait(false);
                summary ??= Summarize(slot.LastRules);
            }
            catch (WorkerRequestException ex)
            {
                _lastError = ex.Message;
                _logger.LogError("Scan worker {Index} could not load the rules: {Reason}", slot.Index, ex.Message);
            }
            finally
            {
                slot.Lock.Release();
            }
        }

        if (summary is not null)
        {
            _rules = summary;
            LogRules(_logger, summary, rules.ReadErrors);
        }

        return summary;
    }

    public void Dispose()
    {
        foreach (var slot in _slots)
        {
            slot.Dispose();
        }

        _packageLock.Dispose();
    }

    internal static void LogRules(ILogger logger, RulesLoadSummary summary, IReadOnlyList<string> readErrors)
    {
        if (summary.RuleCount == 0)
        {
            logger.LogWarning("No YARA rules are loaded: YARA can't detect anything until rules load.");
        }

        foreach (var error in summary.FileErrors)
        {
            logger.LogWarning("YARA rule file problem: {Error}", error);
        }

        logger.LogInformation("Rules loaded: {Rules} YARA rules ({Warnings} warnings, {Errors} file errors, {ReadErrors} read errors), " +
            "{Hashes} blocklist hashes ({BadLines} bad lines); fingerprint {Fingerprint}.",
            summary.RuleCount, summary.WarningCount, summary.FileErrors.Count, readErrors.Count, summary.BlocklistCount,
            summary.BlocklistErrorCount, summary.Fingerprint);
    }

    private static RulesLoadSummary? Summarize(WorkerRulesSummary? rules) =>
        rules is null ? null : new RulesLoadSummary(
            Math.Max(0, rules.RuleCount),
            (rules.FileErrors ?? []).Take(WorkerLimits.MaxRuleErrors).Select(e => SafeText.SingleLine(e ?? "?", WorkerLimits.MaxTextLength)).ToArray(),
            Math.Max(0, rules.WarningCount),
            SafeText.SingleLine(rules.Fingerprint ?? "?", 128),
            Math.Max(0, rules.BlocklistCount),
            Math.Max(0, rules.BlocklistErrorCount));

    private async Task<WorkerResponse> ScanInWorkerAsync(
        WorkerSlot slot, WorkerProcess worker, ScanItem item, OpenedScanFile opened, CancellationToken cancellationToken)
    {
        // MOTW: the broker opens the stream relative to its own handle; the worker can't (no access to user files).
        using var stream = NativeFile.OpenStreamRelative(opened.Handle, ":Zone.Identifier", out int streamError);
        IntPtr remoteFile = IntPtr.Zero, remoteStream = IntPtr.Zero;
        WorkerResponse response;
        try
        {
            remoteFile = worker.DuplicateInto(opened.Handle, WorkerProcess.ReadOnlyFileAccess);
            if (stream is not null)
            {
                remoteStream = worker.DuplicateInto(stream, WorkerProcess.ReadOnlyFileAccess);
            }

            var request = new WorkerScanRequest
            {
                Item = item,
                FileHandle = remoteFile,
                StreamHandle = stream is null ? null : remoteStream,
                StreamOpenError = stream is null ? streamError : 0,
                TestFault = FaultInjector?.Invoke(item) ?? WorkerTestFault.None,
            };
            response = await slot.ScanAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (!worker.HasExited)
            {
                worker.CloseInWorker(remoteFile);
                worker.CloseInWorker(remoteStream);
            }
        }

        // Review M-A: a (compromised) worker could keep its own copy of a brokered handle, so the file stays readable and
        // writer-blocked after the answer. The broker's handles are the only legitimate ones on these file objects, so
        // once the worker's copies are closed the kernel's system-wide handle count on each object must be exactly 1.
        // Counting the worker's own handles could be gamed (close a dummy to stay flat) and enumerating them races.
        switch (BrokeredHandles.Check(opened.Handle, stream))
        {
            case BrokeredHandleState.StillHeld:
                slot.Discard($"worker {slot.Index} kept a copy of a brokered file handle");
                throw new WorkerRequestException(WorkerFailureKind.ProtocolViolation,
                    "The scan worker kept a copy of the file handle after answering; it was killed and its answer discarded.");

            case BrokeredHandleState.Unknown:
                slot.Discard($"worker {slot.Index}: the brokered handles could not be checked");
                throw new WorkerRequestException(WorkerFailureKind.Unavailable,
                    "The brokered file handles could not be checked after the scan; the worker was replaced and its answer discarded.");
        }

        return response;
    }

    private async Task<RulePackage> CurrentPackageAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _package) is { } package)
        {
            return package;
        }

        await _packageLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return _package ??= new RulePackage(1, await _rulesSource.LoadAsync(cancellationToken).ConfigureAwait(false));
        }
        finally
        {
            _packageLock.Release();
        }
    }

    private async Task<WorkerSlot> RentAsync(ScanPriority priority, CancellationToken cancellationToken)
    {
        var slot = await _idle.RentAsync(priority, cancellationToken).ConfigureAwait(false);
        try
        {
            await slot.Lock.WaitAsync(cancellationToken).ConfigureAwait(false); // a reload may hold it briefly
            return slot;
        }
        catch
        {
            _idle.Return(slot, priority);
            throw;
        }
    }

    /// <summary>D2 seam, same rule as <see cref="FileScanner"/>: only scanned, hashed, not trusted-signed, not blocklisted.</summary>
    private async Task<FileScanReport> OnlineLookupAsync(FileScanReport report, CancellationToken cancellationToken)
    {
        var result = report.Result;
        if (_online is null || result.Status != ScanStatus.Scanned || result.Sha256 is null || report.Signature?.IsTrusted == true
            || result.Detections.Any(d => d.Source == DetectionSource.Blocklist))
        {
            return report;
        }

        var online = await _online.LookupAsync(
            new OnlineLookupRequest(result.Item, result.Sha256, result.SignatureStatus, result.Verdict ?? Verdict.Clean), cancellationToken).ConfigureAwait(false);
        return online is null
            ? report
            : report with
            {
                Result = new ScanResult(result.Item, [.. result.Detections, online], result.Timestamp, result.Sha256, result.Status,
                    result.SignatureStatus, result.Signer),
            };
    }

    private FileScanReport FileFailed(ScanItem item, OpenedScanFile opened, List<ScanNote> notes, string key, string kind, string message)
    {
        int count = _failures.Record(key);
        _lastError = message;
        _logger.LogWarning("Scanning {Path} failed in the sandboxed worker ({Kind}, {Count}/{Max}): {Message}",
            item.Path, kind, count, _options.MaxFailuresPerFile, message);
        return count >= _options.MaxFailuresPerFile
            ? CrashedTheEngine(item, opened, notes, count, kind)
            : NotScanned(item, opened, notes, $"The sandboxed scan worker failed on this file ({kind}): {message}");
    }

    private FileScanReport CrashedTheEngine(ScanItem item, OpenedScanFile opened, List<ScanNote> notes, int count, string detail)
    {
        var detection = new Detection(Verdict.Suspicious,
            $"The file crashed, hung or corrupted the sandboxed scan engine {count} times ({detail}): it may be built to break or evade scanners.",
            MitreTechniqueIds.ExploitationForDefenseEvasion, DetectionSource.Heuristic);
        notes.Add(new(ScanNoteLevel.Warning, $"{item.Path}: reported Suspicious because it repeatedly broke the scan worker; it was not fully scanned."));
        var hash = HashResult.NotHashed(HashFailureReason.IoError, "Not hashed: the sandboxed scan worker failed on this file.");
        return new FileScanReport(new ScanResult(item, [detection], _time.GetUtcNow()), hash, null, null, null, null, notes.AsReadOnly())
        {
            Identity = opened.Identity,
        };
    }

    private FileScanReport NotScanned(ScanItem item, OpenedScanFile opened, List<ScanNote> notes, string why)
    {
        notes.Add(new(ScanNoteLevel.Warning, $"Not scanned (Error): {item.Path}: {why}"));
        var hash = HashResult.NotHashed(HashFailureReason.IoError, why);
        return new FileScanReport(ScanResult.NotScanned(item, ScanStatus.Error, _time.GetUtcNow()), hash, null, null, null, null, notes.AsReadOnly())
        {
            Identity = opened.Identity,
        };
    }

    private static string FailureKey(string path, SafeFileHandle handle, FileIdentity? identity)
    {
        long length = -1;
        DateTime lastWrite = default;
        try
        {
            length = RandomAccess.GetLength(handle);
            lastWrite = File.GetLastWriteTimeUtc(handle);
        }
        catch (IOException)
        {
            // metadata only; the key just gets coarser
        }

        return FileFailureTracker.Key(identity, path, length, lastWrite);
    }
}
