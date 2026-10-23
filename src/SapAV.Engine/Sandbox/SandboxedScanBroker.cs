using System.ComponentModel;
using System.Threading.Channels;
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
internal sealed class SandboxedScanBroker : IScanBroker, IDisposable
{
    private readonly SandboxOptions _options;
    private readonly IScanRulesSource _rulesSource;
    private readonly IOnlineHashLookup? _online;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly WorkerSlot[] _slots;
    private readonly Channel<WorkerSlot> _idle;
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
        _idle = Channel.CreateBounded<WorkerSlot>(options.WorkerCount);
        foreach (var slot in _slots)
        {
            _idle.Writer.TryWrite(slot);
        }

        if (options.Isolation != WorkerIsolation.AppContainer)
        {
            logger.LogWarning("Scan workers run WITHOUT the AppContainer (test-only isolation mode).");
        }
    }

    /// <summary>Test seam: a fault for the worker to inject while scanning this item (honored only with worker test hooks).</summary>
    internal Func<ScanItem, WorkerTestFault>? FaultInjector { get; set; }

    /// <summary>Test seam: the pool.</summary>
    internal IReadOnlyList<WorkerSlot> Slots => _slots;

    public SandboxStatus Status =>
        new(SandboxMode.AppContainer, _slots.Count(s => s.IsRunning), Volatile.Read(ref _restarts), _rules, _lastError);

    public async Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<ScanNote>();

        using var opened = ScanFileOpener.Open(item, notes, _time, out var failureReport);
        if (opened is null)
        {
            return failureReport!;
        }

        string key = FailureKey(item, opened);
        if (_failures.Count(key) is var previous && previous >= _options.MaxFailuresPerFile)
        {
            return CrashedTheEngine(item, opened, notes, previous, "seen before; not sent to a worker again");
        }

        var package = await CurrentPackageAsync(cancellationToken).ConfigureAwait(false);
        var slot = await RentAsync(cancellationToken).ConfigureAwait(false);
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
            notes.AddRange(report.Notes);
            report = report with { Identity = opened.Identity, Notes = notes.AsReadOnly() };
            report = await OnlineLookupAsync(report, cancellationToken).ConfigureAwait(false);
            return ScanFileOpener.VerifyUnchanged(opened, report, notes, _time);
        }
        finally
        {
            slot.Lock.Release();
            _idle.Writer.TryWrite(slot);
        }
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
            return await slot.ScanAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (!worker.HasExited)
            {
                worker.CloseInWorker(remoteFile);
                worker.CloseInWorker(remoteStream);
            }
        }
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

    private async Task<WorkerSlot> RentAsync(CancellationToken cancellationToken)
    {
        var slot = await _idle.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await slot.Lock.WaitAsync(cancellationToken).ConfigureAwait(false); // a reload may hold it briefly
            return slot;
        }
        catch
        {
            _idle.Writer.TryWrite(slot);
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

    private static string FailureKey(ScanItem item, OpenedScanFile opened)
    {
        long length = -1;
        DateTime lastWrite = default;
        try
        {
            length = RandomAccess.GetLength(opened.Handle);
            lastWrite = File.GetLastWriteTimeUtc(opened.Handle);
        }
        catch (IOException)
        {
            // metadata only; the key just gets coarser
        }

        return FileFailureTracker.Key(opened.Identity, item.Path, length, lastWrite);
    }
}
