using Microsoft.Extensions.Logging;
using SapAV.Core.Blocklist;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.Yara;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// <see cref="SandboxMode.InProcess"/>: the pre-B5 pipeline (<see cref="FileScanner"/>) inside the engine process, with
/// the same rule source. <b>Debugging only</b>: a parser crash takes the engine down and an exploit runs as the engine's
/// account. A warning is logged when it is created.
/// </summary>
internal sealed class InProcessScanBroker : IScanBroker, IDisposable
{
    private readonly IScanRulesSource _rulesSource;
    private readonly IOnlineHashLookup? _online;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private YaraScanner? _yara;
    private HashBlocklist _blocklist = HashBlocklist.Empty;
    private FileScanner? _scanner;
    private RulesLoadSummary? _rules;

    public InProcessScanBroker(IScanRulesSource rulesSource, ILogger logger, IOnlineHashLookup? online = null)
    {
        _rulesSource = rulesSource ?? throw new ArgumentNullException(nameof(rulesSource));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _online = online;
        _logger.LogWarning("Sandbox:Mode is InProcess: files are parsed INSIDE the engine process, without the sandbox. " +
            "Use this for debugging only.");
    }

    public SandboxStatus Status => new(SandboxMode.InProcess, 0, 0, _rules, null);

    public async Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        var scanner = _scanner ?? await LoadAsync(cancellationToken).ConfigureAwait(false);
        var notes = new List<ScanNote>();
        using var opened = Scanning.SafeScanOpen.Open(item, notes, TimeProvider.System, out var failure); // review B H2: never a following open
        return opened is null ? failure! : await scanner.ScanOpenedAsync(item, opened, notes, cancellationToken).ConfigureAwait(false);
    }

    public async Task<FileScanReport> ScanOpenedAsync(
        ScanItem item, OpenedScanFile file, IReadOnlyList<ScanNote> openNotes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        var scanner = _scanner ?? await LoadAsync(cancellationToken).ConfigureAwait(false);
        return await scanner.ScanOpenedAsync(item, file, openNotes, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RulesLoadSummary?> ReloadRulesAsync(CancellationToken cancellationToken = default)
    {
        await LoadAsync(cancellationToken, force: true).ConfigureAwait(false);
        return _rules;
    }

    public void Dispose()
    {
        _yara?.Rules.Dispose();
        _gate.Dispose();
    }

    private async Task<FileScanner> LoadAsync(CancellationToken cancellationToken, bool force = false)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_scanner is not null && !force)
            {
                return _scanner;
            }

            var package = await _rulesSource.LoadAsync(cancellationToken).ConfigureAwait(false);
            var rules = YaraRuleSet.FromFiles(package.RuleFiles.Select(f => new YaraRuleFile(f.Name, f.Content)),
                package.ReadErrors.Select(e => new YaraRuleFileError("(engine)", [e])), cancellationToken);
            _blocklist = package.Blocklist.Length == 0
                ? HashBlocklist.Empty
                : await HashBlocklist.LoadAsync(new MemoryStream(package.Blocklist, writable: false), cancellationToken).ConfigureAwait(false);
            if (_yara is null)
            {
                _yara = new YaraScanner(rules);
            }
            else
            {
                _yara.SwapRules(rules).Dispose();
            }

            _rules = new RulesLoadSummary(rules.Rules.Count, rules.FileErrors.Select(e => e.ToString()).ToArray(), rules.Warnings.Count,
                rules.Fingerprint, _blocklist.Count, _blocklist.TotalErrorCount);
            SandboxedScanBroker.LogRules(_logger, _rules, package.ReadErrors);
            return _scanner = new FileScanner(new Sha256Hasher(), () => _blocklist, new AuthenticodeVerifier(), _yara,
                new MarkOfTheWebReader(), new FileHeuristics(), _online);
        }
        finally
        {
            _gate.Release();
        }
    }
}
