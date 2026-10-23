using SapAV.Core.Models;
using SapAV.Core.Scanning;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// The engine's file scanner (B5). Same contract as <see cref="IFileScanner"/> (B3 plugs it in unchanged): file
/// problems come back as a not-scanned report, never Clean, and <see cref="FileScanReport.Identity"/> always comes from
/// the broker's own handle. With <see cref="SandboxMode.AppContainer"/> every byte of the file is parsed in a sandboxed
/// worker process; the engine only opens the file and passes a read-only handle.
/// </summary>
public interface IScanBroker : IFileScanner
{
    /// <summary>
    /// Scans a file the caller already opened with <see cref="ScanFileOpener"/> (B3: the scan job keeps the handle for
    /// the quarantine decision, so it acts on exactly the scanned object). Same contract as <see cref="IFileScanner.ScanAsync"/>;
    /// Identity comes from <paramref name="file"/>; the change-journal check is done here. The handle is not closed.
    /// </summary>
    /// <param name="openNotes">The notes <see cref="ScanFileOpener.Open"/> added while opening.</param>
    Task<FileScanReport> ScanOpenedAsync(ScanItem item, OpenedScanFile file, IReadOnlyList<ScanNote> openNotes, CancellationToken cancellationToken = default);

    /// <summary>Re-reads the rules directory and blocklist and loads them into every worker.</summary>
    /// <returns>What was loaded, or null if no worker could load it (see the log).</returns>
    Task<RulesLoadSummary?> ReloadRulesAsync(CancellationToken cancellationToken = default);

    /// <summary>Current state, for the pipe's get-status (B4) and the log.</summary>
    SandboxStatus Status { get; }
}

/// <summary>The outcome of loading a rule package.</summary>
/// <param name="RuleCount">YARA rules compiled. Zero means YARA finds nothing (B3 M5: the engine warns).</param>
/// <param name="FileErrors">Rule files that didn't compile or couldn't be read, one line each (first ones only).</param>
/// <param name="WarningCount">Rule warnings (e.g. a bad <c>mitre</c> meta value).</param>
/// <param name="Fingerprint">The rule set fingerprint (for the scan cache, C5).</param>
/// <param name="BlocklistCount">Hashes in the blocklist.</param>
/// <param name="BlocklistErrorCount">Blocklist lines that were not a SHA-256.</param>
public sealed record RulesLoadSummary(
    int RuleCount, IReadOnlyList<string> FileErrors, int WarningCount, string Fingerprint, int BlocklistCount, int BlocklistErrorCount);

/// <summary>A snapshot of the scanner's state.</summary>
/// <param name="Mode">Where parsing runs.</param>
/// <param name="WorkersRunning">Worker processes alive right now.</param>
/// <param name="WorkerRestarts">Workers that died or were killed (crash, hang, protocol violation) since start.</param>
/// <param name="Rules">The last successful rule load, or null.</param>
/// <param name="LastError">The last reason a worker couldn't start or failed, or null.</param>
public sealed record SandboxStatus(SandboxMode Mode, int WorkersRunning, int WorkerRestarts, RulesLoadSummary? Rules, string? LastError);
