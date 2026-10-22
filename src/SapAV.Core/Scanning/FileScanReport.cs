using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Signatures;
using SapAV.Core.Yara;

namespace SapAV.Core.Scanning;

/// <summary>How important a <see cref="ScanNote"/> is for the log.</summary>
public enum ScanNoteLevel
{
    Information,
    Warning,
}

/// <summary>A log-ready line about one scan (Core has no logger; the engine writes these).</summary>
public sealed record ScanNote(ScanNoteLevel Level, string Message)
{
    public override string ToString() => $"{Level}: {Message}";
}

/// <summary>
/// Everything one <see cref="IFileScanner.ScanAsync"/> call produced: the <see cref="ScanResult"/> (the verdict
/// that goes to the pipe, the cache and the Event Log) plus each step's own result for logs and the UI.
/// A step that didn't run is null.
/// </summary>
public sealed record FileScanReport(
    ScanResult Result,
    HashResult Hash,
    SignatureCheckResult? Signature,
    YaraScanResult? Yara,
    MarkOfTheWebResult? MarkOfTheWeb,
    HeuristicResult? Heuristics,
    IReadOnlyList<ScanNote> Notes)
{
    /// <summary>The download URL from the Mark-of-the-Web, if any (shown in results and alerts).</summary>
    public string? SourceUrl => MarkOfTheWeb?.Mark?.HostUrl;

    /// <summary>
    /// The file object that was scanned (volume serial, 128-bit file ID, final path), from the scan's own handle; null
    /// if the file couldn't be opened or the file system has no file IDs. The quarantine refuses to act without it.
    /// </summary>
    public FileIdentity? Identity { get; init; }
}
