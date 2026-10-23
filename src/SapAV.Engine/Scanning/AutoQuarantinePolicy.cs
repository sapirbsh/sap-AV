using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.Scanning.Native;

namespace SapAV.Engine.Scanning;

/// <summary>Reads a file's owner from its handle. Fake it in tests (a test can't create SYSTEM-owned files unelevated).</summary>
internal interface IFileOwnerReader
{
    SecurityIdentifier? GetOwner(SafeFileHandle handle);
}

internal sealed class HandleOwnerReader : IFileOwnerReader
{
    public static HandleOwnerReader Instance { get; } = new();

    public SecurityIdentifier? GetOwner(SafeFileHandle handle) => ScanNative.TryGetOwner(handle);
}

/// <summary>
/// Where scan jobs may quarantine on their own (review B5 M3). A compromised worker could report any file Malicious, so
/// files only SYSTEM or TrustedInstaller may change are never moved automatically: Windows, Program Files (both views),
/// configured extra folders, and any file owned by SYSTEM or TrustedInstaller. Those are flagged "needs user confirmation"
/// instead. An owner that can't be read counts as protected (fail closed). Only <see cref="Verdict.Malicious"/> is ever
/// eligible: Suspicious, and the PUP / HackTool category (E1), never are.
/// </summary>
internal sealed class AutoQuarantinePolicy
{
    /// <summary>NT SERVICE\TrustedInstaller.</summary>
    public static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    private readonly FolderSet _protected;
    private readonly IFileOwnerReader _owners;

    public AutoQuarantinePolicy(IEnumerable<string> extraProtectedFolders, IFileOwnerReader? owners = null)
    {
        _protected = new FolderSet(DefaultProtectedFolders().Concat(extraProtectedFolders));
        _owners = owners ?? HandleOwnerReader.Instance;
    }

    public FolderSet ProtectedFolders => _protected;

    /// <summary>The Windows folder and both Program Files folders.</summary>
    public static IEnumerable<string> DefaultProtectedFolders() =>
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetEnvironmentVariable("ProgramW6432") ?? string.Empty,
    ];

    /// <summary>True only for a scanned, Malicious result. Never for Suspicious or PUP.</summary>
    public static bool IsEligibleVerdict(FileScanReport report) =>
        report.Result.Status == ScanStatus.Scanned && report.Result.Verdict == Verdict.Malicious;

    /// <summary>Why the file must not be auto-quarantined (it needs the user), or null if it may be.</summary>
    /// <param name="opened">The scan's handle (for the owner); null = no handle, which is refused.</param>
    public string? ProtectedReason(FileScanReport report, OpenedScanFile? opened)
    {
        string path = report.Result.Item.Path;
        string? finalPath = report.Identity?.FinalPath;
        if (_protected.Contains(path) || _protected.Contains(finalPath))
        {
            return "the file is in a protected system folder (Windows or Program Files)";
        }

        if (opened is null)
        {
            return "the scan has no open handle to the file";
        }

        var owner = _owners.GetOwner(opened.Handle);
        return owner is null ? "the file's owner could not be read"
            : owner == LocalSystem ? "the file is owned by SYSTEM"
            : owner == TrustedInstaller ? "the file is owned by TrustedInstaller"
            : null;
    }
}

/// <summary>Sliding-window limit on automatic quarantines (review B5 M3); thread-safe.</summary>
internal sealed class AutoQuarantineLimiter(TimeProvider time, int maxPerWindow, TimeSpan window)
{
    private readonly Queue<DateTimeOffset> _recent = new();
    private readonly Lock _lock = new();
    private DateTimeOffset _burstReportedAt = DateTimeOffset.MinValue;

    public int MaxPerWindow => maxPerWindow;

    public TimeSpan Window => window;

    /// <summary>Takes one slot; false when <see cref="MaxPerWindow"/> were used in the last <see cref="Window"/>.</summary>
    /// <param name="firstRefusalInWindow">True for the first refusal of a burst (raise the burst alert once).</param>
    public bool TryAcquire(out bool firstRefusalInWindow)
    {
        var now = time.GetUtcNow();
        lock (_lock)
        {
            while (_recent.TryPeek(out var oldest) && now - oldest >= window)
            {
                _recent.Dequeue();
            }

            if (_recent.Count < maxPerWindow)
            {
                _recent.Enqueue(now);
                firstRefusalInWindow = false;
                return true;
            }

            firstRefusalInWindow = now - _burstReportedAt >= window;
            if (firstRefusalInWindow)
            {
                _burstReportedAt = now;
            }

            return false;
        }
    }
}
