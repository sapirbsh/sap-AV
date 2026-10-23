using Microsoft.Extensions.Logging;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;

namespace SapAV.Engine.Sandbox;

/// <summary>Picks the scanner for the configured <see cref="SandboxMode"/>.</summary>
internal static class ScanBrokerFactory
{
    /// <remarks>
    /// Review L1: <see cref="SandboxMode.InProcess"/> would parse files as SYSTEM, so it is refused when the engine runs
    /// as a Windows service. The engine then reports every file NotScanned (and logs why) instead of silently parsing
    /// in the service, or silently ignoring the setting.
    /// </remarks>
    public static IScanBroker Create(
        SandboxOptions options, IScanRulesSource rules, ILogger logger, TimeProvider time, IOnlineHashLookup? online, bool runningAsService)
    {
        if (options.Mode != SandboxMode.InProcess)
        {
            return new SandboxedScanBroker(options, rules, logger, time, online);
        }

        if (runningAsService)
        {
            const string why = "Sandbox:Mode=InProcess is refused when the engine runs as a Windows service (it would parse files as SYSTEM). " +
                "Set Sandbox:Mode=AppContainer. Until then no file is scanned.";
            logger.LogError(why);
            return new UnavailableScanBroker(why, time);
        }

        return new InProcessScanBroker(rules, logger, online);
    }
}

/// <summary>A scanner that can't scan: every file is NotScanned (Error) with the reason, never Clean.</summary>
internal sealed class UnavailableScanBroker(string reason, TimeProvider time) : IScanBroker
{
    public SandboxStatus Status => new(SandboxMode.InProcess, 0, 0, null, reason);

    public Task<FileScanReport> ScanAsync(ScanItem item, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        var notes = new List<ScanNote>();
        using var opened = ScanFileOpener.Open(item, notes, time, out var failure);
        if (opened is null)
        {
            return Task.FromResult(failure!);
        }

        notes.Add(new(ScanNoteLevel.Warning, $"Not scanned (Error): {item.Path}: {reason}"));
        return Task.FromResult(new FileScanReport(ScanResult.NotScanned(item, ScanStatus.Error, time.GetUtcNow()),
            HashResult.NotHashed(HashFailureReason.IoError, reason), null, null, null, null, notes.AsReadOnly())
        {
            Identity = opened.Identity,
        });
    }

    public Task<RulesLoadSummary?> ReloadRulesAsync(CancellationToken cancellationToken = default) => Task.FromResult<RulesLoadSummary?>(null);
}
