using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Scanning;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Signatures;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>
/// B5 end to end in the real AppContainer: the sandboxed broker gives the same results as the in-process pipeline for
/// catalog- and embedded-signed Microsoft binaries, a downloaded file with a Mark-of-the-Web (stream handle brokered),
/// and EICAR (opt-in, on disk); and a crash inside the container is NotScanned with a restart.
/// </summary>
public sealed class ScanBrokerAppContainerTests(AppContainerFixture fixture) : IClassFixture<AppContainerFixture>, IDisposable
{
    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"))).FullName;
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned)
        {
            d.Dispose(); // brokers kill their workers
        }

        TempDir.DeleteTree(_dir);
    }

    private (SandboxedScanBroker Sandboxed, InProcessScanBroker InProcess) Brokers(IScanRulesSource rules)
    {
        var sandboxed = new SandboxedScanBroker(fixture.Container.Options(), rules, NullLogger.Instance);
        var inProcess = new InProcessScanBroker(rules, NullLogger.Instance);
        _owned.Add(sandboxed);
        _owned.Add(inProcess);
        return (sandboxed, inProcess);
    }

    private static async Task<(FileScanReport Sandboxed, FileScanReport InProcess)> BothAsync(
        (SandboxedScanBroker Sandboxed, InProcessScanBroker InProcess) brokers, string path)
    {
        var item = new ScanItem(path, ScanTrigger.CustomScan);
        var sandboxed = await brokers.Sandboxed.ScanAsync(item);
        var inProcess = await brokers.InProcess.ScanAsync(item);

        Assert.Equal(inProcess.Result with { Timestamp = default }, sandboxed.Result with { Timestamp = default });
        Assert.Equal(inProcess.Hash, sandboxed.Hash);
        Assert.Equal(inProcess.Signature, sandboxed.Signature);
        Assert.Equal(inProcess.Yara?.Matches.Select(m => m.Identifier), sandboxed.Yara?.Matches.Select(m => m.Identifier));
        Assert.Equal(inProcess.MarkOfTheWeb, sandboxed.MarkOfTheWeb);
        Assert.Equal(inProcess.Heuristics?.Score, sandboxed.Heuristics?.Score);
        Assert.True(inProcess.Identity!.IsSameObject(sandboxed.Identity));
        return (sandboxed, inProcess);
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task CatalogSignedWindowsBinary_IsMicrosoft_InsideTheContainer_SameAsInProcess()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var (sandboxed, _) = await BothAsync(Brokers(new FakeRulesSource(ScanBrokerSupervisionTests.MarkerRule)), cmd);

        Assert.Equal(SignatureStatus.Microsoft, sandboxed.Result.SignatureStatus);
        Assert.Equal(SignatureKind.Catalog, sandboxed.Signature!.Kind); // WinVerifyTrust catalog lookups work in the AppContainer
        Assert.Equal(Verdict.Clean, sandboxed.Result.Verdict);
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task EmbeddedSignedRuntimeDll_IsMicrosoft_SameAsInProcess()
    {
        var dll = Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "System.Runtime.dll");
        var (sandboxed, _) = await BothAsync(Brokers(new FakeRulesSource()), dll);

        Assert.Equal(SignatureStatus.Microsoft, sandboxed.Result.SignatureStatus);
        Assert.Equal(SignatureKind.Embedded, sandboxed.Signature!.Kind);
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task DownloadedMarkedFile_WithMotw_SameVerdictAndMark_AsInProcess()
    {
        var path = Path.Combine(_dir, "invoice.pdf.exe");
        File.WriteAllText(path, "MZ sapav-b5-marker");
        File.WriteAllText(path + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://downloads.example.test/invoice.pdf.exe\r\n");

        var (sandboxed, _) = await BothAsync(Brokers(new FakeRulesSource(ScanBrokerSupervisionTests.MarkerRule)), path);

        Assert.Equal(Verdict.Malicious, sandboxed.Result.Verdict);
        Assert.Equal(MarkOfTheWebStatus.Present, sandboxed.MarkOfTheWeb!.Status); // brokered stream handle
        Assert.True(sandboxed.MarkOfTheWeb.Mark!.IsFromInternet);
        Assert.Equal("https://downloads.example.test/invoice.pdf.exe", sandboxed.SourceUrl);
    }

    [RequiresFact(Requires.AppContainer, Requires.EicarFileOnDisk)]
    public async Task Eicar_OnDisk_ShippedRules_IsMalicious_SameAsInProcess()
    {
        var path = Path.Combine(_dir, "eicar.com");
        File.WriteAllBytes(path, SapAV.Core.Tests.TestSupport.Eicar.Bytes());
        var rules = new DirectoryScanRulesSource(new SandboxOptions()); // the engine's default data\rules + blocklist

        var (sandboxed, _) = await BothAsync(Brokers(rules), path);

        Assert.Equal(Verdict.Malicious, sandboxed.Result.Verdict);
        Assert.Equal(SapAV.Core.Tests.TestSupport.Eicar.KnownSha256, sandboxed.Result.Sha256);
    }

    [RequiresFact(Requires.AppContainer)]
    public async Task CrashInsideTheContainer_IsNotScanned_AndTheWorkerRestarts()
    {
        var broker = new SandboxedScanBroker(fixture.Container.Options(), new FakeRulesSource(), NullLogger.Instance)
        {
            FaultInjector = item => item.Path.EndsWith("crash.bin", StringComparison.Ordinal) ? WorkerTestFault.Crash : WorkerTestFault.None,
        };
        _owned.Add(broker);
        File.WriteAllText(Path.Combine(_dir, "crash.bin"), "x");
        File.WriteAllText(Path.Combine(_dir, "ok.txt"), "x");

        var crashed = await broker.ScanAsync(new ScanItem(Path.Combine(_dir, "crash.bin"), ScanTrigger.RealTime));
        var next = await broker.ScanAsync(new ScanItem(Path.Combine(_dir, "ok.txt"), ScanTrigger.RealTime));

        Assert.Equal(ScanStatus.Error, crashed.Result.Status);
        Assert.Equal(Verdict.Clean, next.Result.Verdict);
        Assert.Equal(1, broker.Status.WorkerRestarts);
        Assert.True(broker.Slots[0].Worker!.QueryToken().IsAppContainer);
    }
}
