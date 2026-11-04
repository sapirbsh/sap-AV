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

        // A real antivirus removing or blocking the test file is named as such, never an opaque failure (and never a pass).
        Assert.False(inProcess.Identity is null && inProcess.Hash.FailureReason is Core.Hashing.HashFailureReason.BlockedByAntivirus
                or Core.Hashing.HashFailureReason.NotFound or Core.Hashing.HashFailureReason.IoError,
            $"Another antivirus blocked or removed the test file ({inProcess.Hash.FailureReason}: {inProcess.Hash.ErrorMessage}); "
            + "it must use content no antivirus flags.");
        Assert.NotNull(inProcess.Identity);

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
        // No "MZ" prefix: an MZ-looking .pdf.exe with an internet Zone.Identifier is what Defender's ML flags
        // (Trojan:Script/Wacatac.H!ml) and removes. The marker rule, not the header, makes it Malicious here.
        var path = Path.Combine(_dir, "invoice.pdf.exe");
        File.WriteAllText(path, "plain text sapav-b5-marker");
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
    public void TasksAndShortcuts_AreParsedInsideTheContainer_DeepXmlIsMalformed_AndACrashIsAnIssue()
    {
        // Review C H2 in the sandbox the service really uses: brokered read-only handles, the worker can't open anything by path.
        var broker = new SandboxedScanBroker(fixture.Container.Options(), new FakeRulesSource(), NullLogger.Instance)
        {
            ParseFaultInjector = path => path.EndsWith("Crash", StringComparison.Ordinal) ? WorkerTestFault.Crash : WorkerTestFault.None,
        };
        _owned.Add(broker);
        const string task = @"<Task><Actions><Exec><Command>C:\Tools\ok.exe</Command></Exec></Actions></Task>";
        File.WriteAllText(Path.Combine(_dir, "Crash"), task);
        File.WriteAllText(Path.Combine(_dir, "Good"), task);
        File.WriteAllText(Path.Combine(_dir, "Deep"), "<Task>" + string.Concat(Enumerable.Repeat("<a>", 140_000)) + string.Concat(Enumerable.Repeat("</a>", 140_000)) + "</Task>");
        var links = Directory.CreateDirectory(Path.Combine(_dir, "links")).FullName;
        File.WriteAllBytes(Path.Combine(links, "app.lnk"), new Core.Tests.TestSupport.ShellLinkBuilder { IdListPath = @"C:\Tools\app.exe" }.Build());
        using var root = new Persistence.RegistryTestRoot();

        var result = new SapAV.Engine.Persistence.PersistenceCollector(root.View, new Persistence.SetProbe(),
            [new SapAV.Engine.Persistence.StartupFolderSource([(links, null)]), new SapAV.Engine.Persistence.ScheduledTaskSource(_dir)], parser: broker).Collect();

        Assert.Contains(result.Entries, e => e.ValueName == "app.lnk" && e.Resolution.TargetPath == @"C:\Tools\app.exe");
        Assert.Contains(result.Entries, e => e.Location == @"\Good" && e.Resolution.TargetPath == @"C:\Tools\ok.exe");
        Assert.Contains(result.Issues, i => i.Location == @"\Deep" && i.Reason == Core.Persistence.PersistenceIssueReason.Malformed);
        Assert.Contains(result.Issues, i => i.Location == @"\Crash" && i.Reason == Core.Persistence.PersistenceIssueReason.Malformed);
        Assert.DoesNotContain(result.Issues, i => i.Reason == Core.Persistence.PersistenceIssueReason.ParserUnavailable);
        Assert.True(broker.Slots[0].Worker!.QueryToken().IsAppContainer);
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

    /// <summary>D3: the engine-side lookup runs after the worker's verdict; its detection and note reach the report, signed files never get it.</summary>
    [RequiresFact(Requires.AppContainer)]
    public async Task TheOnlineLookup_RunsInTheEngineAfterTheWorker_AddsItsDetectionAndNote_AndNeverSeesASignedFile()
    {
        var online = new RecordingOnline();
        var broker = new SandboxedScanBroker(fixture.Container.Options(), new FakeRulesSource(), NullLogger.Instance, online: online);
        _owned.Add(broker);
        var path = Path.Combine(_dir, "tool.exe");
        File.WriteAllText(path, "nothing local engines flag");

        var report = await broker.ScanAsync(new ScanItem(path, ScanTrigger.RealTime));
        var signed = await broker.ScanAsync(new ScanItem(Path.Combine(Environment.SystemDirectory, "cmd.exe"), ScanTrigger.RealTime));

        Assert.Equal(Verdict.Suspicious, report.Result.Verdict);
        Assert.Contains(report.Result.Detections, d => d.Source == DetectionSource.VirusTotal);
        Assert.Contains(report.Notes, n => n.Message == RecordingOnline.NoteText);
        Assert.Equal(Verdict.Clean, signed.Result.Verdict);
        Assert.Equal([path], online.Paths);
    }

    /// <summary>Review D3 M2: a slow online lookup doesn't hold the worker slot (one worker: a second scan runs during the lookup).</summary>
    [RequiresFact(Requires.AppContainer)]
    public async Task TheOnlineLookup_RunsAfterTheWorkerSlotIsReleased()
    {
        var options = fixture.Container.Options();
        options.WorkerCount = 1;
        SandboxedScanBroker? broker = null;
        var other = Path.Combine(_dir, "other.exe");
        File.WriteAllText(other, "second file");
        FileScanReport? nested = null;
        var online = new DelegateOnline(async request =>
        {
            if (request.Item.Path != other)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                nested = await broker!.ScanAsync(new ScanItem(other, ScanTrigger.RealTime), timeout.Token); // would wait forever for the slot
            }

            return OnlineLookupOutcome.None;
        });
        broker = new SandboxedScanBroker(options, new FakeRulesSource(), NullLogger.Instance, online: online);
        _owned.Add(broker);
        var first = Path.Combine(_dir, "first.exe");
        File.WriteAllText(first, "first file");

        var report = await broker.ScanAsync(new ScanItem(first, ScanTrigger.RealTime));

        Assert.Equal(ScanStatus.Scanned, report.Result.Status);
        Assert.Equal(ScanStatus.Scanned, nested!.Result.Status);
    }

    private sealed class DelegateOnline(Func<OnlineLookupRequest, Task<OnlineLookupOutcome>> lookup) : IOnlineHashLookup
    {
        public Task<OnlineLookupOutcome> LookupAsync(OnlineLookupRequest request, CancellationToken cancellationToken = default) => lookup(request);
    }

    private sealed class RecordingOnline : IOnlineHashLookup
    {
        public const string NoteText = "VirusTotal: 3/70 engines flagged the file (live).";

        public List<string> Paths { get; } = [];

        public Task<OnlineLookupOutcome> LookupAsync(OnlineLookupRequest request, CancellationToken cancellationToken = default)
        {
            lock (Paths)
            {
                Paths.Add(request.Item.Path);
            }

            return Task.FromResult(new OnlineLookupOutcome(
                new Detection(Verdict.Suspicious, "VirusTotal: 3 engines.", Core.Mitre.MitreTechniqueIds.MaliciousFile, DetectionSource.VirusTotal),
                new ScanNote(ScanNoteLevel.Information, NoteText)));
        }
    }
}
