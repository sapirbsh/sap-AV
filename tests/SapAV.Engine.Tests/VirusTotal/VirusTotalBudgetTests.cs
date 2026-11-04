using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;
using SapAV.Core.VirusTotal;
using SapAV.Engine.VirusTotal;

namespace SapAV.Engine.Tests.VirusTotal;

/// <summary>
/// Review D3 M3: one user's real-time files can't use up the shared VirusTotal day. Each owner gets 1/4 of the day, files with no
/// user owner use the engine's own share, and a reserve stays for scans. A fake service with a small day (8) keeps it fast.
/// </summary>
public sealed class VirusTotalBudgetTests
{
    private readonly Clock _clock = new();
    private readonly FakeService _service = new() { PerDay = 8 };

    private VirusTotalOnlineLookup Lookup() =>
        new(_service, new VirusTotalOptions { ScanReserve = 2, RealTimeOwnerShare = 4 }, noteWhenUnavailable: true, _clock);

    private static OnlineLookupRequest RealTime(int i) =>
        new(new ScanItem($@"C:\Users\u\Downloads\f{i}.exe", ScanTrigger.RealTime), i.ToString("x64"), SignatureStatus.UnsignedOrInvalid, Verdict.Clean);

    private static async Task<OnlineLookupOutcome> AsOwner(VirusTotalOnlineLookup lookup, string? owner, int i)
    {
        using var scope = OnlineLookupOwner.Use(owner);
        return await lookup.LookupAsync(RealTime(i));
    }

    [Fact]
    public async Task EachOwner_GetsAQuarterOfTheDay_AndTheEngineShareIsSeparate()
    {
        var lookup = Lookup();
        await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 1);
        await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 2);

        var third = await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 3);

        Assert.Equal(2, _service.Sent);
        Assert.Contains("share of today's budget", third.Note!.Message, StringComparison.Ordinal);
        await AsOwner(lookup, "S-1-5-21-1-2-3-1002", 4); // another user still gets theirs
        await AsOwner(lookup, null, 5); // machine-wide / admin-owned files: the engine's share
        Assert.Equal(4, _service.Sent);
    }

    [Fact]
    public async Task RealTime_StopsBeforeTheScanReserve_WhileScansStillGo()
    {
        var lookup = Lookup();
        _service.UsedToday = 6; // 8 - reserve 2

        var realTime = await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 1);
        var scan = await lookup.LookupAsync(new OnlineLookupRequest(new ScanItem(@"C:\data\x.bin", ScanTrigger.FullScan), new string('f', 64),
            SignatureStatus.UnsignedOrInvalid, Verdict.Suspicious));

        Assert.Contains("kept for scans", realTime.Note!.Message, StringComparison.Ordinal);
        Assert.Equal(1, _service.Sent); // only the scan
        Assert.DoesNotContain("not checked", scan.Note?.Message ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CacheAnswers_DontCount_AndANewUtcDayStartsAgain()
    {
        var lookup = Lookup();
        _service.Origin = VirusTotalOrigin.Cache;
        for (int i = 0; i < 5; i++)
        {
            await AsOwner(lookup, "S-1-5-21-1-2-3-1001", i);
        }

        Assert.Equal(0, lookup.OwnerBudget.UsedBy("S-1-5-21-1-2-3-1001"));

        _service.Origin = VirusTotalOrigin.Live;
        await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 10);
        await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 11);
        Assert.NotNull((await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 12)).Note);
        _clock.Now = _clock.Now.AddDays(1);
        var nextDay = await AsOwner(lookup, "S-1-5-21-1-2-3-1001", 13);
        Assert.DoesNotContain("share", nextDay.Note?.Message ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(3, _service.Sent);
    }

    [Fact]
    public async Task TheScanPipeline_PassesTheRealTimeOwnerToTheLookup_AndNothingLeaksAfterwards()
    {
        using var temp = new TestSupport.TempDir();
        var path = Path.Combine(temp.Path, "a.exe");
        File.WriteAllText(path, "x");
        var broker = new TestSupport.FakeScanBroker();
        string? seen = "unset";
        broker.OnScan = (_, _, _) =>
        {
            seen = OnlineLookupOwner.Current;
            return Task.FromResult<FileScanReport?>(null);
        };
        var pipeline = new SapAV.Engine.Scanning.ScanFilePipeline(broker, SapAV.Engine.Scanning.ExclusionSet.Always(new SapAV.Engine.Scanning.FolderSet([])), null, TimeProvider.System,
            Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        await pipeline.ProcessDetailedAsync(path, ScanTrigger.RealTime, _ => { }, CancellationToken.None,
            budget: new SapAV.Engine.Scanning.ScanBudget(ScanTrigger.RealTime) { Owner = "S-1-5-21-1-2-3-1001" });

        Assert.Equal("S-1-5-21-1-2-3-1001", seen);
        Assert.Null(OnlineLookupOwner.Current);
    }

    private sealed class FakeService : IVirusTotalService
    {
        public int PerDay { get; init; }

        public int UsedToday { get; set; }

        public int Sent { get; private set; }

        public VirusTotalOrigin Origin { get; set; } = VirusTotalOrigin.Live;

        public VirusTotalActivity Activity => VirusTotalActivity.Active;

        public VirusTotalStatusInfo GetStatus() => new(true, true, true, false, false, UsedToday, PerDay, null);

        public Task<VirusTotalLookupResult> LookupAsync(string sha256, TimeSpan maxWait, CancellationToken cancellationToken)
        {
            if (Origin == VirusTotalOrigin.Live)
            {
                Sent++;
                UsedToday++;
            }

            return Task.FromResult(new VirusTotalLookupResult(Origin, VirusTotalStatus.NotFound, null, DateTimeOffset.UnixEpoch, null,
                "VirusTotal does not know this file."));
        }

        public VirusTotalChange SetKey(string? apiKey) => VirusTotalChange.Done;

        public VirusTotalChange ClearKey() => VirusTotalChange.Done;

        public VirusTotalChange SetEnabled(bool enabled) => VirusTotalChange.Done;
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
