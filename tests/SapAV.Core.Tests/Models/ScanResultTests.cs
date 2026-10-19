using SapAV.Core.Models;

namespace SapAV.Core.Tests.Models;

public class ScanResultTests
{
    private static readonly ScanItem Item = new(@"C:\Temp\sample.bin", ScanTrigger.CustomScan);
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);

    // SHA-256 of the 68-byte EICAR test string.
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private static Detection Suspicious(string reason = "high entropy") =>
        new(Verdict.Suspicious, reason, "T1027.002", DetectionSource.Heuristic);

    private static Detection Malicious(string reason = "blocklist") =>
        new(Verdict.Malicious, reason, "T1204.002", DetectionSource.Blocklist);

    [Fact]
    public void NoDetections_IsClean()
    {
        var result = new ScanResult(Item, [], Now);

        Assert.Equal(Verdict.Clean, result.Verdict);
        Assert.Empty(result.Detections);
    }

    [Fact]
    public void CleanFactory_IsClean()
    {
        var result = ScanResult.Clean(Item, Now, EicarSha256);

        Assert.Equal(Verdict.Clean, result.Verdict);
        Assert.Empty(result.Detections);
        Assert.Equal(EicarSha256, result.Sha256);
    }

    [Fact]
    public void OnlySuspicious_IsSuspicious()
    {
        var result = new ScanResult(Item, [Suspicious(), Suspicious("double extension")], Now);

        Assert.Equal(Verdict.Suspicious, result.Verdict);
    }

    [Fact]
    public void WorstDetectionWins_RegardlessOfOrder()
    {
        Assert.Equal(Verdict.Malicious, new ScanResult(Item, [Suspicious(), Malicious()], Now).Verdict);
        Assert.Equal(Verdict.Malicious, new ScanResult(Item, [Malicious(), Suspicious()], Now).Verdict);
    }

    [Fact]
    public void With_Detections_RecomputesVerdict()
    {
        var clean = ScanResult.Clean(Item, Now);

        var malicious = clean with { Detections = [Malicious()] };
        var backToClean = malicious with { Detections = [] };

        Assert.Equal(Verdict.Malicious, malicious.Verdict);
        Assert.Equal(Verdict.Clean, backToClean.Verdict);
        Assert.Equal(Verdict.Clean, clean.Verdict);
    }

    [Fact]
    public void Detections_AreCopied_NotAliased()
    {
        var list = new List<Detection> { Suspicious() };
        var result = new ScanResult(Item, list, Now);

        list.Add(Malicious());

        Assert.Single(result.Detections);
        Assert.Equal(Verdict.Suspicious, result.Verdict);
        Assert.IsNotType<Detection[]>(result.Detections);
    }

    [Fact]
    public void StoresItemAndTimestamp()
    {
        var result = new ScanResult(Item, [], Now);

        Assert.Same(Item, result.Item);
        Assert.Equal(Now, result.Timestamp);
        Assert.Null(result.Sha256);
    }

    [Fact]
    public void Sha256_IsNormalizedToLowercase()
    {
        var result = new ScanResult(Item, [], Now, EicarSha256.ToUpperInvariant());

        Assert.Equal(EicarSha256, result.Sha256);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0")]   // 63 chars
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f0")] // 65 chars
    [InlineData("z75a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")]  // non-hex
    [InlineData("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0 ")]  // trailing space, 64 chars
    [InlineData("２" + "75a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")] // fullwidth digit
    [InlineData("٢" + "75a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")] // Arabic-Indic digit
    public void Sha256_RejectsMalformedValues(string sha256)
    {
        Assert.Throws<ArgumentException>(() => new ScanResult(Item, [], Now, sha256));
    }

    [Fact]
    public void With_StillValidatesAndNormalizesSha256()
    {
        var result = ScanResult.Clean(Item, Now);

        Assert.Throws<ArgumentException>(() => result with { Sha256 = "abc" });
        Assert.Equal(EicarSha256, (result with { Sha256 = EicarSha256.ToUpperInvariant() }).Sha256);
        Assert.Null((ScanResult.Clean(Item, Now, EicarSha256) with { Sha256 = null }).Sha256);
    }

    [Fact]
    public void With_StillValidatesItemAndDetections()
    {
        var result = ScanResult.Clean(Item, Now);

        Assert.Throws<ArgumentNullException>(() => result with { Item = null! });
        Assert.Throws<ArgumentNullException>(() => result with { Detections = null! });
        Assert.Throws<ArgumentException>(() => result with { Detections = [Suspicious(), null!] });
    }

    [Fact]
    public void With_OtherProperty_KeepsDerivedVerdict()
    {
        var malicious = new ScanResult(Item, [Malicious()], Now);

        var later = malicious with { Timestamp = Now.AddMinutes(5) };

        Assert.Equal(Verdict.Malicious, later.Verdict);
        Assert.Single(later.Detections);
    }

    [Fact]
    public void Detections_CannotBeMutatedThroughCast()
    {
        var result = new ScanResult(Item, [Suspicious()], Now);

        var asList = Assert.IsAssignableFrom<IList<Detection>>(result.Detections);
        Assert.Throws<NotSupportedException>(() => asList[0] = Malicious());
        Assert.Equal(Verdict.Suspicious, result.Verdict);
    }

    [Fact]
    public void RejectsNullItemOrDetections()
    {
        Assert.Throws<ArgumentNullException>(() => new ScanResult(null!, [], Now));
        Assert.Throws<ArgumentNullException>(() => new ScanResult(Item, null!, Now));
        Assert.Throws<ArgumentException>(() => new ScanResult(Item, [Malicious(), null!], Now));
    }

    // --- Scan status ---

    [Fact]
    public void Status_DefaultsToScanned()
    {
        Assert.Equal(ScanStatus.Scanned, new ScanResult(Item, [], Now).Status);
        Assert.Equal(ScanStatus.Scanned, ScanResult.Clean(Item, Now).Status);
        Assert.Equal(ScanStatus.Scanned, new ScanResult(Item, [Malicious()], Now).Status);
    }

    [Theory]
    [InlineData(ScanStatus.SkippedTooLarge)]
    [InlineData(ScanStatus.AccessDenied)]
    [InlineData(ScanStatus.Locked)]
    [InlineData(ScanStatus.Error)]
    public void NotScanned_HasNullVerdict_NeverClean(ScanStatus status)
    {
        var result = ScanResult.NotScanned(Item, status, Now);

        Assert.Equal(status, result.Status);
        Assert.Null(result.Verdict);
        Assert.False(result.Verdict == Verdict.Clean);
        Assert.Empty(result.Detections);
        Assert.Same(Item, result.Item);
        Assert.Equal(Now, result.Timestamp);
    }

    [Fact]
    public void NotScanned_ViaConstructor_AlsoHasNullVerdict()
    {
        var result = new ScanResult(Item, [], Now, status: ScanStatus.Locked);

        Assert.Null(result.Verdict);
    }

    [Fact]
    public void NotScanned_KeepsOptionalSha256()
    {
        // e.g. hashed, but YARA failed with an error.
        var result = ScanResult.NotScanned(Item, ScanStatus.Error, Now, EicarSha256.ToUpperInvariant());

        Assert.Equal(EicarSha256, result.Sha256);
        Assert.Null(result.Verdict);
    }

    [Fact]
    public void NotScannedFactory_RejectsScannedAndUndefinedStatus()
    {
        var scanned = Assert.Throws<ArgumentOutOfRangeException>(() => ScanResult.NotScanned(Item, ScanStatus.Scanned, Now));
        Assert.Equal("status", scanned.ParamName);

        var undefined = Assert.Throws<ArgumentOutOfRangeException>(() => ScanResult.NotScanned(Item, (ScanStatus)42, Now));
        Assert.Equal("status", undefined.ParamName);

        var negative = Assert.Throws<ArgumentOutOfRangeException>(() => ScanResult.NotScanned(Item, (ScanStatus)(-1), Now));
        Assert.Equal("status", negative.ParamName);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(5)]
    public void Constructor_RejectsUndefinedStatus(int raw)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => new ScanResult(Item, [], Now, status: (ScanStatus)raw));
        Assert.Equal(nameof(ScanResult.Status), ex.ParamName);
    }

    [Theory]
    [InlineData(ScanStatus.SkippedTooLarge)]
    [InlineData(ScanStatus.AccessDenied)]
    [InlineData(ScanStatus.Locked)]
    [InlineData(ScanStatus.Error)]
    public void NotScanned_RejectsDetections(ScanStatus status)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new ScanResult(Item, [Malicious()], Now, status: status));
        Assert.Equal(nameof(ScanResult.Detections), ex.ParamName);
    }

    [Fact]
    public void With_CannotAddDetectionsToNotScannedResult()
    {
        var locked = ScanResult.NotScanned(Item, ScanStatus.Locked, Now);

        Assert.Throws<ArgumentException>(() => locked with { Detections = [Suspicious()] });

        var later = locked with { Timestamp = Now.AddMinutes(1), Detections = [] };
        Assert.Equal(ScanStatus.Locked, later.Status);
        Assert.Null(later.Verdict);
    }

    // --- Value equality ---

    private static ScanResult Result(params Detection[] detections) =>
        new(Item, detections, Now, EicarSha256);

    [Fact]
    public void Equal_WhenSameValuesAndDetections_EvenWithDifferentInstances()
    {
        var a = Result(Suspicious(), Malicious());
        var b = new ScanResult(
            new ScanItem(@"C:\Temp\sample.bin", ScanTrigger.CustomScan),
            new List<Detection> { Suspicious(), Malicious() },
            Now,
            EicarSha256.ToUpperInvariant());

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Equal_NotScannedResults_WithSameValues()
    {
        var a = ScanResult.NotScanned(Item, ScanStatus.AccessDenied, Now);
        var b = ScanResult.NotScanned(Item, ScanStatus.AccessDenied, Now);

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void NotEqual_WhenDetectionOrderOrContentDiffers()
    {
        var baseline = Result(Suspicious(), Malicious());

        Assert.NotEqual(baseline, Result(Malicious(), Suspicious()));
        Assert.NotEqual(baseline, Result(Suspicious(), Malicious("other reason")));
        Assert.NotEqual(baseline, Result(Suspicious()));
        Assert.NotEqual(baseline, Result());
    }

    [Fact]
    public void NotEqual_WhenScalarsOrStatusDiffer()
    {
        var baseline = Result();

        Assert.NotEqual(baseline, baseline with { Timestamp = Now.AddSeconds(1) });
        Assert.NotEqual(baseline, baseline with { Sha256 = null });
        Assert.NotEqual(baseline, baseline with { Item = new ScanItem(@"C:\other.bin", ScanTrigger.CustomScan) });
        Assert.NotEqual(baseline, ScanResult.NotScanned(Item, ScanStatus.Locked, Now, EicarSha256));
        Assert.NotEqual(
            ScanResult.NotScanned(Item, ScanStatus.Locked, Now),
            ScanResult.NotScanned(Item, ScanStatus.Error, Now));
        Assert.False(baseline.Equals(null));
    }
}
