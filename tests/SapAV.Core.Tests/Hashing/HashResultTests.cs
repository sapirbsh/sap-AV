using System.Text.Json;
using SapAV.Core.Hashing;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.Hashing;

public class HashResultTests
{
    private const string Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private static readonly ScanItem Item = new(@"C:\Temp\x.bin", ScanTrigger.RealTime);
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTime LastWrite = new(2026, 10, 1, 8, 30, 0, DateTimeKind.Utc);

    [Fact]
    public void Hashed_StoresNormalizedHashLengthAndMetadata()
    {
        var result = HashResult.Hashed(Abc.ToUpperInvariant(), 3, LastWrite, FileAttributes.Archive);

        Assert.True(result.IsHashed);
        Assert.Equal(ScanStatus.Scanned, result.Status);
        Assert.Equal(HashFailureReason.None, result.FailureReason);
        Assert.Equal(Abc, result.Sha256);
        Assert.Equal(3, result.Length);
        Assert.Equal(LastWrite, result.LastWriteTimeUtc);
        Assert.Equal(FileAttributes.Archive, result.Attributes);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void Hashed_RejectsBadInput()
    {
        Assert.Throws<ArgumentException>(() => HashResult.Hashed("abc", 3));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashResult.Hashed(Abc, -1));
    }

    public static TheoryData<HashFailureReason, ScanStatus> ReasonToStatus => new()
    {
        { HashFailureReason.InvalidPath, ScanStatus.Error },
        { HashFailureReason.NotRegularFile, ScanStatus.Error },
        { HashFailureReason.Directory, ScanStatus.Error },
        { HashFailureReason.NotFound, ScanStatus.Error },
        { HashFailureReason.AccessDenied, ScanStatus.AccessDenied },
        { HashFailureReason.Locked, ScanStatus.Locked },
        { HashFailureReason.TooLarge, ScanStatus.SkippedTooLarge },
        { HashFailureReason.Offline, ScanStatus.SkippedOffline },
        { HashFailureReason.ChangedDuringHashing, ScanStatus.Error },
        { HashFailureReason.BlockedByAntivirus, ScanStatus.Error },
        { HashFailureReason.IoError, ScanStatus.Error },
    };

    [Fact]
    public void ReasonToStatus_CoversEveryReasonExceptNone()
    {
        var covered = ReasonToStatus.Select(row => (HashFailureReason)row[0]).ToHashSet();

        Assert.Equal(Enum.GetValues<HashFailureReason>().Where(r => r != HashFailureReason.None).ToHashSet(), covered);
    }

    [Theory]
    [MemberData(nameof(ReasonToStatus))]
    public void NotHashed_DerivesStatus_HasNoHash_AndMapsToNotScannedResult(HashFailureReason reason, ScanStatus status)
    {
        var hash = HashResult.NotHashed(reason, "detail", 10, LastWrite, FileAttributes.Offline);

        Assert.Equal(status, HashResult.StatusFor(reason));
        Assert.Equal(status, hash.Status);
        Assert.Equal(reason, hash.FailureReason);
        Assert.False(hash.IsHashed);
        Assert.Null(hash.Sha256);
        Assert.Equal("detail", hash.ErrorMessage);
        Assert.Equal(10, hash.Length);
        Assert.Equal(LastWrite, hash.LastWriteTimeUtc);

        var scan = hash.ToNotScannedResult(Item, Now);
        Assert.Equal(status, scan.Status);
        Assert.Null(scan.Verdict);
        Assert.Empty(scan.Detections);
        Assert.Same(Item, scan.Item);
        Assert.Equal(Now, scan.Timestamp);
    }

    [Fact]
    public void NotHashed_RejectsNoneUndefinedOrNegativeLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HashResult.NotHashed(HashFailureReason.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashResult.NotHashed((HashFailureReason)42));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashResult.NotHashed(HashFailureReason.IoError, length: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashResult.StatusFor(HashFailureReason.None));
    }

    [Fact]
    public void ToNotScannedResult_ThrowsForHashedResult()
    {
        Assert.Throws<InvalidOperationException>(() => HashResult.Hashed(Abc, 3).ToNotScannedResult(Item, Now));
    }

    [Fact]
    public void HashedValue_IsAcceptedByScanResult()
    {
        var hash = HashResult.Hashed(Abc, 3);

        var scan = new ScanResult(Item, [], Now, hash.Sha256);

        Assert.Equal(Abc, scan.Sha256);
    }

    [Fact]
    public void FailureReason_SerializesStrictlyByName()
    {
        foreach (var reason in Enum.GetValues<HashFailureReason>())
        {
            var json = JsonSerializer.Serialize(reason);
            Assert.Equal($"\"{reason}\"", json);
            Assert.Equal(reason, JsonSerializer.Deserialize<HashFailureReason>(json));
        }

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<HashFailureReason>("3"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<HashFailureReason>("\"locked\""));
    }
}
