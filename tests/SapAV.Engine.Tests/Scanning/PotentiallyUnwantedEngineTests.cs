using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Quarantine;
using SapAV.Engine.Alerts;
using SapAV.Engine.Scanning.Cache;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>E1 in the engine: persisted data from before the PotentiallyUnwanted verdict, and the alert budget for PUP alerts.</summary>
public sealed class PotentiallyUnwantedEngineTests
{
    [Fact]
    public void ScanCache_FromBeforeE1_IsCleanlyInvalidated_RowsDropped_NotACorruptionRebuild()
    {
        using var h = new CacheHarness();
        h.Cache.Store.Put(ScanCacheTests.SampleRow(1));
        h.Cache.Store.Put(ScanCacheTests.SampleRow(2) with { Verdict = Verdict.PotentiallyUnwanted }); // a PUP row stores and reads back
        Assert.Equal(Verdict.PotentiallyUnwanted, h.Cache.Store.Get(ScanCacheTests.SampleRow(2).Stamp.Volume, ScanCacheTests.SampleRow(2).Stamp.FileId)!.Verdict);
        h.Cache.Dispose();
        SqliteConnection.ClearAllPools();

        string database = Path.Combine(h.Folder, ScanCacheStore.DatabaseName);
        using (var connection = new SqliteConnection($"Data Source={database};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version = 1"; // what a pre-E1 engine wrote (old verdict numbers)
            command.ExecuteNonQuery();
        }

        using var reopened = h.CreateCache();

        Assert.Equal(0, reopened.Store.Count());
        Assert.Equal(0, reopened.Store.Rebuilds);
        Assert.Null(reopened.Store.LastProblem);
        using var check = new SqliteConnection($"Data Source={database};Pooling=False");
        check.Open();
        using var version = check.CreateCommand();
        version.CommandText = "PRAGMA user_version";
        Assert.Equal(2L, (long)version.ExecuteScalar()!);
    }

    [Fact]
    public void PupAlerts_CountAgainstTheAlertCap_LikeSuspicious_WhileMaliciousStaysUncapped()
    {
        var sink = new RecordingAlertSink();
        using var dispatcher = new AlertDispatcher(sink, TimeProvider.System, NullLogger<AlertDispatcher>.Instance, TimeSpan.FromMinutes(10), 1, 64);

        Assert.True(dispatcher.Post(SampleAlerts.Create(AlertType.PotentiallyUnwantedFile, path: @"C:\Users\u\Downloads\pup-a.exe")));
        Assert.False(dispatcher.Post(SampleAlerts.Create(AlertType.PotentiallyUnwantedFile, path: @"C:\Users\u\Downloads\pup-b.exe")));
        Assert.True(dispatcher.Post(SampleAlerts.Create(AlertType.MaliciousFile, path: @"C:\Users\u\Downloads\mal.exe")));
    }

    [Fact]
    public void DecodedPowerShell_IsForTheAdminPipeOnly_SanitizedAndCapped()
    {
        // E4 review L3: the decoded command is attacker-written; it is shown to administrators from the entry, never in reasons.
        string script = "Write-Output 'sapav-e4'\r\n\u202E" + new string('x', 400);
        string arguments = "-NoProfile -enc " + Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
        var resolution = Core.Persistence.ResolvedCommand.Unresolved(Core.Persistence.TargetUnresolvedReason.InlineCommand,
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", arguments,
            [Core.Persistence.ResolutionFlag.InterpreterHost, Core.Persistence.ResolutionFlag.InlineCommand]);
        var entry = new Core.Persistence.PersistenceEntry(Core.Persistence.PersistenceKind.RunKey, null,
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Upd", "powershell.exe " + arguments, resolution, true);

        string? decoded = Engine.Pipe.PipeMapping.DecodedCommand(entry);

        Assert.StartsWith("Write-Output 'sapav-e4'", decoded, StringComparison.Ordinal);
        Assert.True(decoded!.Length <= Core.Persistence.EncodedPowerShell.MaxDisplayLength);
        Assert.DoesNotContain('\u202E', decoded);
        Assert.DoesNotContain('\n', decoded);
    }

    [Fact]
    public void QuarantineMetadata_AcceptsAPupTheUserChoseToQuarantine_ButNeverClean()
    {
        var metadata = new QuarantineMetadata
        {
            Id = QuarantineItemId.New(), State = QuarantineState.Quarantined, MoveKind = QuarantineMoveKind.SameVolume,
            OriginalPath = @"C:\Users\u\Downloads\keygen.exe", ScannedPath = @"C:\Users\u\Downloads\keygen.exe", SizeBytes = 1,
            Sha256 = new string('a', 64), SourceVolumeSerial = 1, SourceFileId = QuarantineItemId.New(), Attributes = 0,
            CreationTimeUtc = DateTimeOffset.UnixEpoch, LastWriteTimeUtc = DateTimeOffset.UnixEpoch, LastAccessTimeUtc = DateTimeOffset.UnixEpoch,
            Verdict = Verdict.PotentiallyUnwanted, Reasons = ["YARA rule Test_Keygen matched"], TechniqueIds = ["T1204.002"],
            Trigger = ScanTrigger.CustomScan, ScanTimestamp = DateTimeOffset.UnixEpoch, QuarantinedAtUtc = DateTimeOffset.UnixEpoch,
            TransformAlgorithm = QuarantineContentTransform.Algorithm, TransformKey = new byte[QuarantineContentTransform.KeyLength],
        };

        metadata.Validate();
        Assert.Throws<InvalidDataException>(() => (metadata with { Verdict = Verdict.Clean }).Validate());
    }
}
