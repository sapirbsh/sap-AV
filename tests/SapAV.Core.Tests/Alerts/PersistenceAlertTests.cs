using System.Text.Json;
using SapAV.Core.Alerts;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Tests.Persistence;
using static SapAV.Core.Tests.Persistence.Judging;

namespace SapAV.Core.Tests.Alerts;

/// <summary>C3: alerts for judged autostart entries (MaliciousPersistence / SuspiciousPersistence).</summary>
public sealed class PersistenceAlertTests
{
    private const string Version = "0.1.0+test";
    private const string Target = @"C:\Users\alice\AppData\Local\Temp\drop.exe";
    private static readonly DateTimeOffset Now = new(2026, 10, 28, 9, 0, 0, TimeSpan.Zero);

    private static PersistenceFinding Finding(Verdict? targetVerdict, string? valueName = "Updater")
    {
        var entry = Entry(Target, sid: Sid, valueName: valueName);
        var report = Report(Target, targetVerdict);
        return new PersistenceFinding(entry, Judge.Judge(entry, report, null, new FakeAcl().WithFolder(@"C:\Users\alice")), report.Result, null);
    }

    [Fact]
    public void MaliciousTarget_GivesAMaliciousPersistenceAlert_WithTheEntry_AndRoundTripsAsJson()
    {
        var alert = Alert.FromPersistence(Finding(Verdict.Malicious), AlertAction.None, ScanTrigger.QuickScan, Now, Version)!;

        Assert.Equal((AlertType.MaliciousPersistence, Verdict.Malicious), (alert.Type, alert.Verdict));
        Assert.Equal(Target, alert.FilePath);
        Assert.Equal(new string('a', 64), alert.Sha256);
        Assert.Equal(MitreTechniqueIds.MaliciousFile, alert.TechniqueId);
        Assert.Contains(MitreTechniqueIds.RegistryRunKeysStartupFolder, alert.SecondaryTechniqueIds);
        Assert.StartsWith("Autostart target: YARA rule", alert.Reasons[0], StringComparison.Ordinal);
        Assert.Equal((PersistenceKind.RunKey, UserRun, "Updater", Sid), (alert.Autostart!.Kind, alert.Autostart.Location, alert.Autostart.ValueName, alert.Autostart.UserSid));

        var back = JsonSerializer.Deserialize<Alert>(JsonSerializer.Serialize(alert))!;
        Assert.Equal(alert, back);
    }

    [Fact]
    public void RuleOnlyFinding_IsSuspiciousPersistence_AndCleanGivesNoAlert()
    {
        var suspicious = Alert.FromPersistence(Finding(null), AlertAction.None, ScanTrigger.QuickScan, Now, Version)!;
        Assert.Equal((AlertType.SuspiciousPersistence, MitreTechniqueIds.RegistryRunKeysStartupFolder), (suspicious.Type, suspicious.TechniqueId));
        Assert.Contains(suspicious.Reasons, r => r.Contains("Temp", StringComparison.Ordinal));

        var vendor = @"C:\Program Files\Contoso\app.exe";
        var entry = Entry(vendor);
        var clean = new PersistenceFinding(entry, Judge.Judge(entry, Report(vendor, signature: VendorSigned()), null, new FakeAcl()), null, null);
        Assert.Null(Alert.FromPersistence(clean, AlertAction.None, ScanTrigger.QuickScan, Now, Version));
    }

    [Fact]
    public void TwoEntriesRunningTheSameFile_GetDifferentAlertIds()
    {
        var a = Alert.FromPersistence(Finding(Verdict.Malicious, "One"), AlertAction.None, ScanTrigger.QuickScan, Now, Version)!;
        var b = Alert.FromPersistence(Finding(Verdict.Malicious, "Two"), AlertAction.None, ScanTrigger.QuickScan, Now, Version)!;

        Assert.NotEqual(a.AlertId, b.AlertId);
        Assert.NotEqual(a.Autostart!.Key, b.Autostart!.Key);
    }

    [Fact]
    public void PersistenceTypes_RequireTheAutostartEntry_AndOtherTypesRefuseIt()
    {
        var autostart = new AlertAutostart(PersistenceKind.RunKey, MachineRun, "x", null, true);
        Alert Make(AlertType type, Verdict verdict, AlertAutostart? entry) => new(Guid.NewGuid(), Now, type, verdict, Target, null, null, null,
            "T1547.001", [], ["reason"], null, AlertAction.None, ScanTrigger.QuickScan, Version, entry);

        Assert.NotNull(Make(AlertType.SuspiciousPersistence, Verdict.Suspicious, autostart));
        Assert.Throws<ArgumentException>(() => Make(AlertType.SuspiciousPersistence, Verdict.Suspicious, null));
        Assert.Throws<ArgumentException>(() => Make(AlertType.MaliciousPersistence, Verdict.Suspicious, autostart)); // verdict must fit
        Assert.Throws<ArgumentException>(() => Make(AlertType.SuspiciousFile, Verdict.Suspicious, autostart));
    }

    [Fact]
    public void AutostartText_IsSanitizedAndCapped()
    {
        var entry = new AlertAutostart(PersistenceKind.RunKey, MachineRun + @"\" + new string('k', 2000), "bad\u0007name", null, true);

        Assert.Equal(AlertAutostart.MaxLocationLength, entry.Location.Length);
        Assert.DoesNotContain("\u0007", entry.ValueName!, StringComparison.Ordinal);
    }
}
