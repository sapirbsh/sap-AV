using System.Text.Json;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Core.Persistence;

namespace SapAV.Core.Tests.Persistence;

/// <summary>D5: the entry ID a client sends for Block &amp; remove, and the alerts that carry it.</summary>
public sealed class PersistenceEntryIdTests
{
    private const string Sid = "S-1-5-21-1000-2000-3000-1001";

    private static PersistenceEntry Run(string command = @"C:\Tools\upd.exe", bool enabled = true, string? sid = Sid) =>
        new(PersistenceKind.RunKey, sid, sid is null ? @"HKLM\SOFTWARE\Run" : $@"HKU\{sid}\Software\Run", "Updater", command,
            ResolvedCommand.Resolved(@"C:\Tools\upd.exe"), enabled);

    [Fact]
    public void Id_IsStable_ChangesWithWhatTheEntryStores_AndNamesKindAndScopeButNotTheSid()
    {
        string id = PersistenceEntryId.Compute(Run());

        Assert.Equal(id, PersistenceEntryId.Compute(Run()));
        Assert.NotEqual(id, PersistenceEntryId.Compute(Run(command: @"C:\Tools\other.exe")));
        Assert.NotEqual(id, PersistenceEntryId.Compute(Run(enabled: false)));
        Assert.StartsWith("pe1-RunKey-u-", id, StringComparison.Ordinal);
        Assert.DoesNotContain(Sid, id, StringComparison.Ordinal);
        Assert.True(PersistenceEntryId.TryParse(PersistenceEntryId.Compute(Run(sid: null)), out var kind, out bool machine));
        Assert.Equal((PersistenceKind.RunKey, true), (kind, machine));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("pe1-RunKey-u-0123")]
    [InlineData("pe1-RunKey-x-0123456789abcdef0123456789abcdef")]
    [InlineData("pe1-NoSuchKind-u-0123456789abcdef0123456789abcdef")]
    [InlineData("pe1-RunKey-u-0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("pe1-RunKey-u-0123456789abcdef0123456789abcdef\n")]
    public void TryParse_RefusesAnythingButAnExactId(string? id) => Assert.False(PersistenceEntryId.TryParse(id, out _, out _));

    [Fact]
    public void PersistenceAlerts_CarryTheEntryId_AndTheActionAlertsNeedTheEntry()
    {
        var autostart = AlertAutostart.From(Run());
        var read = JsonSerializer.Deserialize<AlertAutostart>(JsonSerializer.Serialize(autostart))!;

        Assert.Equal(PersistenceEntryId.Compute(Run()), read.EntryId);
        Assert.Throws<ArgumentException>(() => new AlertAutostart(PersistenceKind.RunKey, "x", null, null, true, "not-an-id"));
        Assert.Throws<ArgumentException>(() => Blocked(autostart: null));
        Assert.Equal(AlertAction.Blocked, Blocked(autostart).Action);
    }

    private static Alert Blocked(AlertAutostart? autostart) =>
        new(Guid.NewGuid(), DateTimeOffset.UnixEpoch, AlertType.PersistenceBlocked, Verdict.Suspicious, @"HKU\x\Run\Updater", null, null, null,
            "T1547.001", [], ["Block & remove by the user."], null, AlertAction.Blocked, ScanTrigger.Persistence, "0.1.0", autostart);
}
