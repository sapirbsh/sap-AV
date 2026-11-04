using System.Security.Principal;
using System.Text;
using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Engine.Tests.Persistence;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

/// <summary>D5 over the real pipe: Block &amp; remove, the backup list and restore, strict JSON, and the per-user rate limit.</summary>
public sealed class PersistencePipeTests : IDisposable
{
    private const string Alice = RemediationHarness.Alice;
    private readonly RemediationHarness _h = new();

    public void Dispose() => _h.Dispose();

    private static CancellationToken Timeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    private static FakeClientIdentity AliceClient() => new(new SecurityIdentifier(Alice), isAdmin: false);

    [Fact]
    public async Task BlockListRestore_RoundTripThroughThePipe_WithoutTheUserSidForAStandardUser()
    {
        _h.UserRunKey(Alice).SetValue("Updater", @"C:\Tools\upd.exe");
        await using var server = new PipeTestServer(remediation: _h.Remediator);
        var client = await server.ConnectAsync(AliceClient());

        var blocked = await client.BlockPersistenceAsync(_h.IdOf("Updater"), Timeout());
        var listed = await client.ListPersistenceBackupsAsync(Timeout());
        var restored = await client.RestorePersistenceAsync(blocked.Backup!.BackupId, Timeout());

        Assert.Equal(PersistenceActionOutcome.Blocked, blocked.Status);
        var info = Assert.Single(listed.Backups);
        Assert.Equal((PersistenceKind.RunKey, false, null, "Updater"), (info.Kind, info.MachineWide, info.UserSid, info.ValueName!.Value));
        Assert.Equal((PersistenceActionOutcome.Restored, PersistenceBackupState.Restored), (restored.Status, restored.Backup!.State));
        Assert.Equal(@"C:\Tools\upd.exe", _h.UserRunKey(Alice).GetValue("Updater"));
    }

    [Fact]
    public async Task MachineEntry_ForAStandardUser_IsAccessDenied_AndAnUnknownBackupIsNotFound()
    {
        _h.Registry.Machine(RemediationHarness.MachineRun).SetValue("Vendor", @"C:\Program Files\Vendor\tray.exe");
        await using var server = new PipeTestServer(remediation: _h.Remediator);
        var client = await server.ConnectAsync(AliceClient());

        var denied = await client.SendRawAsync(PipeRequestKind.PersistenceBlock, new PersistenceBlockRequest(_h.IdOf("Vendor")), Timeout());
        var missing = await client.SendRawAsync(PipeRequestKind.PersistenceRestore, new PersistenceBackupRequest("pb-" + new string('0', 32)), Timeout());

        Assert.Equal(PipeStatus.AccessDenied, denied.Status);
        Assert.Equal(PipeStatus.NotFound, missing.Status);
        Assert.NotNull(_h.Registry.Machine(RemediationHarness.MachineRun).GetValue("Vendor"));
    }

    [Theory]
    [InlineData("""{"Id":7,"Kind":"PersistenceBlock","Body":{}}""")]
    [InlineData("""{"Id":7,"Kind":"PersistenceBlock","Body":{"EntryId":"pe1-RunKey-u-00000000000000000000000000000000","Path":"HKLM\\x"}}""")]
    [InlineData("""{"Id":7,"Kind":"PersistenceBlock","Body":{"EntryId":5}}""")]
    [InlineData("""{"Id":7,"Kind":"PersistenceBackupList","Body":{"All":true}}""")]
    public async Task MalformedBodies_AreBadRequest_AndTheConnectionSurvives(string payload)
    {
        await using var server = new PipeTestServer(remediation: _h.Remediator);
        var client = await server.ConnectAsync(AliceClient());

        var reply = await client.SendBytesAsync(7, Encoding.UTF8.GetBytes(payload), Timeout());
        var list = await client.ListPersistenceBackupsAsync(Timeout());

        Assert.Equal((PipeStatus.BadRequest, 7L), (reply.Status, reply.ReplyTo));
        Assert.Empty(list.Backups);
    }

    [Fact]
    public async Task StandardUsers_AreRateLimited_AdministratorsAreNot()
    {
        await using var server = new PipeTestServer(o => (o.PersistenceRequestBurst, o.PersistenceRequestsPerMinute) = (2, 0.01), remediation: _h.Remediator);
        var user = await server.ConnectAsync(AliceClient());
        var admin = await server.ConnectAsync(new FakeClientIdentity(isAdmin: true));
        string unknown = "pe1-RunKey-u-" + new string('0', 32);

        var statuses = new List<PipeStatus?>();
        for (int i = 0; i < 3; i++)
        {
            statuses.Add((await user.SendRawAsync(PipeRequestKind.PersistenceBlock, new PersistenceBlockRequest(unknown), Timeout())).Status);
        }

        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(PipeStatus.Ok, (await admin.SendRawAsync(PipeRequestKind.PersistenceBlock, new PersistenceBlockRequest(unknown), Timeout())).Status);
        }

        Assert.Equal([PipeStatus.Ok, PipeStatus.Ok, PipeStatus.RateLimited], statuses); // Ok = EntryChanged: no such entry now
    }

    [Fact]
    public async Task WithoutRemediation_TheRequestsAreUnavailable()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(AliceClient());

        var reply = await client.SendRawAsync(PipeRequestKind.PersistenceBackupList, null, Timeout());

        Assert.Equal(PipeStatus.Unavailable, reply.Status);
    }
}
