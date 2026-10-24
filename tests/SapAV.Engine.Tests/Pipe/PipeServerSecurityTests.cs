using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Core.Pipe;
using SapAV.Engine.Pipe;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Pipe;

public sealed class PipeServerSecurityTests
{
    [Fact]
    public async Task PipeDacl_AsBuilt_SystemFull_AuthenticatedUsersConnectWithoutCreateInstance_Protected()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync();

        var sd = PipeNative.TryReadKernelObjectSecurity(client.PipeHandle);

        Assert.NotNull(sd);
        Assert.True(sd!.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected));
        var aces = sd.DiscretionaryAcl!.Cast<CommonAce>().ToArray();
        Assert.All(aces, a => Assert.Equal(AceQualifier.AccessAllowed, a.AceQualifier));
        Assert.Contains(aces, a => a.SecurityIdentifier == EnginePipeSecurity.LocalSystem && a.AccessMask == EnginePipeSecurity.FullControl);
        var users = Assert.Single(aces, a => a.SecurityIdentifier == EnginePipeSecurity.AuthenticatedUsers);
        Assert.Equal(EnginePipeSecurity.ClientAccess, users.AccessMask);
        Assert.Equal(0, users.AccessMask & (int)PipeNative.FileCreatePipeInstance);
        Assert.DoesNotContain(aces, a => a.SecurityIdentifier.Value is "S-1-1-0" or "S-1-15-2-1"); // no Everyone, no AppContainers
        Assert.Equal(EnginePipeSecurity.CurrentAccount(), sd.Owner);
    }

    [Fact]
    public void AnAccountWithoutTheServerEntry_CannotCreateAnotherInstance()
    {
        string name = @"\\.\pipe\sap-AV.engine.test." + Guid.NewGuid().ToString("N");
        var sd = EnginePipeSecurity.ToBytes(EnginePipeSecurity.Create(EnginePipeSecurity.CurrentAccount(), serverAccount: null)); // SYSTEM + Authenticated Users only
        uint mode = PipeNative.PipeAccessDuplex | PipeNative.FileFlagOverlapped;
        uint pipeMode = PipeNative.PipeRejectRemoteClients;
        using var first = PipeNative.CreatePipe(name, mode | PipeNative.FileFlagFirstPipeInstance, pipeMode, 4, 4096, sd, out int firstError);
        Assert.False(first.IsInvalid, $"first instance: Win32 error {firstError}");

        using var second = PipeNative.CreatePipe(name, mode, pipeMode, 4, 4096, sd, out int error);

        Assert.True(second.IsInvalid);
        Assert.Equal(PipeNative.ErrorAccessDenied, error);
    }

    [Fact]
    public async Task ASquattedPipeName_IsRefused_FirstPipeInstance()
    {
        string name = "sap-AV.engine.test." + Guid.NewGuid().ToString("N");
        var permissive = EnginePipeSecurity.ToBytes(EnginePipeSecurity.Create(EnginePipeSecurity.CurrentAccount(), EnginePipeSecurity.CurrentAccount()));
        using var squatter = PipeNative.CreatePipe(@"\\.\pipe\" + name, PipeNative.PipeAccessDuplex | PipeNative.FileFlagOverlapped, 0, 8, 4096,
            permissive, out _);
        Assert.False(squatter.IsInvalid);

        await using var server = new PipeTestServer(o => o.PipeName = name);

        await Assert.ThrowsAsync<PipeNameTakenException>(() => server.Server.Listening.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task Client_RefusesAPipeNotOwnedBySystem()
    {
        await using var server = new PipeTestServer();
        await server.Server.Listening;

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            EnginePipeClient.ConnectAsync(server.Options.PipeName, requireSystemServer: true, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task RealIdentity_ComesFromThePipeClientToken()
    {
        await using var server = new PipeTestServer();
        var client = await server.ConnectAsync(); // no injected identity: the production resolver runs

        using var me = WindowsIdentity.GetCurrent();
        bool elevated = new WindowsPrincipal(me).IsInRole(WindowsBuiltInRole.Administrator);
        Assert.Equal(me.User!.Value, client.Hello!.Client.UserSid);
        Assert.Equal(System.Diagnostics.Process.GetCurrentProcess().SessionId, client.Hello.Client.SessionId);
        Assert.Equal(elevated, client.Hello.Client.IsAdmin);
        Assert.Equal(PipeProtocol.Version, client.Hello.Version);
    }

    [Fact]
    public void TokenIdentity_IsGranted_HonoursADenyAceForTheUser()
    {
        using var temp = new TempDir();
        using var identity = TokenClientIdentity.ForCurrentProcess();
        var injected = new FakeClientIdentity(identity.User);
        try
        {
            Assert.Equal(AccessDecision.Granted, ClientAccess.CanReadOrList(injected, temp.Path));
            using (new DenyAce(temp.Path, FileSystemRights.ListDirectory))
            {
                Assert.Equal(AccessDecision.Denied, ClientAccess.CanReadOrList(injected, temp.Path));
            }

            Assert.Equal(AccessDecision.NotFound, ClientAccess.CanReadOrList(injected, Path.Combine(temp.Path, "missing")));
        }
        finally
        {
            injected.Dispose();
        }
    }
}
