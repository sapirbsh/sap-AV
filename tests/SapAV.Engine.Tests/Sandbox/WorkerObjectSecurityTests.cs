using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>The worker process/thread DACL check (review H1) must fail closed.</summary>
public sealed class WorkerObjectSecurityTests
{
    private static RawSecurityDescriptor Ours() => new(WorkerObjectSecurity.DescriptorBytes(), 0);

    [Fact]
    public void OurDescriptor_IsLockedDown() => Assert.True(WorkerObjectSecurity.IsLockedDown(Ours()));

    [Fact]
    public void AnyOtherAceType_FailsClosed()
    {
        var sd = Ours();
        sd.DiscretionaryAcl!.InsertAce(0, new ObjectAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            ObjectAceFlags.ObjectAceTypePresent, Guid.NewGuid(), Guid.Empty, false, null));

        Assert.False(WorkerObjectSecurity.IsLockedDown(sd));
    }

    [Theory]
    [InlineData("S-1-1-0")] // Everyone
    [InlineData("S-1-15-2-1")] // ALL APPLICATION PACKAGES
    [InlineData("S-1-15-2-11-22-33-44-55-66-77")] // an AppContainer
    public void AnAllowForAnyoneElse_IsRejected(string sid)
    {
        var sd = Ours();
        sd.DiscretionaryAcl!.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x0010 /* PROCESS_VM_READ */, new SecurityIdentifier(sid), false, null));

        Assert.False(WorkerObjectSecurity.IsLockedDown(sd));
    }

    [Fact]
    public void AnUnprotectedDacl_IsRejected_ButADenyEntryIsFine()
    {
        var unprotected = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, Ours().DiscretionaryAcl);
        Assert.False(WorkerObjectSecurity.IsLockedDown(unprotected));

        var withDeny = Ours();
        withDeny.DiscretionaryAcl!.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 0x1FFFFF, new SecurityIdentifier("S-1-1-0"), false, null));
        Assert.True(WorkerObjectSecurity.IsLockedDown(withDeny));
    }
}
