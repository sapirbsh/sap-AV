using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.EventLogging;

public sealed class EventLogCustomSdTests
{
    private const string Expected = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)";

    [Fact]
    public void Sddl_IsExactlyTheDocumentedString()
    {
        Assert.Equal(Expected, EventLogCustomSd.Build());
        Assert.Equal(Expected, EventLogCustomSd.Sddl);
        Assert.Equal(Expected, EventLogSettings.Default.CustomSd);
    }

    [Fact]
    public void Sddl_ParsesBackToOnlySystemAdministratorsAndEventLogReaders()
    {
        var descriptor = EventLogCustomSd.TryParse(EventLogCustomSd.Sddl)!;

        Assert.Equal(EventLogCustomSd.Administrators, descriptor.Owner);
        Assert.Equal(EventLogCustomSd.LocalSystem, descriptor.Group);
        var grants = descriptor.DiscretionaryAcl!.Cast<CommonAce>()
            .Select(a => (a.AceQualifier, a.AceFlags, a.SecurityIdentifier.Value, a.AccessMask)).ToList();
        Assert.Equal(
        [
            (AceQualifier.AccessAllowed, AceFlags.None, "S-1-5-18", 0xF0007),     // SYSTEM: read, write, clear + standard
            (AceQualifier.AccessAllowed, AceFlags.None, "S-1-5-32-544", 0x7),     // Administrators: read, write, clear
            (AceQualifier.AccessAllowed, AceFlags.None, "S-1-5-32-573", 0x1),     // Event Log Readers: read
        ], grants);
    }

    [Theory]
    [InlineData("O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;ER)", true)] // ER = the alias of S-1-5-32-573
    [InlineData("O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x3;;;IU)", false)] // INTERACTIVE may write
    [InlineData("O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;S-1-5-32-573)", false)] // readers may write
    [InlineData("not sddl", false)]
    [InlineData("", false)]
    public void IsExpected_ComparesTheDescriptorNotTheSpelling(string sddl, bool expected)
    {
        Assert.Equal(expected, EventLogCustomSd.IsExpected(sddl));
    }

    [Fact]
    public void NonAdminToken_GetsNoWriteOrClearAccess()
    {
        Assert.NotEqual(WindowsIdentity.GetCurrent().User, EventLogCustomSd.LocalSystem); // the test itself must not run as SYSTEM
        using var token = FilteredToken.CreateNonAdmin();
        var descriptor = EventLogCustomSd.TryParse(EventLogCustomSd.Sddl)!;

        Assert.Equal(0, FilteredToken.GrantedAccess(token, descriptor, EventLogCustomSd.LogFileWrite));
        Assert.Equal(0, FilteredToken.GrantedAccess(token, descriptor, EventLogCustomSd.LogFileClear));
    }

    [Fact]
    public void DefaultSettings_Are20MbOverwriteAsNeeded_NoBackups()
    {
        var settings = EventLogSettings.Default;

        Assert.Equal(20 * 1024 * 1024, settings.MaxSizeBytes);
        Assert.Equal(0, settings.MaxSizeBytes % (64 * 1024)); // classic logs need a multiple of 64 KB
        Assert.Equal((0, false), (settings.RetentionSeconds, settings.AutoBackup));
    }
}
