using SapAV.Core.Defender;
using SapAV.Engine.Defender;
using static SapAV.Engine.Tests.Defender.DefenderWmiData;

namespace SapAV.Engine.Tests.Defender;

/// <summary>E5: WMI property bags -> <see cref="DefenderStatusSnapshot"/>, from synthetic data only.</summary>
public sealed class DefenderStatusMapperTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 11, 12, 0, 0, TimeSpan.Zero);

    private static DefenderStatusSnapshot Map(WmiReadResult status, WmiReadResult preference, WmiReadResult? securityCenter = null) =>
        DefenderStatusMapper.Map(status, preference, securityCenter ?? NoSecurityCenter, Now);

    [Fact]
    public void HealthyDefender_MapsEveryFlag_TheExclusions_AndIsTheActiveAntivirus()
    {
        var prefs = Preference(paths: [@"C:\Dev\build", "D:\\"], extensions: [".log"], processes: [@"C:\Tools\devenv.exe"]);

        var snapshot = Map(One(HealthyStatus()), One(prefs), WmiReadResult.Ok([DefenderProduct(on: true)]));

        Assert.Equal(DefenderReadState.Available, snapshot.Availability);
        Assert.Null(snapshot.Detail);
        Assert.Equal(Now, snapshot.CollectedAt);
        var p = snapshot.Protection;
        Assert.True(p.AntimalwareServiceEnabled & p.AntivirusEnabled & p.AntispywareEnabled & p.RealTimeProtectionEnabled
            & p.OnAccessProtectionEnabled & p.BehaviorMonitorEnabled & p.IoavProtectionEnabled & p.TamperProtected);
        Assert.Equal(DefenderRunningMode.Normal, p.RunningMode);
        Assert.Equal("4.18.25010.11", p.ProductVersion);
        Assert.False(snapshot.Preferences.RealtimeMonitoringDisabled);
        Assert.Equal([@"C:\Dev\build", "D:\\"], snapshot.Exclusions.Paths.Items);
        Assert.Equal([".log"], snapshot.Exclusions.Extensions.Items);
        Assert.Equal([@"C:\Tools\devenv.exe"], snapshot.Exclusions.Processes.Items);
        Assert.Equal(DefenderExclusionListState.Known, snapshot.Exclusions.IpAddresses.State); // null = no IP exclusions
        Assert.Empty(snapshot.Exclusions.IpAddresses.Items);
        Assert.True(snapshot.DefenderIsActiveAntivirus);
        Assert.Equal(DefenderActiveSource.RunningMode, snapshot.ActiveAntivirusDecidedBy);
        Assert.False(snapshot.ThirdPartyAntivirusActive);
        Assert.Equal(DefenderExclusionSource.Wmi, snapshot.Exclusions.Paths.Source);
    }

    [Fact]
    public void AdministratorPlaceholder_IsHidden_NeverAnEmptyKnownList()
    {
        var prefs = Preference(paths: [AdminPlaceholder], extensions: [AdminPlaceholder], processes: [AdminPlaceholder]);
        prefs["ExclusionIpAddress"] = AdminPlaceholder;

        var exclusions = Map(One(HealthyStatus()), One(prefs)).Exclusions;

        foreach (var list in new[] { exclusions.Paths, exclusions.Extensions, exclusions.Processes, exclusions.IpAddresses })
        {
            Assert.Equal(DefenderExclusionListState.Hidden, list.State);
            Assert.Empty(list.Items);
        }
    }

    [Fact]
    public void PlaceholderLookalike_NextToRealExclusions_CantHideThem()
    {
        var prefs = Preference(paths: [AdminPlaceholder, @"C:\Users\Public\x"], extensions: ["N/A: no exclusions here"]);

        var exclusions = Map(One(HealthyStatus()), One(prefs)).Exclusions;

        Assert.Equal(DefenderExclusionListState.Known, exclusions.Paths.State);
        Assert.Equal([AdminPlaceholder, @"C:\Users\Public\x"], exclusions.Paths.Items);
        Assert.Equal(DefenderExclusionListState.Known, exclusions.Extensions.State); // only the exact placeholder text hides a list
        Assert.Equal(["N/A: no exclusions here"], exclusions.Extensions.Items);
    }

    [Fact]
    public void MissingProperties_AndWrongTypes_AreUnknown_NotFalseOrEmpty()
    {
        var status = HealthyStatus();
        status.Remove("IsTamperProtected");          // older Defender: no such property
        status["RealTimeProtectionEnabled"] = "True"; // wrong type
        status["BehaviorMonitorEnabled"] = null;
        status["AMRunningMode"] = "Some Future Mode";
        var prefs = Preference(paths: [@"C:\x"]);
        prefs.Remove("ExclusionIpAddress");
        prefs["ExclusionProcess"] = new[] { 1, 2 };

        var snapshot = Map(One(status), One(prefs));

        Assert.Null(snapshot.Protection.TamperProtected);
        Assert.Null(snapshot.Protection.RealTimeProtectionEnabled);
        Assert.Null(snapshot.Protection.BehaviorMonitorEnabled);
        Assert.Equal(DefenderRunningMode.Unknown, snapshot.Protection.RunningMode);
        Assert.Equal("Some Future Mode", snapshot.Protection.RunningModeText);
        Assert.Equal(DefenderExclusionListState.Unknown, snapshot.Exclusions.IpAddresses.State);
        Assert.Equal(DefenderExclusionListState.Unknown, snapshot.Exclusions.Processes.State);
        Assert.Equal(DefenderExclusionListState.Known, snapshot.Exclusions.Paths.State);
        Assert.Null(snapshot.DefenderIsActiveAntivirus); // unknown mode, no Security Center
    }

    [Fact]
    public void ThirdPartyAntivirus_DefenderPassive_IsNotTheActiveAntivirus()
    {
        var status = HealthyStatus();
        status["AMRunningMode"] = "Passive Mode";
        status["RealTimeProtectionEnabled"] = false;
        var products = WmiReadResult.Ok([DefenderProduct(on: false), Product("Other AV", ThirdPartyGuid, State(on: true))]);

        var snapshot = Map(One(status), One(Preference()), products);

        Assert.Equal(DefenderRunningMode.Passive, snapshot.Protection.RunningMode);
        Assert.False(snapshot.DefenderIsActiveAntivirus);
        Assert.True(snapshot.ThirdPartyAntivirusActive);
        Assert.Collection(snapshot.RegisteredAntivirus!,
            d => Assert.True(d.IsDefender && d.Enabled == false),
            o => Assert.True(!o.IsDefender && o.Enabled == true && o.DisplayName == "Other AV"));
    }

    [Fact]
    public void ThirdPartyAntivirus_DefenderServiceStopped_IsAPlainSnapshot()
    {
        var stopped = WmiReadResult.Failure(WmiReadStatus.ServiceNotRunning, "ManagementException 0x800106BA");
        var products = WmiReadResult.Ok([Product("Other AV", ThirdPartyGuid, State(on: true))]);

        var snapshot = Map(stopped, stopped, products);

        Assert.Equal(DefenderReadState.ServiceNotRunning, snapshot.Availability);
        Assert.Null(snapshot.DefenderIsActiveAntivirus); // a stopped Defender is unknown, never "handed over" (review M3)
        Assert.Equal(DefenderActiveSource.Unknown, snapshot.ActiveAntivirusDecidedBy);
        Assert.True(snapshot.ThirdPartyAntivirusActive);
        Assert.Same(DefenderProtectionState.Unknown, snapshot.Protection);
        Assert.Equal(DefenderExclusionListState.Unknown, snapshot.Exclusions.Paths.State);
        Assert.Contains("0x800106BA", snapshot.Detail);
    }

    [Theory]
    [InlineData(WmiReadStatus.NotFound, DefenderReadState.NotInstalled)]
    [InlineData(WmiReadStatus.AccessDenied, DefenderReadState.AccessDenied)]
    [InlineData(WmiReadStatus.Unavailable, DefenderReadState.WmiUnavailable)]
    [InlineData(WmiReadStatus.TimedOut, DefenderReadState.TimedOut)]
    public void FailedReads_BecomeReadStates_WithEverythingUnknown(WmiReadStatus wmi, DefenderReadState expected)
    {
        var failed = WmiReadResult.Failure(wmi, "why");

        var snapshot = Map(failed, failed);

        Assert.Equal(expected, snapshot.ComputerStatusRead);
        Assert.Equal(expected, snapshot.PreferenceRead);
        Assert.Null(snapshot.Protection.RealTimeProtectionEnabled);
        Assert.Equal(DefenderExclusionListState.Unknown, snapshot.Exclusions.Paths.State);
        Assert.Null(snapshot.RegisteredAntivirus);
        Assert.Contains("MSFT_MpComputerStatus: " + expected, snapshot.Detail);
        Assert.Null(snapshot.DefenderIsActiveAntivirus); // review M1: not installed, without Security Center, is unknown
        Assert.Null(snapshot.ThirdPartyAntivirusActive); // review M2: Security Center unknown
        Assert.Null(snapshot.DefenderExpected);
    }

    [Fact]
    public void StatusReadable_PreferencesDenied_KeepsTheStatus_AndMarksExclusionsUnknown()
    {
        var snapshot = Map(One(HealthyStatus()), WmiReadResult.Failure(WmiReadStatus.AccessDenied, null));

        Assert.Equal(DefenderReadState.Available, snapshot.ComputerStatusRead);
        Assert.Equal(DefenderReadState.AccessDenied, snapshot.Availability);
        Assert.True(snapshot.Protection.RealTimeProtectionEnabled);
        Assert.Equal(DefenderExclusionListState.Unknown, snapshot.Exclusions.Paths.State);
        Assert.Null(snapshot.Preferences.RealtimeMonitoringDisabled);
    }

    [Fact]
    public void ExclusionItems_AreStoredRaw_OnlyUnloggableCharactersReplaced()
    {
        var hostile = Preference(paths: ["C:\\a\r\nfake  line\u0007", @" C:\lead\  ", new string('x', DefenderExclusionList.MaxItemLength + 50), "  ", null!]);

        var paths = Map(One(HealthyStatus()), One(hostile)).Exclusions.Paths;

        Assert.Equal(3, paths.Items.Count);
        Assert.Equal("C:\\a\uFFFD\uFFFDfake  line\uFFFD", paths.Items[0]); // same length, nothing collapsed
        Assert.Equal(@" C:\lead\  ", paths.Items[1]);                     // nothing trimmed
        Assert.Equal(new string('x', DefenderExclusionList.MaxItemLength), paths.Items[2]); // cut at the cap, no ellipsis
        Assert.True(paths.Truncated);
        Assert.Equal(2, paths.BlankItemsDropped);
        Assert.DoesNotContain(DefenderExclusionList.ForDisplay("C:\\a\r\nfake line"), c => char.IsControl(c)); // display only
    }

    [Fact]
    public void PaddedList_IsTruncated_KeepingTheFirstAndLastHalf_AndTheRealCount()
    {
        const int total = 600;
        var prefs = Preference(extensions: Enumerable.Range(0, total).Select(i => $".e{i}").ToArray());

        var extensions = Map(One(HealthyStatus()), One(prefs)).Exclusions.Extensions;

        Assert.True(extensions.Truncated); // surfaced: a padded list is suspicious in itself
        Assert.Equal(total, extensions.TotalCount);
        Assert.Equal(DefenderExclusionList.MaxItems, extensions.Items.Count);
        Assert.Equal(".e0", extensions.Items[0]);
        Assert.Equal(".e255", extensions.Items[255]);
        Assert.Equal($".e{total - 256}", extensions.Items[256]);
        Assert.Equal($".e{total - 1}", extensions.Items[^1]); // an entry appended at the end is never pushed out of view
    }

    [Fact]
    public void NotInstalled_UsesSecurityCenter_AndIsATamperSignOnAClient()
    {
        var missing = WmiReadResult.Failure(WmiReadStatus.NotFound, "0x8004100E");
        var client = new DefenderEnvironmentInfo(IsClientSku: true, RunningAsSystem: true, DefenderRegistryExclusions.Unreadable);
        var thirdParty = WmiReadResult.Ok([Product("Other AV", ThirdPartyGuid, State(on: true))]);

        var withCenter = DefenderStatusMapper.Map(missing, missing, thirdParty, Now, client);
        var withoutCenter = DefenderStatusMapper.Map(missing, missing, NoSecurityCenter, Now, client);

        Assert.Equal(DefenderReadState.NotInstalled, withCenter.Availability);
        Assert.True(withCenter.DefenderExpected);
        Assert.False(withCenter.DefenderIsActiveAntivirus);
        Assert.Equal(DefenderActiveSource.SecurityCenter, withCenter.ActiveAntivirusDecidedBy);
        Assert.Null(withoutCenter.DefenderIsActiveAntivirus);
        Assert.Null(withoutCenter.ThirdPartyAntivirusActive);
    }

    [Fact]
    public void FailedStatusRead_IgnoresSecurityCenter_EvenWhenAnotherProductIsOn()
    {
        var timedOut = WmiReadResult.Failure(WmiReadStatus.TimedOut, null);
        var products = WmiReadResult.Ok([DefenderProduct(on: false), Product("Other AV", ThirdPartyGuid, State(on: true))]);

        var snapshot = Map(timedOut, One(Preference()), products);

        Assert.Null(snapshot.DefenderIsActiveAntivirus);
        Assert.Equal(DefenderActiveSource.Unknown, snapshot.ActiveAntivirusDecidedBy);
        Assert.True(snapshot.ThirdPartyAntivirusActive);
    }

    [Fact]
    public void HiddenFromSystem_IsFlagged_AndTheRegistryFallbackFillsReadableLists()
    {
        var prefs = Preference(paths: [AdminPlaceholder], extensions: [AdminPlaceholder], processes: [AdminPlaceholder]);
        var registry = new DefenderRegistryExclusions(Paths: [@"C:\Games"], Extensions: null, Processes: [], IpAddresses: null);
        var environment = new DefenderEnvironmentInfo(IsClientSku: true, RunningAsSystem: true, registry);

        var snapshot = DefenderStatusMapper.Map(One(HealthyStatus()), One(prefs), NoSecurityCenter, Now, environment);

        Assert.True(snapshot.CollectedAsSystem);
        Assert.True(snapshot.ExclusionsHiddenFromSystem);
        Assert.Equal(DefenderExclusionSource.Registry, snapshot.Exclusions.Paths.Source);
        Assert.Equal([@"C:\Games"], snapshot.Exclusions.Paths.Items);
        Assert.Equal(DefenderExclusionListState.Known, snapshot.Exclusions.Processes.State);
        Assert.Equal(DefenderExclusionListState.Hidden, snapshot.Exclusions.Extensions.State); // registry couldn't read it either
        Assert.Equal(DefenderExclusionListState.Known, snapshot.Exclusions.IpAddresses.State); // WMI null list stays Known (WMI)
        Assert.Equal(DefenderExclusionSource.Wmi, snapshot.Exclusions.IpAddresses.Source);
    }

    [Theory]
    [InlineData("Normal", DefenderRunningMode.Normal)]
    [InlineData("SxS Passive Mode", DefenderRunningMode.SideBySidePassive)]
    [InlineData("EDR Block Mode", DefenderRunningMode.EdrBlock)]
    [InlineData("", DefenderRunningMode.Unknown)]
    public void RunningMode_IsParsed(string text, DefenderRunningMode expected) =>
        Assert.Equal(expected, DefenderStatusMapper.ParseRunningMode(text));
}
