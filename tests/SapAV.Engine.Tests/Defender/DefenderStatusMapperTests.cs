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
        Assert.False(snapshot.ThirdPartyAntivirusActive);
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
        var prefs = Preference(paths: [AdminPlaceholder, @"C:\Users\Public\x"]);

        var paths = Map(One(HealthyStatus()), One(prefs)).Exclusions.Paths;

        Assert.Equal(DefenderExclusionListState.Known, paths.State);
        Assert.Equal([AdminPlaceholder, @"C:\Users\Public\x"], paths.Items);
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
        Assert.False(snapshot.DefenderIsActiveAntivirus);
        Assert.True(snapshot.ThirdPartyAntivirusActive);
        Assert.Same(DefenderProtectionState.Unknown, snapshot.Protection);
        Assert.Same(DefenderExclusions.Unknown, snapshot.Exclusions);
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
        Assert.Equal(expected == DefenderReadState.NotInstalled ? false : null, snapshot.DefenderIsActiveAntivirus);
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
    public void ExclusionText_IsSanitized_AndCapped()
    {
        var many = Enumerable.Range(0, DefenderExclusionList.MaxItems + 5).Select(i => $@"C:\e{i}").ToArray();
        var hostile = Preference(paths: ["C:\\a\r\nfake line\u0007", new string('x', DefenderExclusionList.MaxItemLength + 50), "  ", null!]);
        hostile["ExclusionExtension"] = many;

        var exclusions = Map(One(HealthyStatus()), One(hostile)).Exclusions;

        Assert.Equal(2, exclusions.Paths.Items.Count); // blank and null entries dropped
        Assert.DoesNotContain(exclusions.Paths.Items[0], c => char.IsControl(c));
        Assert.True(exclusions.Paths.Items[1].Length <= DefenderExclusionList.MaxItemLength);
        Assert.True(exclusions.Paths.Truncated);
        Assert.Equal(DefenderExclusionList.MaxItems, exclusions.Extensions.Items.Count);
        Assert.True(exclusions.Extensions.Truncated);
    }

    [Theory]
    [InlineData("Normal", DefenderRunningMode.Normal)]
    [InlineData("SxS Passive Mode", DefenderRunningMode.SideBySidePassive)]
    [InlineData("EDR Block Mode", DefenderRunningMode.EdrBlock)]
    [InlineData("", DefenderRunningMode.Unknown)]
    public void RunningMode_IsParsed(string text, DefenderRunningMode expected) =>
        Assert.Equal(expected, DefenderStatusMapper.ParseRunningMode(text));
}
