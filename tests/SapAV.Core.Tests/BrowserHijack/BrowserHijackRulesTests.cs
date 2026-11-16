using System.Text;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Tests.BrowserHijack;

/// <summary>E6 (rules): proxy / PAC / WinHTTP and hosts-file hijack rules on synthetic snapshots.</summary>
public class BrowserHijackRulesTests
{
    private const string UserSid = "S-1-5-21-1000-2000-3000-1001";

    private static HostsParseResult ParseHosts(string text) =>
        HostsFileParser.Parse(Encoding.UTF8.GetBytes(text), inputTruncated: false, HostsNameFilter.ToPredicate(HostsNameFilter.DefaultSecurityDomains));

    private static HostsFileSnapshot Hosts(string text = "# empty\n127.0.0.1 localhost\n") => new()
    {
        Read = HijackReadState.Available,
        Path = @"C:\Windows\System32\drivers\etc\hosts",
        Content = ParseHosts(text),
        OwnerIsTrusted = true,
        WritableByNonAdmins = false,
        NumberOfLinks = 1,
        DataBasePathRead = HijackReadState.Available,
        DataBasePathRedirected = false,
    };

    private static BrowserHijackSnapshot Snap(
        ProxySettings? user = null, ProxySettings? userPolicy = null, ProxySettings? machine = null, WinHttpProxySettings? winHttp = null,
        HostsFileSnapshot? hosts = null) => new()
    {
        CollectedAt = new DateTimeOffset(2026, 11, 16, 12, 0, 0, TimeSpan.Zero),
        CollectedAsSystem = true,
        UsersRead = HijackReadState.Available,
        Users = [new UserProxySettings(UserSid, HiveLoaded: true, IsServiceAccount: false, user ?? ProxySettings.Missing, userPolicy ?? ProxySettings.Missing)],
        MachineSettings = machine ?? ProxySettings.Missing,
        MachinePolicy = ProxySettings.Missing,
        WinHttp = winHttp ?? new WinHttpProxySettings { Read = HijackReadState.Available },
        Hosts = hosts ?? Hosts(),
    };

    private static ProxySettings Proxy(string? server = null, string? pac = null, long enable = 1) => new()
    {
        Read = HijackReadState.Available, KeyExists = true, ProxyEnable = enable, ProxyServer = server, AutoConfigUrl = pac,
    };

    private static BrowserHijackAssessment Eval(BrowserHijackSnapshot s, bool? managed = false) =>
        BrowserHijackRules.Evaluate(s, new BrowserHijackRuleOptions { OrganizationManaged = managed });

    private static BrowserHijackAssessment EvalHosts(string text) => Eval(Snap(hosts: Hosts(text)));

    [Fact]
    public void CleanSnapshot_IsClean_AndFullyVerified()
    {
        var a = Eval(Snap());

        Assert.Empty(a.Findings);
        Assert.Empty(a.Unverified);
        Assert.Equal(BrowserHijackOutcome.Clean, a.Outcome);
    }

    [Theory]
    [InlineData("127.0.0.1:8888")]
    [InlineData("http=localhost:8080;https=localhost:8080")]
    [InlineData("[::1]:3128")]
    [InlineData("0x7f.1:8080")] // inet_aton form of 127.0.0.1
    public void LocalProxy_IsSuspicious_T1557(string server)
    {
        var f = Assert.Single(Eval(Snap(user: Proxy(server))).Findings);

        Assert.Equal(BrowserHijackRuleIds.ProxyLocal, f.RuleId);
        Assert.Equal(Verdict.Suspicious, f.Verdict);
        Assert.Equal(MitreTechniqueIds.AdversaryInTheMiddle, f.TechniqueId);
        Assert.Equal(ThreatCategory.BrowserHijack, f.Category);
        Assert.Contains("You decide", f.Reason);
        Assert.Equal(new BrowserHijackItem(BrowserHijackLocation.UserSettings, UserSid, "ProxyServer", server), f.Item);
    }

    [Fact]
    public void PublicIpProxy_IsSuspicious_AndDisabledProxyIsIgnored()
    {
        Assert.Equal(BrowserHijackRuleIds.ProxyPublicAddress, Assert.Single(Eval(Snap(user: Proxy("203.0.113.7:8080"))).Findings).RuleId);
        Assert.Empty(Eval(Snap(user: Proxy("203.0.113.7:8080", enable: 0))).Findings);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public void CorporateProxyByName_DependsOnWhetherThePcIsManaged(bool? managed)
    {
        var a = Eval(Snap(user: Proxy("proxy.corp.example.com:8080"), machine: Proxy(pac: "http://wpad.corp.example.com/wpad.dat")), managed);

        switch (managed)
        {
            case true:
                Assert.Equal(BrowserHijackOutcome.Clean, a.Outcome);
                break;
            case false:
                Assert.All(a.Findings, f => Assert.Equal(Verdict.Suspicious, f.Verdict)); // never Malicious
                Assert.Equal([BrowserHijackRuleIds.PacUnmanaged, BrowserHijackRuleIds.ProxyUnmanaged], a.Findings.Select(f => f.RuleId).Order());
                break;
            default:
                Assert.Empty(a.Findings);
                Assert.Equal(BrowserHijackOutcome.Unverified, a.Outcome);
                Assert.Contains(a.Unverified, u => u.Contains("managed isn't known"));
                break;
        }
    }

    [Fact]
    public void PolicyKeyProxy_IsNamedAsGroupPolicy()
    {
        var f = Assert.Single(Eval(Snap(userPolicy: Proxy("127.0.0.1:9000"))).Findings);

        Assert.Equal(BrowserHijackLocation.UserPolicy, f.Item!.Location);
        Assert.Contains("Group Policy", f.Reason);
    }

    [Fact]
    public void ProxyOnlyInTheConnectionBlob_IsFound()
    {
        var blob = new ConnectionSettingsBlob
        {
            Status = BlobParseStatus.Parsed, Length = 64, RawFlags = (uint)(ConnectionFlags.Direct | ConnectionFlags.Proxy), ProxyServer = "127.0.0.1:8080",
        };
        var settings = Proxy("127.0.0.1:8080", enable: 0) with { DefaultConnection = blob };

        var f = Assert.Single(Eval(Snap(user: settings)).Findings);

        Assert.Equal(BrowserHijackRuleIds.ProxyLocal, f.RuleId);
        Assert.Equal("DefaultConnectionSettings", f.Item!.ValueName);
    }

    [Fact]
    public void LocalProxyPlusPacInUserFolder_IsMalicious()
    {
        const string Pac = "file:///C:/Users/bob/AppData/Roaming/sys/proxy.pac";

        var pacOnly = Assert.Single(Eval(Snap(user: Proxy(pac: Pac, enable: 0))).Findings);
        var both = Eval(Snap(user: Proxy("127.0.0.1:8877", Pac)));

        Assert.Equal(BrowserHijackRuleIds.PacUserFolderFile, pacOnly.RuleId);
        Assert.Equal(Verdict.Suspicious, pacOnly.Verdict);
        Assert.Equal(BrowserHijackOutcome.Malicious, both.Outcome);
        Assert.Equal(BrowserHijackRuleIds.LocalProxyWithUserPac, both.Findings[0].RuleId);
        Assert.Equal(3, both.Findings.Count);
    }

    [Theory]
    [InlineData("http://198.51.100.20/proxy.pac", BrowserHijackRuleIds.PacPublicAddress)]
    [InlineData("http://127.0.0.1:9090/p.pac", BrowserHijackRuleIds.PacLocal)]
    [InlineData("file:///C:/Windows/proxy.pac", BrowserHijackRuleIds.PacLocalFile)]
    [InlineData("data:text/plain,function FindProxyForURL(){}", BrowserHijackRuleIds.PacUnusualUrl)]
    public void UnusualPacSources_AreSuspicious(string pac, string rule)
    {
        var f = Assert.Single(Eval(Snap(machine: Proxy(pac: pac, enable: 0)), managed: true).Findings);

        Assert.Equal(rule, f.RuleId);
        Assert.Equal(Verdict.Suspicious, f.Verdict);
        Assert.Equal(BrowserHijackLocation.MachineSettings, f.Item!.Location);
    }

    [Fact]
    public void WinHttpLocalProxy_IsSuspicious()
    {
        var winHttp = new WinHttpProxySettings
        {
            Read = HijackReadState.Available,
            Settings = new ConnectionSettingsBlob { Status = BlobParseStatus.Parsed, Length = 40, RawFlags = (uint)ConnectionFlags.Proxy, ProxyServer = "127.0.0.1:8888" },
        };

        var f = Assert.Single(Eval(Snap(winHttp: winHttp)).Findings);

        Assert.Equal(BrowserHijackFindingKind.WinHttpProxy, f.Kind);
        Assert.Equal(BrowserHijackRuleIds.ProxyLocal, f.RuleId);
    }

    [Fact]
    public void UnknownStates_GiveUnverified_NeverClean()
    {
        var s = Snap(machine: ProxySettings.Unknown(HijackReadState.AccessDenied), winHttp: WinHttpProxySettings.Unknown(HijackReadState.Failed),
            hosts: new HostsFileSnapshot { Read = HijackReadState.ParserUnavailable, Path = "hosts", DataBasePathRead = HijackReadState.AccessDenied }) with
        {
            Users = [new UserProxySettings(UserSid, false, false, ProxySettings.Unknown(HijackReadState.NotLoaded), ProxySettings.Unknown(HijackReadState.NotLoaded))],
        };

        var a = Eval(s);

        Assert.Empty(a.Findings);
        Assert.Equal(BrowserHijackOutcome.Unverified, a.Outcome);
        Assert.Contains(a.Unverified, u => u.Contains("isn't logged on"));
        Assert.Contains(a.Unverified, u => u.Contains("WinHTTP"));
        Assert.Contains(a.Unverified, u => u.Contains("ParserUnavailable"));
    }

    [Fact]
    public void LockedHostsFile_IsUnverified_NotAFinding()
    {
        var a = Eval(Snap(hosts: Hosts() with { Read = HijackReadState.Locked, Content = null }));

        Assert.Empty(a.Findings);
        Assert.Equal(BrowserHijackOutcome.Unverified, a.Outcome);
        Assert.Contains(a.Unverified, u => u.Contains("locked"));
    }

    [Theory]
    [InlineData("10.6.6.6 update.microsoft.com", "update.microsoft.com")]
    [InlineData("2001:db8::66 www.virustotal.com", "www.virustotal.com")]
    [InlineData("203.0.113.5 login.microsoftonline.com", "login.microsoftonline.com")]
    [InlineData("198.51.100.1 WWW.PayPal.COM.", "WWW.PayPal.COM.")] // case and a trailing dot
    public void HostsRedirectOfListedDomain_IsMalicious_T1565(string line, string name)
    {
        var f = Assert.Single(EvalHosts(line + "\n").Findings);

        Assert.Equal(BrowserHijackRuleIds.HostsRedirectsListedDomain, f.RuleId);
        Assert.Equal(Verdict.Malicious, f.Verdict);
        Assert.Equal(MitreTechniqueIds.StoredDataManipulation, f.TechniqueId);
        Assert.Contains(MitreTechniqueIds.AdversaryInTheMiddle, f.SecondaryTechniqueIds);
        Assert.Equal(name, f.Item!.HostsName);
        Assert.Equal(1, f.Item.HostsLine);
    }

    [Fact]
    public void HostsBlocking_DefenderIsTampering_SecurityIsHijack_AccountsIsNothing()
    {
        var a = EvalHosts("0.0.0.0 definitionupdates.microsoft.com\n::1 www.avast.com\n0.0.0.0 facebook.com\n127.0.0.1 vortex.data.microsoft.com\n");

        Assert.Equal(2, a.Findings.Count);
        var defender = Assert.Single(a.Findings, f => f.RuleId == BrowserHijackRuleIds.HostsBlocksDefenderDomain);
        Assert.Equal(ThreatCategory.DefenderTampering, defender.Category);
        Assert.Equal(MitreTechniqueIds.DisableOrModifyTools, defender.TechniqueId);
        var security = Assert.Single(a.Findings, f => f.RuleId == BrowserHijackRuleIds.HostsBlocksSecurityDomain);
        Assert.Equal(ThreatCategory.BrowserHijack, security.Category);
        Assert.All(a.Findings, f => Assert.Equal(Verdict.Malicious, f.Verdict));
    }

    [Theory]
    [InlineData("microsoft.com.evil.net")]
    [InlineData("evilmicrosoft.com")]
    [InlineData("xn--mcrosoft-n2a.com")] // punycode lookalike: a different domain
    [InlineData("micr\u043Esoft.com")] // Cyrillic o: a homograph, a different domain
    [InlineData("virustotal.com-login.example")]
    public void Lookalikes_DontMatchTheListedDomain(string name)
    {
        Assert.Empty(EvalHosts($"203.0.113.9 {name}\n").Findings);
    }

    [Fact]
    public void FullWidthSpelling_MatchesByIdnMapping()
    {
        var f = Assert.Single(EvalHosts("203.0.113.9 \uFF56\uFF49\uFF52\uFF55\uFF53\uFF54\uFF4F\uFF54\uFF41\uFF4C.com\n").Findings);

        Assert.Equal(BrowserHijackRuleIds.HostsRedirectsListedDomain, f.RuleId);
        Assert.Contains("\"virustotal.com\"", f.Reason); // the ASCII form is shown next to the raw name
    }

    [Fact]
    public void AdBlockList_GivesNothing_EvenPastTheReadCap()
    {
        var sb = new StringBuilder("# ad-block list\n");
        for (int i = 0; i < 600; i++)
        {
            sb.Append(i % 2 == 0 ? "0.0.0.0" : "127.0.0.1").Append($" ads{i}.tracker-example.net\n");
        }

        var hosts = Hosts(sb.ToString());

        Assert.Equal(BrowserHijackOutcome.Clean, Eval(Snap(hosts: hosts)).Outcome);
        var capped = Eval(Snap(hosts: hosts with { ContentTruncated = true }));
        Assert.Empty(capped.Findings);
        Assert.Equal(BrowserHijackOutcome.Unverified, capped.Outcome);
    }

    [Fact]
    public void TruncatedHostsFile_ThatIsntABlockList_IsSuspicious()
    {
        var f = Assert.Single(Eval(Snap(hosts: Hosts("192.168.1.20 nas.home\n") with { ContentTruncated = true })).Findings);

        Assert.Equal(BrowserHijackRuleIds.HostsTruncated, f.RuleId);
        Assert.Equal(Verdict.Suspicious, f.Verdict);
    }

    [Fact]
    public void NonCanonicalAddress_IsSuspicious()
    {
        var f = Assert.Single(EvalHosts("0177.0.0.1 something.example\n").Findings);

        Assert.Equal(BrowserHijackRuleIds.HostsNonCanonicalAddress, f.RuleId);
        Assert.Equal(Verdict.Suspicious, f.Verdict);
        Assert.Equal("0177.0.0.1", f.Item!.RawValue);
    }

    [Fact]
    public void Utf16HostsFile_IsSuspicious()
    {
        var bytes = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("127.0.0.1 localhost\r\n")).ToArray();
        var content = HostsFileParser.Parse(bytes, false);

        var a = Eval(Snap(hosts: Hosts() with { Content = content }));

        Assert.Equal(BrowserHijackRuleIds.HostsEncodingMismatch, Assert.Single(a.Findings).RuleId);
    }

    [Theory]
    [InlineData(@"C:\Windows\hostsdb", Verdict.Suspicious, BrowserHijackRuleIds.HostsDataBasePathRedirected)]
    [InlineData(@"C:\Users\bob\AppData\Local\net", Verdict.Malicious, BrowserHijackRuleIds.HostsDataBasePathUserFolder)]
    public void DataBasePathRedirect_IsFlagged(string path, Verdict verdict, string rule)
    {
        var f = Assert.Single(Eval(Snap(hosts: Hosts() with { DataBasePath = path, DataBasePathExpanded = path, DataBasePathRedirected = true })).Findings);

        Assert.Equal(rule, f.RuleId);
        Assert.Equal(verdict, f.Verdict);
        Assert.Equal(BrowserHijackLocation.DataBasePath, f.Item!.Location);
    }

    [Fact]
    public void WeakPermissionsHardLinksAndRedirectedFolder_AreSuspicious()
    {
        var a = Eval(Snap(hosts: Hosts() with { Read = HijackReadState.Redirected, Content = null, WritableByNonAdmins = true, NumberOfLinks = 2 }));

        Assert.Equal(
            [BrowserHijackRuleIds.HostsHardLinks, BrowserHijackRuleIds.HostsPathRedirected, BrowserHijackRuleIds.HostsWritableByUsers],
            a.Findings.Select(f => f.RuleId).Order());
        Assert.All(a.Findings, f => Assert.Equal(Verdict.Suspicious, f.Verdict));
    }

    [Fact]
    public void ManyRedirects_AreCapped_WithASummary()
    {
        var text = string.Concat(Enumerable.Range(0, 70).Select(i => $"203.0.113.1 h{i}.virustotal.com\n"));

        var a = EvalHosts(text);

        Assert.Equal(BrowserHijackRules.MaxHostsFindingsPerRule + 1, a.Findings.Count);
        Assert.Contains("20 more", Assert.Single(a.Findings, f => f.RuleId == BrowserHijackRuleIds.HostsMoreFlagged).Reason);
    }

    [Fact]
    public void UntrustedText_IsSanitizedForDisplay_RawKeptForRemoval()
    {
        const string Evil = "127.0.0.1:8080\u202Eexe.\nFAKE";

        var f = Assert.Single(Eval(Snap(user: Proxy(Evil))).Findings);

        Assert.DoesNotContain('\u202E', f.Reason);
        Assert.DoesNotContain('\n', f.Reason);
        Assert.Equal(Evil, f.Item!.RawValue);
    }

    [Fact]
    public void ShippedDomainList_LoadsAndIsTheCollectorsKeepFilter()
    {
        var list = SecurityDomainList.Default;

        Assert.Same(list.KeepSuffixes, HostsNameFilter.DefaultSecurityDomains);
        Assert.True(HostsNameFilter.IsValid(list.KeepSuffixes));
        Assert.Equal(SecurityDomainGroup.Defender, list.Classify("fe2.update.microsoft.com", out _));
        Assert.Equal(SecurityDomainGroup.Accounts, list.Classify("www.microsoft.com", out _));
        Assert.Equal(SecurityDomainGroup.Security, list.Classify("VirusTotal.com.", out var suffix));
        Assert.Equal("virustotal.com", suffix);
    }

    [Theory]
    [InlineData("example.com\n")] // before a group
    [InlineData("[nope]\nexample.com\n")]
    [InlineData("[security]\nExample.com\n")]
    [InlineData("[security]\nexample.com\n[accounts]\nexample.com\n")]
    [InlineData("[security]\n.example.com\n")]
    public void DomainList_RejectsInvalidContent(string text)
    {
        Assert.False(SecurityDomainList.TryParse(text, out _, out var error));
        Assert.NotNull(error);
        Assert.Throws<FormatException>(() => SecurityDomainList.Parse(text));
    }
}
