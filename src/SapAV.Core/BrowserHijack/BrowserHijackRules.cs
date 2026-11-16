using System.Net;
using System.Net.Sockets;
using SapAV.Core.Defender;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Text;

namespace SapAV.Core.BrowserHijack;

/// <summary>What the browser-hijack rules need besides the snapshot.</summary>
public sealed record BrowserHijackRuleOptions
{
    public static BrowserHijackRuleOptions Default { get; } = new();

    /// <summary>The domain list hosts entries are judged against; null = <see cref="SecurityDomainList.Default"/>.</summary>
    public SecurityDomainList? Domains { get; init; }

    /// <summary>
    /// True when the PC is managed by an organization (joined to an Active Directory domain, or Entra ID / MDM managed), where a
    /// proxy or PAC set by host name or private address is normal; false when it is known not to be; null when unknown (such
    /// proxies are then listed as Unverified, never as findings). E7 passes it.
    /// </summary>
    public bool? OrganizationManaged { get; init; }
}

/// <summary>
/// The browser-hijack rules (ROADMAP E6, threat pack "Browser hijack"): a pure function from a <see cref="BrowserHijackSnapshot"/>
/// to findings. No I/O, no machine state, nothing is changed.
/// </summary>
/// <remarks>
/// <para><b>Unknown is never benign, and never an alarm.</b> A part that wasn't read (a hive that isn't loaded, a denied key, an
/// unparsed blob, a locked or unparsed hosts file, an unknown permission) gives no finding and is listed in
/// <see cref="BrowserHijackAssessment.Unverified"/>, so the outcome is Unverified rather than Clean.</para>
/// <para><b>Proxy / PAC</b> (every WinINet key: per user, machine-wide and both Group Policy keys; and the WinHTTP proxy), T1557,
/// Suspicious by default: a proxy on this PC (localhost, 127.x, ::1) or at a public IP address; a PAC script from this PC
/// (localhost, a <c>file://</c> path, worse in a user-writable folder), a public IP, a network share or an odd scheme. A proxy or
/// PAC by host name or private address is what organizations use: nothing on a managed PC, Suspicious on a PC known not to be
/// managed, Unverified when that isn't known. Malicious only for the clear local-interception pattern: a localhost proxy plus a
/// PAC file in a user-writable folder for the same account.</para>
/// <para><b>Hosts entries</b> for a domain on the <see cref="SecurityDomainList"/> (lookalikes such as
/// <c>microsoft.com.evil.net</c> or <c>evilmicrosoft.com</c> don't match): sent to any non-blocking address → Malicious,
/// T1565.001; blocked (0.0.0.0, 127.x, ::, ::1) → Malicious, T1562.001, as Defender tampering for Windows Update / Defender
/// domains and browser hijack for antivirus vendors and scanners; blocking a sign-in or banking site → nothing (privacy and
/// social block lists). Ad-block lists give nothing. A non-canonical address (octal, hex, integer) → Suspicious.</para>
/// <para><b>The hosts file</b>, T1565.001: UTF-16 byte order mark or entries that differ between readings, truncation (a padded
/// file; a large file of blocking entries is an ad-block list and only Unverified past the read cap), writable by non-admins or
/// a non-admin owner, extra hard links, a junction on the way → Suspicious; DataBasePath pointing elsewhere → Suspicious,
/// Malicious when it points into a user-writable folder. A Locked hosts file is Unverified here; E7 tracks one that stays locked
/// across snapshots.</para>
/// <para>Every finding says the user decides, is never quarantined, and keeps its raw item (<see cref="BrowserHijackFinding.Item"/>)
/// for a later user-confirmed removal.</para>
/// </remarks>
public static class BrowserHijackRules
{
    public const int MaxHostsFindingsPerRule = 50;

    /// <summary>A hosts file with at least this many entries, nearly all blocking, is read as an ad-block list.</summary>
    public const int BlockListMinEntries = 100;

    private const int MaxShown = 120;

    public static BrowserHijackAssessment Evaluate(BrowserHijackSnapshot snapshot, BrowserHijackRuleOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        options ??= BrowserHijackRuleOptions.Default;
        var context = new Context(options.Domains ?? SecurityDomainList.Default, options.OrganizationManaged);

        CheckProxies(snapshot, context);
        CheckWinHttp(snapshot.WinHttp, context);
        CheckHostsFile(snapshot.Hosts, context);
        return new BrowserHijackAssessment(context.Findings, context.Unverified);
    }

    // ---------------------------------------------------------------- proxy / PAC

    private static void CheckProxies(BrowserHijackSnapshot s, Context c)
    {
        if (s.UsersRead != HijackReadState.Available)
        {
            c.Unverified.Add($"The list of user profiles couldn't be read ({s.UsersRead}), so some users' proxy settings weren't checked.");
        }

        if (s.UsersTruncated)
        {
            c.Findings.Add(new BrowserHijackFinding(BrowserHijackRuleIds.ProfilesTruncated, Verdict.Suspicious, BrowserHijackFindingKind.Proxy,
                $"This PC lists more than {BrowserHijackSnapshot.MaxUsers} user accounts, so the rest weren't checked. A padded profile list can hide changed proxy settings. "
                + BrowserHijackFinding.UserDecides, MitreTechniqueIds.AdversaryInTheMiddle));
        }

        bool? machineWide = s.ProxyIsMachineWide;
        string machineNote = machineWide == true ? string.Empty : " (Windows uses it only when Group Policy makes the proxy machine-wide)";
        var machine = new ScopeFlags();
        CheckScope(new Scope(BrowserHijackLocation.MachineSettings, null, "The machine-wide proxy settings" + machineNote), s.MachineSettings, c, machine);
        CheckScope(new Scope(BrowserHijackLocation.MachinePolicy, null, "The machine-wide Group Policy proxy settings"), s.MachinePolicy, c, machine);
        if (machine.LocalProxy && machine.UserFolderPac)
        {
            AddCombo(c, null, "the machine-wide settings");
        }

        int notLoaded = 0;
        foreach (var user in s.Users)
        {
            if (!user.HiveLoaded || (user.Settings.Read == HijackReadState.NotLoaded && user.Policy.Read == HijackReadState.NotLoaded))
            {
                notLoaded++;
                continue;
            }

            string account = AccountLabel(user);
            string userNote = machineWide == true ? " (not in effect while Group Policy sets one machine-wide proxy)" : string.Empty;
            var flags = new ScopeFlags();
            CheckScope(new Scope(BrowserHijackLocation.UserSettings, user.Sid, $"The proxy settings of {account}{userNote}"), user.Settings, c, flags);
            CheckScope(new Scope(BrowserHijackLocation.UserPolicy, user.Sid,
                $"The Group Policy proxy settings of {account} (they lock the setting, so it can't be changed in Windows)"), user.Policy, c, flags);
            if ((flags.LocalProxy || flags.UserFolderPac) && (flags.LocalProxy || machine.LocalProxy) && (flags.UserFolderPac || machine.UserFolderPac))
            {
                AddCombo(c, user.Sid, account);
            }
        }

        if (notLoaded > 0)
        {
            c.Unverified.Add(notLoaded == 1
                ? "1 user profile isn't logged on, so its proxy settings weren't checked."
                : $"{notLoaded} user profiles aren't logged on, so their proxy settings weren't checked.");
        }
    }

    private static void CheckScope(Scope scope, ProxySettings p, Context c, ScopeFlags flags)
    {
        if (p.Read != HijackReadState.Available)
        {
            c.Unverified.Add($"{Lower(scope.Label)} couldn't be read ({p.Read}){DetailSuffix(p.Detail)}.");
            return;
        }

        if (p.UnreadableValues.Count > 0)
        {
            c.Unverified.Add($"{Lower(scope.Label)} have values that couldn't be read: {string.Join(", ", p.UnreadableValues.Take(4).Select(v => Show(v, 40)))}.");
        }

        if (p.DefaultConnection is { Status: not BlobParseStatus.Parsed })
        {
            c.Unverified.Add($"The connection settings blob in {Lower(scope.Label)} didn't fully parse, so part of it wasn't checked.");
        }

        if (p.Truncated)
        {
            c.Findings.Add(new BrowserHijackFinding(BrowserHijackRuleIds.ProxyValueTruncated, Verdict.Suspicious, BrowserHijackFindingKind.Proxy,
                $"{scope.Label} hold a proxy value longer than {ProxySettings.MaxValueLength} characters. Real proxy settings are short. " + BrowserHijackFinding.UserDecides,
                MitreTechniqueIds.AdversaryInTheMiddle, item: scope.Item(null, null)));
        }

        var proxies = new List<(string Value, string Name)>();
        if (p.ProxyEnable is { } enable && enable != 0 && !string.IsNullOrEmpty(p.ProxyServer))
        {
            proxies.Add((p.ProxyServer, "ProxyServer"));
        }

        if (p.DefaultConnection is { ProxyEnabled: true, ProxyServer: { Length: > 0 } blobProxy })
        {
            proxies.Add((blobProxy, "DefaultConnectionSettings"));
        }

        foreach (var (value, name) in proxies.DistinctBy(x => x.Value, StringComparer.OrdinalIgnoreCase))
        {
            JudgeProxy(scope.Label, value, BrowserHijackFindingKind.Proxy, scope.Item(name, value), c, flags);
        }

        var pacs = new List<(string Value, string Name)>();
        if (!string.IsNullOrEmpty(p.AutoConfigUrl))
        {
            pacs.Add((p.AutoConfigUrl, "AutoConfigURL"));
        }

        if (p.DefaultConnection is { AutoConfigEnabled: true, AutoConfigUrl: { Length: > 0 } blobPac })
        {
            pacs.Add((blobPac, "DefaultConnectionSettings"));
        }

        foreach (var (value, name) in pacs.DistinctBy(x => x.Value, StringComparer.OrdinalIgnoreCase))
        {
            JudgePac(scope.Label, value, scope.Item(name, value), c, flags);
        }
    }

    private static void CheckWinHttp(WinHttpProxySettings w, Context c)
    {
        const string Label = "The WinHTTP proxy settings (used by Windows Update, Defender updates and many services)";
        if (w.Read != HijackReadState.Available)
        {
            c.Unverified.Add($"The WinHTTP proxy couldn't be read ({w.Read}){DetailSuffix(w.Detail)}.");
            return;
        }

        if (w.TooLarge)
        {
            c.Findings.Add(new BrowserHijackFinding(BrowserHijackRuleIds.WinHttpValueTooLarge, Verdict.Suspicious, BrowserHijackFindingKind.WinHttpProxy,
                $"The WinHTTP proxy setting is larger than {ProxySettings.MaxStoredBytes / 1024} KB, so it wasn't read. Real settings are a few bytes. "
                + BrowserHijackFinding.UserDecides, MitreTechniqueIds.AdversaryInTheMiddle, item: new BrowserHijackItem(BrowserHijackLocation.WinHttp, ValueName: "WinHttpSettings")));
            return;
        }

        if (w.UnexpectedType)
        {
            c.Unverified.Add("The WinHTTP proxy setting has an unexpected registry type, so it wasn't checked.");
            return;
        }

        if (w.Settings is { Status: not BlobParseStatus.Parsed } && w.ConfiguresProxy is null)
        {
            c.Unverified.Add("The WinHTTP proxy setting didn't parse, so it wasn't checked.");
            return;
        }

        if (w.ConfiguresProxy == true && w.Settings?.ProxyServer is { Length: > 0 } server)
        {
            JudgeProxy(Label, server, BrowserHijackFindingKind.WinHttpProxy,
                new BrowserHijackItem(BrowserHijackLocation.WinHttp, ValueName: "WinHttpSettings", RawValue: server), c, new ScopeFlags());
        }
    }

    private static void JudgeProxy(string label, string value, BrowserHijackFindingKind kind, BrowserHijackItem item, Context c, ScopeFlags flags)
    {
        var host = ProxyHosts(value).Select(h => (Host: h, Class: ClassifyHost(h))).OrderByDescending(h => h.Class).FirstOrDefault();
        string shown = Show(value);
        switch (host.Class)
        {
            case HostClass.Loopback:
                flags.LocalProxy = true;
                c.Findings.Add(Proxy(BrowserHijackRuleIds.ProxyLocal, kind, item,
                    $"{label} send web traffic through a proxy on this PC ({shown}). Hijackers and adware use a local proxy to read and change the pages you "
                    + "visit; debugging tools (Fiddler, Charles) and some privacy or VPN apps do this too."));
                break;
            case HostClass.PublicAddress:
                c.Findings.Add(Proxy(BrowserHijackRuleIds.ProxyPublicAddress, kind, item,
                    $"{label} send web traffic through a proxy at a public internet address ({shown}), which can see and change what you browse."));
                break;
            case HostClass.PrivateAddress or HostClass.Name:
                JudgeManaged(BrowserHijackRuleIds.ProxyUnmanaged, kind, item, c,
                    $"{label} send web traffic through the proxy {shown}");
                break;
            default:
                c.Unverified.Add($"{label} name a proxy ({shown}) that couldn't be understood, so it wasn't judged.");
                break;
        }
    }

    private static void JudgePac(string label, string value, BrowserHijackItem item, Context c, ScopeFlags flags)
    {
        string shown = Show(value);
        string lead = $"{label} load a proxy script (PAC) from {shown}, which decides where your web traffic goes";
        string? localPath = null;
        if (Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri))
        {
            if (uri.IsFile)
            {
                if (uri.IsUnc)
                {
                    c.Findings.Add(Proxy(BrowserHijackRuleIds.PacUnusualUrl, BrowserHijackFindingKind.Proxy, item, $"{lead}. A PAC script on a network share is unusual."));
                    return;
                }

                localPath = uri.LocalPath;
            }
            else if (uri.Scheme is "http" or "https")
            {
                switch (ClassifyHost(uri.Host))
                {
                    case HostClass.Loopback:
                        c.Findings.Add(Proxy(BrowserHijackRuleIds.PacLocal, BrowserHijackFindingKind.Proxy, item,
                            $"{lead}. The script is served by a program on this PC, which can route chosen sites through itself; some VPN and security apps do this too."));
                        return;
                    case HostClass.PublicAddress:
                        c.Findings.Add(Proxy(BrowserHijackRuleIds.PacPublicAddress, BrowserHijackFindingKind.Proxy, item,
                            $"{lead}. It comes from a bare public IP address rather than an organization's server."));
                        return;
                    case HostClass.PrivateAddress or HostClass.Name:
                        JudgeManaged(BrowserHijackRuleIds.PacUnmanaged, BrowserHijackFindingKind.Proxy, item, c, lead);
                        return;
                }
            }
        }
        else if (value.Length > 2 && char.IsAsciiLetter(value[0]) && value[1] == ':')
        {
            localPath = value; // a bare Windows path
        }

        if (localPath is null)
        {
            c.Findings.Add(Proxy(BrowserHijackRuleIds.PacUnusualUrl, BrowserHijackFindingKind.Proxy, item, $"{lead}. This kind of address is unusual for a PAC script."));
            return;
        }

        if (IsUserWritablePath(localPath))
        {
            flags.UserFolderPac = true;
            c.Findings.Add(Proxy(BrowserHijackRuleIds.PacUserFolderFile, BrowserHijackFindingKind.Proxy, item,
                $"{lead}. The script is a file in a folder that programs without admin rights can change, a common hijacker setup."));
        }
        else
        {
            c.Findings.Add(Proxy(BrowserHijackRuleIds.PacLocalFile, BrowserHijackFindingKind.Proxy, item,
                $"{lead}. PAC scripts are normally served by an organization's web server; a local file is unusual."));
        }
    }

    private static void JudgeManaged(string ruleId, BrowserHijackFindingKind kind, BrowserHijackItem item, Context c, string lead)
    {
        switch (c.OrganizationManaged)
        {
            case true:
                return; // an organization's proxy on a managed PC is normal
            case false:
                c.Findings.Add(Proxy(ruleId, kind, item, $"{lead}, but this PC isn't managed by an organization, where such settings normally come from."));
                return;
            default:
                c.Unverified.Add($"{lead}. That is normal on a PC managed by an organization, but whether this PC is managed isn't known, so it wasn't judged.");
                return;
        }
    }

    private static void AddCombo(Context c, string? sid, string where) =>
        c.Findings.Add(new BrowserHijackFinding(BrowserHijackRuleIds.LocalProxyWithUserPac, Verdict.Malicious, BrowserHijackFindingKind.Proxy,
            $"For {where}, web traffic goes through a proxy on this PC and a proxy script (PAC) stored in a user-writable folder. Together these are a "
            + "classic local interception setup that can read and change your browsing. " + BrowserHijackFinding.UserDecides,
            MitreTechniqueIds.AdversaryInTheMiddle,
            item: new BrowserHijackItem(sid is null ? BrowserHijackLocation.MachineSettings : BrowserHijackLocation.UserSettings, sid)));

    private static BrowserHijackFinding Proxy(string ruleId, BrowserHijackFindingKind kind, BrowserHijackItem item, string text) =>
        new(ruleId, Verdict.Suspicious, kind, text + " " + BrowserHijackFinding.UserDecides, MitreTechniqueIds.AdversaryInTheMiddle, item: item);

    private static string AccountLabel(UserProxySettings user) => user.Sid switch
    {
        "S-1-5-18" => "the SYSTEM account (used by services)",
        "S-1-5-19" => "the LocalService account (used by services)",
        "S-1-5-20" => "the NetworkService account (used by services)",
        _ => $"the user {Show(user.Sid, 80)}",
    };

    /// <summary>The host of every endpoint in a proxy value (<c>host:port</c>, <c>http=host:port;https=...</c>, <c>scheme://user@host:port</c>, <c>[v6]:port</c>).</summary>
    internal static IEnumerable<string> ProxyHosts(string value)
    {
        foreach (var part in value.Split([';', ' ', '\t', ','], StringSplitOptions.RemoveEmptyEntries))
        {
            var s = part;
            int eq = s.IndexOf('=');
            if (eq >= 0)
            {
                s = s[(eq + 1)..];
            }

            int scheme = s.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0)
            {
                s = s[(scheme + 3)..];
            }

            int slash = s.IndexOf('/');
            if (slash >= 0)
            {
                s = s[..slash];
            }

            int at = s.LastIndexOf('@');
            if (at >= 0)
            {
                s = s[(at + 1)..];
            }

            if (s.StartsWith('['))
            {
                int close = s.IndexOf(']');
                yield return close > 0 ? s[1..close] : s[1..];
            }
            else if (s.Count(ch => ch == ':') == 1)
            {
                yield return s[..s.IndexOf(':')];
            }
            else
            {
                yield return s;
            }
        }
    }

    internal enum HostClass
    {
        Unparsed,
        Name,
        PrivateAddress,
        PublicAddress,
        Loopback,
    }

    internal static HostClass ClassifyHost(string host)
    {
        host = host.Trim().TrimEnd('.');
        if (host.StartsWith('[') && host.EndsWith(']'))
        {
            host = host[1..^1];
        }

        if (host.Length == 0)
        {
            return HostClass.Unparsed;
        }

        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return HostClass.Loopback;
        }

        if (host.Contains(':'))
        {
            return host.IndexOf('%') < 0 && IPAddress.TryParse(host, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6
                ? ClassifyAddress(v6)
                : HostClass.Unparsed;
        }

        // inet_aton rules: 127.1, 0x7f.0.0.1 and 2130706433 are all 127.0.0.1 to the networking stack.
        return HostsFileParser.TryParseLooseIPv4(host, out var v4) ? ClassifyAddress(v4!) : HostClass.Name;
    }

    private static HostClass ClassifyAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] is 127 or 0 ? HostClass.Loopback
                : b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254)
                    || (b[0] == 100 && b[1] is >= 64 and <= 127) ? HostClass.PrivateAddress
                : HostClass.PublicAddress;
        }

        return address.Equals(IPAddress.IPv6Loopback) || address.Equals(IPAddress.IPv6Any) ? HostClass.Loopback
            : address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal ? HostClass.PrivateAddress
            : HostClass.PublicAddress;
    }

    // ---------------------------------------------------------------- hosts

    private static void CheckHostsFile(HostsFileSnapshot h, Context c)
    {
        var file = new BrowserHijackItem(BrowserHijackLocation.HostsFile, RawValue: h.Path);
        switch (h.Read)
        {
            case HijackReadState.Available when h.Content is not null:
                CheckHostsContent(h, h.Content, c);
                break;
            case HijackReadState.Available:
                c.Unverified.Add("The hosts file was read, but its entries are missing, so they weren't checked.");
                break;
            case HijackReadState.NotFound:
                break; // no hosts file: Windows has no hosts entries
            case HijackReadState.Locked:
                // E7 tracks a hosts file that stays Locked across snapshots (any user can hold an oplock); one snapshot can't tell.
                c.Unverified.Add("The hosts file is locked by another program, so it couldn't be checked.");
                break;
            case HijackReadState.Redirected:
                c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsPathRedirected, Verdict.Suspicious, file,
                    "The folder that holds the hosts file (drivers\\etc) is redirected through a link, so Windows may read a hosts file from somewhere else."));
                c.Unverified.Add("The hosts file's entries weren't read, because a link on the way wasn't followed.");
                break;
            default:
                c.Unverified.Add($"The hosts file couldn't be checked ({h.Read}){DetailSuffix(h.Detail)}.");
                break;
        }

        if (h.WritableByNonAdmins == true || h.OwnerIsTrusted == false)
        {
            c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsWritableByUsers, Verdict.Suspicious, file, h.WritableByNonAdmins == true
                ? "The hosts file can be changed by programs without admin rights, so any program can redirect or block websites."
                : "The hosts file is owned by an account that isn't an administrator, which can give itself the right to change it."));
        }
        else if (h.Read == HijackReadState.Available && h.WritableByNonAdmins is null)
        {
            c.Unverified.Add("The hosts file's permissions couldn't be read.");
        }

        if (h.NumberOfLinks > 1)
        {
            c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsHardLinks, Verdict.Suspicious, file,
                $"The hosts file has {h.NumberOfLinks} names (hard links), so it can be changed through another name somewhere else."));
        }

        CheckDataBasePath(h, c);
    }

    private static void CheckDataBasePath(HostsFileSnapshot h, Context c)
    {
        if (h.DataBasePathRead != HijackReadState.Available)
        {
            c.Unverified.Add($"Where Windows looks for the hosts file (DataBasePath) couldn't be read ({h.DataBasePathRead}).");
            return;
        }

        switch (h.DataBasePathRedirected)
        {
            case null:
                c.Unverified.Add("It couldn't be confirmed that Windows reads the standard hosts file (DataBasePath).");
                return;
            case false:
                return;
        }

        string path = h.DataBasePathExpanded ?? h.DataBasePath ?? string.Empty;
        bool userWritable = path.Length > 0 && IsUserWritablePath(path);
        var item = new BrowserHijackItem(BrowserHijackLocation.DataBasePath, ValueName: "DataBasePath", RawValue: h.DataBasePath);
        c.Findings.Add(HostsFile(userWritable ? BrowserHijackRuleIds.HostsDataBasePathUserFolder : BrowserHijackRuleIds.HostsDataBasePathRedirected,
            userWritable ? Verdict.Malicious : Verdict.Suspicious, item,
            $"Windows is set to read its hosts file from {Show(path)} instead of drivers\\etc"
            + (userWritable ? ", a folder programs without admin rights can change, so any program can redirect websites." : ".")
            + " sap-AV checked the standard hosts file; the one Windows actually uses there wasn't read."));
    }

    private static void CheckHostsContent(HostsFileSnapshot h, HostsParseResult content, Context c)
    {
        var file = new BrowserHijackItem(BrowserHijackLocation.HostsFile, RawValue: h.Path);
        if (content.EncodingMismatch)
        {
            c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsEncodingMismatch, Verdict.Suspicious, file,
                "The hosts file is saved as UTF-16, so Notepad shows different entries from the ones Windows reads. This can hide entries from anyone who opens it."));
        }
        else if (content.Utf16Bom)
        {
            c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsEncodingMismatch, Verdict.Suspicious, file,
                "The hosts file is saved as UTF-16, which Windows doesn't read the way editors show it. Hosts files are normally plain text."));
        }

        bool blockList = LooksLikeBlockList(content);
        if (h.ContentTruncated || content.InputTruncated)
        {
            if (blockList)
            {
                c.Unverified.Add($"The hosts file is larger than {HostsFileSnapshot.MaxBytes / (1024 * 1024)} MB (it looks like an ad-block list), so the rest of it wasn't checked.");
            }
            else
            {
                c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsTruncated, Verdict.Suspicious, file,
                    $"The hosts file is larger than {HostsFileSnapshot.MaxBytes / (1024 * 1024)} MB and isn't an ad-block list, so the rest of it wasn't checked. A padded hosts file can hide a harmful entry."));
            }
        }
        else if (content.EntriesTruncated && !blockList)
        {
            c.Findings.Add(HostsFile(BrowserHijackRuleIds.HostsTruncated, Verdict.Suspicious, file,
                $"The hosts file has {content.TotalEntries} entries and isn't an ad-block list. A padded hosts file can hide a harmful entry."));
        }

        var flagged = new Dictionary<string, List<BrowserHijackFinding>>(StringComparer.Ordinal);
        var seen = new HashSet<(string, string)>();
        JudgeEntries(content.Entries, false, c, flagged, seen);
        if (content.Utf16Decoding is { } other)
        {
            JudgeEntries(other.Entries, true, c, flagged, seen);
        }

        foreach (var (rule, list) in flagged)
        {
            c.Findings.AddRange(list.Take(MaxHostsFindingsPerRule));
            if (list.Count > MaxHostsFindingsPerRule)
            {
                var first = list[0];
                c.Findings.Add(new BrowserHijackFinding(BrowserHijackRuleIds.HostsMoreFlagged, list.Max(f => f.Verdict), BrowserHijackFindingKind.HostsEntry,
                    $"{list.Count - MaxHostsFindingsPerRule} more hosts entries like these ({rule}) aren't listed one by one. " + BrowserHijackFinding.UserDecides,
                    first.TechniqueId, first.Category, file, first.SecondaryTechniqueIds));
            }
        }
    }

    private static void JudgeEntries(IReadOnlyList<HostsEntry> entries, bool utf16, Context c, Dictionary<string, List<BrowserHijackFinding>> flagged,
        HashSet<(string, string)> seen)
    {
        string where = utf16 ? " (as an editor shows it)" : string.Empty;
        foreach (var entry in entries)
        {
            bool blocking = IsBlockingAddress(entry.Address);
            bool anyNew = false;
            foreach (var name in entry.Names)
            {
                if (!seen.Add((entry.Address, SecurityDomainList.Normalize(name) ?? name)))
                {
                    continue;
                }

                anyNew = true;
                if (c.Domains.Classify(name, out _) is not { } group)
                {
                    continue;
                }

                var item = new BrowserHijackItem(BrowserHijackLocation.HostsFile, RawValue: entry.RawAddress ?? entry.Address, HostsLine: entry.Line, HostsName: name);
                string lead = $"The hosts file (line {entry.Line}{where})";
                if (!blocking)
                {
                    Add(flagged, new BrowserHijackFinding(BrowserHijackRuleIds.HostsRedirectsListedDomain, Verdict.Malicious, BrowserHijackFindingKind.HostsEntry,
                        $"{lead} sends {ShowHost(name)} to {Show(entry.Address, 64)} instead of the real site. " + group switch
                        {
                            SecurityDomainGroup.Defender => "Windows Update or Microsoft Defender could get fake updates or none at all. ",
                            SecurityDomainGroup.Security => "Your antivirus or an online scanner could be faked or cut off. ",
                            _ => "A fake copy of the site could collect your password or payment details. ",
                        } + BrowserHijackFinding.UserDecides,
                        MitreTechniqueIds.StoredDataManipulation, item: item, secondaryTechniqueIds: [MitreTechniqueIds.AdversaryInTheMiddle]));
                }
                else if (group == SecurityDomainGroup.Defender)
                {
                    Add(flagged, new BrowserHijackFinding(BrowserHijackRuleIds.HostsBlocksDefenderDomain, Verdict.Malicious, BrowserHijackFindingKind.HostsEntry,
                        $"{lead} blocks {ShowHost(name)}, which Windows Update or Microsoft Defender needs, so security updates or cloud protection can stop working. "
                        + BrowserHijackFinding.UserDecides,
                        MitreTechniqueIds.DisableOrModifyTools, ThreatCategory.DefenderTampering, item, [MitreTechniqueIds.StoredDataManipulation]));
                }
                else if (group == SecurityDomainGroup.Security)
                {
                    Add(flagged, new BrowserHijackFinding(BrowserHijackRuleIds.HostsBlocksSecurityDomain, Verdict.Malicious, BrowserHijackFindingKind.HostsEntry,
                        $"{lead} blocks {ShowHost(name)}, an antivirus or security site, so security software can't update and you can't reach it for help. "
                        + BrowserHijackFinding.UserDecides,
                        MitreTechniqueIds.DisableOrModifyTools, ThreatCategory.BrowserHijack, item, [MitreTechniqueIds.StoredDataManipulation]));
                }

                // Blocking a sign-in or banking site: privacy and social block lists do it on purpose; no finding.
            }

            if (entry.NonCanonicalAddress && anyNew)
            {
                Add(flagged, new BrowserHijackFinding(BrowserHijackRuleIds.HostsNonCanonicalAddress, Verdict.Suspicious, BrowserHijackFindingKind.HostsEntry,
                    $"The hosts file (line {entry.Line}{where}) writes the address as {Show(entry.RawAddress!, 64)} (read as {entry.Address}) for "
                    + $"{string.Join(", ", entry.Names.Take(3).Select(n => ShowHost(n)))}{(entry.Names.Count > 3 ? ", ..." : string.Empty)}. "
                    + "This unusual form is used to slip entries past tools that look for plain addresses. " + BrowserHijackFinding.UserDecides,
                    MitreTechniqueIds.StoredDataManipulation,
                    item: new BrowserHijackItem(BrowserHijackLocation.HostsFile, RawValue: entry.RawAddress, HostsLine: entry.Line, HostsName: entry.Names.FirstOrDefault())));
            }
        }
    }

    private static void Add(Dictionary<string, List<BrowserHijackFinding>> flagged, BrowserHijackFinding finding)
    {
        if (!flagged.TryGetValue(finding.RuleId, out var list))
        {
            flagged[finding.RuleId] = list = [];
        }

        list.Add(finding);
    }

    /// <summary>0.0.0.0/8, 127.0.0.0/8, ::, ::1 and their IPv4-mapped forms: the name is blocked, not redirected.</summary>
    internal static bool IsBlockingAddress(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        return ip.AddressFamily == AddressFamily.InterNetwork
            ? ip.GetAddressBytes()[0] is 0 or 127
            : ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6Loopback);
    }

    private static bool LooksLikeBlockList(HostsParseResult content)
    {
        int total = content.Entries.Count;
        if (total < BlockListMinEntries)
        {
            return false;
        }

        int blocking = content.Entries.Count(e => IsBlockingAddress(e.Address));
        return blocking * 100L >= total * 95L;
    }

    private static BrowserHijackFinding HostsFile(string ruleId, Verdict verdict, BrowserHijackItem item, string text) =>
        new(ruleId, verdict, BrowserHijackFindingKind.HostsFile, text + " " + BrowserHijackFinding.UserDecides, MitreTechniqueIds.StoredDataManipulation, item: item);

    // ---------------------------------------------------------------- helpers

    /// <summary>A path standard users can change by its location: inside a profile, Temp, the Recycle Bin, or ProgramData.</summary>
    internal static bool IsUserWritablePath(string path)
    {
        var breadth = DefenderExclusionPatterns.ClassifyPath(path).Breadth;
        if (breadth is ExclusionBreadth.UserFolder or ExclusionBreadth.Broad)
        {
            return true;
        }

        var normalized = path.Replace('/', '\\');
        return normalized.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%ProgramData%\", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%Temp%", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%Tmp%", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%AppData%", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%LocalAppData%", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%UserProfile%", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(@"%Public%", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>An untrusted value for display: quoted, one line, invisible and bidi characters replaced, capped.</summary>
    private static string Show(string raw, int max = MaxShown) => "\"" + SafeText.Display(raw, max) + "\"";

    /// <summary>A host name for display; a non-ASCII name also shows its ASCII (punycode) form, so a homograph can't pass as the real name.</summary>
    private static string ShowHost(string name)
    {
        string shown = Show(name, 100);
        return System.Text.Ascii.IsValid(name) || SecurityDomainList.Normalize(name) is not { } ascii ? shown : $"{shown} ({Show(ascii, 100)})";
    }

    private static string DetailSuffix(string? detail) => string.IsNullOrWhiteSpace(detail) ? string.Empty : ": " + SafeText.Display(detail, 160);

    private static string Lower(string label) => label.Length > 0 && char.IsUpper(label[0]) ? char.ToLowerInvariant(label[0]) + label[1..] : label;

    private sealed record Scope(BrowserHijackLocation Location, string? Sid, string Label)
    {
        public BrowserHijackItem Item(string? valueName, string? rawValue) => new(Location, Sid, valueName, rawValue);
    }

    private sealed class ScopeFlags
    {
        public bool LocalProxy { get; set; }

        public bool UserFolderPac { get; set; }
    }

    private sealed class Context(SecurityDomainList domains, bool? organizationManaged)
    {
        public SecurityDomainList Domains { get; } = domains;

        public bool? OrganizationManaged { get; } = organizationManaged;

        public List<BrowserHijackFinding> Findings { get; } = [];

        public List<string> Unverified { get; } = [];
    }
}
