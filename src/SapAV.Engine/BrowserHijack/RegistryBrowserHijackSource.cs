using SapAV.Core.BrowserHijack;
using SapAV.Core.Persistence;
using SapAV.Core.Text;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.BrowserHijack;

/// <summary>
/// The engine's <see cref="IBrowserHijackSource"/> (ROADMAP E6): per-account WinINet proxy / PAC settings for every profile
/// (ProfileList + loaded hives, the same enumeration as the persistence collectors) and the loaded service-account hives, the
/// machine-wide and Group Policy Internet Settings, the WinHTTP proxy blob, and the hosts file.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read-only:</b> registry keys are opened through <see cref="IRegistryView"/> (KEY_READ) and the hosts file through the
/// hardened open with read access; nothing is written, and unloaded hives are never loaded (they are reported NotLoaded).
/// </para>
/// <para>
/// The hosts file is always <c>&lt;system directory&gt;\drivers\etc\hosts</c> (GetSystemDirectory, not the registry): a
/// changed <c>Tcpip\Parameters\DataBasePath</c> is reported as a redirect instead of being followed.
/// </para>
/// <para>
/// B5 note: the hosts text is parsed in the engine by <see cref="HostsFileParser"/> (a pure, bounded, managed function over at
/// most 1 MB of a file only administrators can write by default). It has no I/O, so it can move into the sandboxed worker unchanged.
/// </para>
/// </remarks>
public sealed class RegistryBrowserHijackSource : IBrowserHijackSource
{
    internal const string InternetSettingsPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
    internal const string PolicyInternetSettingsPath = @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    internal const string ConnectionsSubKey = "Connections";
    internal const string WinHttpValue = "WinHttpSettings";
    internal const string DefaultConnectionValue = "DefaultConnectionSettings";
    internal const string TcpipParametersPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    internal const string DefaultDataBasePath = @"%SystemRoot%\System32\drivers\etc";

    /// <summary>Accounts whose hives are always loaded and whose proxy services use; not in the user enumeration.</summary>
    internal static readonly string[] ServiceAccounts = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];

    private const int MaxUnreadableNames = 16;

    private static readonly HashSet<string> TrustedOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18", // SYSTEM
        "S-1-5-32-544", // Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
    };

    private readonly IRegistryView _registry;
    private readonly IHostsFileReader _hostsReader;
    private readonly string _systemDirectory;
    private readonly Func<bool> _isSystem;
    private readonly Func<string, bool>? _keepHostsName;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public RegistryBrowserHijackSource(TimeProvider time, ILogger<RegistryBrowserHijackSource> logger)
        : this(new WindowsRegistryView(), new SafeHostsFileReader(), Environment.SystemDirectory, Sandbox.AppContainerName.IsLocalSystem,
            null, time, logger)
    {
    }

    /// <param name="keepHostsName">Hosts entries with a name this accepts are kept beyond the entry cap (E6 rules: the security-domain list).</param>
    internal RegistryBrowserHijackSource(IRegistryView registry, IHostsFileReader hostsReader, string systemDirectory, Func<bool> isSystem,
        Func<string, bool>? keepHostsName, TimeProvider time, ILogger logger)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _hostsReader = hostsReader ?? throw new ArgumentNullException(nameof(hostsReader));
        _systemDirectory = string.IsNullOrWhiteSpace(systemDirectory) ? throw new ArgumentException("A system directory is needed.", nameof(systemDirectory)) : systemDirectory;
        _isSystem = isSystem ?? throw new ArgumentNullException(nameof(isSystem));
        _keepHostsName = keepHostsName;
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>The hosts file read: <c>&lt;system directory&gt;\drivers\etc\hosts</c>.</summary>
    internal string HostsPath => Path.Join(_systemDirectory, @"drivers\etc\hosts");

    public async Task<BrowserHijackSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return await Task.Run(() => Collect(cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            // Never an exception for callers (the contract): an unexpected bug makes every part unknown.
            _logger.LogError(ex, "Browser-hijack settings collection failed unexpectedly");
            string detail = ex.GetType().Name;
            return new BrowserHijackSnapshot
            {
                CollectedAt = _time.GetUtcNow(),
                UsersRead = HijackReadState.Failed,
                MachineSettings = ProxySettings.Unknown(HijackReadState.Failed, detail),
                MachinePolicy = ProxySettings.Unknown(HijackReadState.Failed, detail),
                WinHttp = WinHttpProxySettings.Unknown(HijackReadState.Failed, detail),
                Hosts = new HostsFileSnapshot { Read = HijackReadState.Failed, Detail = detail, Path = HostsPath, DataBasePathRead = HijackReadState.Failed },
            };
        }
    }

    internal BrowserHijackSnapshot Collect(CancellationToken cancellationToken)
    {
        var collectedAt = _time.GetUtcNow();
        var machine = ReadSettings(RegistryRoot.LocalMachine, InternetSettingsPath);
        var policy = ReadSettings(RegistryRoot.LocalMachine, PolicyInternetSettingsPath);
        var winHttp = ReadWinHttp();
        cancellationToken.ThrowIfCancellationRequested();

        var users = ReadUsers(out var usersRead, out bool usersTruncated, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        var hosts = ReadHosts();
        var snapshot = new BrowserHijackSnapshot
        {
            CollectedAt = collectedAt,
            CollectedAsSystem = IsSystem(),
            UsersRead = usersRead,
            Users = users,
            UsersTruncated = usersTruncated,
            MachineSettings = machine,
            MachinePolicy = policy,
            WinHttp = winHttp,
            Hosts = hosts,
        };

        _logger.LogDebug("Browser-hijack snapshot: {Users} accounts ({UsersRead}), WinHTTP {WinHttp}, hosts {Hosts} ({Entries} entries)",
            users.Count, usersRead, winHttp.Read, hosts.Read, hosts.Content?.TotalEntries);
        return snapshot;
    }

    private List<UserProxySettings> ReadUsers(out HijackReadState state, out bool truncated, CancellationToken cancellationToken)
    {
        var listState = HijackReadState.Available;
        PersistenceContextIssues issues = (_, _, location, reason, _) =>
        {
            // Only a failed listing of HKU or ProfileList makes the account list incomplete.
            if (listState == HijackReadState.Available)
            {
                listState = reason == PersistenceIssueReason.AccessDenied ? HijackReadState.AccessDenied : HijackReadState.Failed;
            }
        };

        var profiles = RegistryEnvironment.Profiles(_registry, RegistryEnvironment.Machine(_registry), issues, BrowserHijackSnapshot.MaxUsers + 1);
        truncated = profiles.Count > BrowserHijackSnapshot.MaxUsers;
        var result = new List<UserProxySettings>();
        foreach (var profile in profiles.Take(BrowserHijackSnapshot.MaxUsers))
        {
            cancellationToken.ThrowIfCancellationRequested();
            result.Add(profile.HiveLoaded
                ? ReadAccount(profile.Sid, isServiceAccount: false)
                : NotLoaded(profile.Sid, isServiceAccount: false));
        }

        foreach (var sid in ServiceAccounts)
        {
            result.Add(ReadServiceAccount(sid));
        }

        state = listState;
        result.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Sid, b.Sid));
        return result;
    }

    private UserProxySettings ReadServiceAccount(string sid)
    {
        try
        {
            using var hive = _registry.Open(RegistryRoot.Users, sid);
            return hive is null ? NotLoaded(sid, isServiceAccount: true) : ReadAccount(sid, isServiceAccount: true);
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            var unknown = ProxySettings.Unknown(StateOf(ex), "The hive can't be opened.");
            return new UserProxySettings(sid, HiveLoaded: true, IsServiceAccount: true, unknown, unknown);
        }
    }

    private UserProxySettings ReadAccount(string sid, bool isServiceAccount) =>
        new(sid, HiveLoaded: true, isServiceAccount,
            ReadSettings(RegistryRoot.Users, sid + @"\" + InternetSettingsPath),
            ReadSettings(RegistryRoot.Users, sid + @"\" + PolicyInternetSettingsPath));

    private static UserProxySettings NotLoaded(string sid, bool isServiceAccount)
    {
        var unknown = ProxySettings.Unknown(HijackReadState.NotLoaded, "The user's registry hive isn't loaded (not logged on).");
        return new UserProxySettings(sid, HiveLoaded: false, isServiceAccount, unknown, unknown);
    }

    /// <summary>One Internet Settings key and its <c>Connections\DefaultConnectionSettings</c> blob.</summary>
    internal ProxySettings ReadSettings(RegistryRoot root, string path)
    {
        try
        {
            using var key = _registry.Open(root, path);
            if (key is null)
            {
                return ProxySettings.Missing;
            }

            var unreadable = new List<string>();
            bool cut = false;
            var settings = new ProxySettings
            {
                Read = HijackReadState.Available,
                KeyExists = true,
                ProxyEnable = Number(key, "ProxyEnable", unreadable),
                ProxyServer = Text(key, "ProxyServer", unreadable, ref cut),
                ProxyOverride = Text(key, "ProxyOverride", unreadable, ref cut),
                AutoConfigUrl = Text(key, "AutoConfigURL", unreadable, ref cut),
                ProxySettingsPerUser = Number(key, "ProxySettingsPerUser", unreadable),
            };

            ConnectionSettingsBlob? blob = null;
            using (var connections = key.OpenSubKey(ConnectionsSubKey))
            {
                if (connections?.Value(DefaultConnectionValue) is { } data)
                {
                    if (data.AsBinary() is { } bytes)
                    {
                        blob = ConnectionSettingsBlob.ParseWinInet(bytes);
                    }
                    else
                    {
                        unreadable.Add(ConnectionsSubKey + @"\" + DefaultConnectionValue);
                    }
                }
            }

            return settings with
            {
                DefaultConnection = blob,
                UnreadableValues = unreadable.Take(MaxUnreadableNames).ToArray(),
                Truncated = cut || (blob?.StringsTruncated ?? false),
            };
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            return ProxySettings.Unknown(StateOf(ex), $"The key can't be read ({ex.GetType().Name}).");
        }
    }

    internal WinHttpProxySettings ReadWinHttp()
    {
        try
        {
            using var connections = _registry.Open(RegistryRoot.LocalMachine, InternetSettingsPath + @"\" + ConnectionsSubKey);
            if (connections?.Value(WinHttpValue) is not { } data)
            {
                return new WinHttpProxySettings { Read = HijackReadState.Available };
            }

            return data.AsBinary() is { } bytes
                ? new WinHttpProxySettings { Read = HijackReadState.Available, Settings = ConnectionSettingsBlob.ParseWinHttp(bytes) }
                : new WinHttpProxySettings { Read = HijackReadState.Available, UnexpectedType = true };
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            return WinHttpProxySettings.Unknown(StateOf(ex), $"The WinHTTP settings can't be read ({ex.GetType().Name}).");
        }
    }

    internal HostsFileSnapshot ReadHosts()
    {
        var path = HostsPath;
        var (dbState, dbRaw, dbExpanded, dbRedirected) = ReadDataBasePath();
        HostsFileRead read;
        try
        {
            read = _hostsReader.Read(path, HostsFileSnapshot.MaxBytes);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            read = HostsFileRead.Failed(HijackReadState.Failed, ex.GetType().Name);
        }

        return new HostsFileSnapshot
        {
            Read = read.State,
            Detail = read.Detail is null ? null : SafeText.SingleLine(read.Detail, 256),
            Path = path,
            Length = read.Length,
            LastWriteTime = read.LastWriteTime,
            OwnerSid = read.OwnerSid,
            OwnerIsTrusted = read.OwnerSid is null ? null : TrustedOwners.Contains(read.OwnerSid),
            ContentTruncated = read.State == HijackReadState.Available && read.Truncated,
            Content = read.State == HijackReadState.Available ? HostsFileParser.Parse(read.Content, read.Truncated, _keepHostsName) : null,
            DataBasePathRead = dbState,
            DataBasePath = dbRaw,
            DataBasePathExpanded = dbExpanded,
            DataBasePathRedirected = dbRedirected,
        };
    }

    /// <summary>
    /// <c>Tcpip\Parameters\DataBasePath</c>: the folder the resolver takes the hosts file from. Redirected unless it is the stored
    /// default, or expands (machine environment from the registry) to <c>&lt;system directory&gt;\drivers\etc</c>.
    /// </summary>
    private (HijackReadState State, string? Raw, string? Expanded, bool? Redirected) ReadDataBasePath()
    {
        try
        {
            using var key = _registry.Open(RegistryRoot.LocalMachine, TcpipParametersPath);
            var data = key?.Value("DataBasePath");
            if (data is null)
            {
                return (HijackReadState.Available, null, null, false);
            }

            if (data.Value.AsString() is not { } raw || data.Value.Data is string[])
            {
                // Not a string: Windows won't use it as the default either; what the resolver does with it is unknown.
                return (HijackReadState.Available, null, null, null);
            }

            bool tooLong = raw.Length > ProxySettings.MaxValueLength;
            var stored = SafeText.Identifier(tooLong ? raw[..ProxySettings.MaxValueLength] : raw);
            var expanded = tooLong ? null : RegistryEnvironment.Machine(_registry).Expand(raw, out bool unknown) is { } e && !unknown ? e : null;
            bool isDefault = Same(raw, DefaultDataBasePath) || (expanded is not null && Same(expanded, Path.Join(_systemDirectory, @"drivers\etc")));
            return (HijackReadState.Available, stored, expanded is null ? null : SafeText.Identifier(expanded), !isDefault);
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            return (StateOf(ex), null, null, null);
        }
    }

    private static bool Same(string a, string b) =>
        string.Equals(a.Trim().TrimEnd('\\'), b.Trim().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    private static long? Number(IRegistryKeyReader key, string name, List<string> unreadable)
    {
        if (key.Value(name) is not { } data)
        {
            return null;
        }

        if (data.AsNumber() is { } number)
        {
            return number;
        }

        unreadable.Add(name);
        return null;
    }

    private static string? Text(IRegistryKeyReader key, string name, List<string> unreadable, ref bool cut)
    {
        if (key.Value(name) is not { } data)
        {
            return null;
        }

        if (data.Data is not string value)
        {
            unreadable.Add(name);
            return null;
        }

        if (value.Length > ProxySettings.MaxValueLength)
        {
            cut = true;
            int length = char.IsHighSurrogate(value[ProxySettings.MaxValueLength - 1]) ? ProxySettings.MaxValueLength - 1 : ProxySettings.MaxValueLength;
            value = value[..length];
        }

        return SafeText.Identifier(value);
    }

    private bool? IsSystem()
    {
        try
        {
            return _isSystem();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    private static bool IsReadFailure(Exception ex) => ex is UnauthorizedAccessException or System.Security.SecurityException or IOException;

    private static HijackReadState StateOf(Exception ex) =>
        ex is UnauthorizedAccessException or System.Security.SecurityException ? HijackReadState.AccessDenied : HijackReadState.Failed;
}
