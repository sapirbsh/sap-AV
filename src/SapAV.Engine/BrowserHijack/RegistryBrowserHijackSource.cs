using SapAV.Core.BrowserHijack;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning.Isolation;
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
/// B5 rule: the engine never parses the hosts file. It opens it with the hardened open, reads only metadata from the handle
/// (owner, last-write time, size), and brokers the read-only handle to the sandboxed scan worker
/// (<see cref="IPersistenceFileParser"/>, kind <see cref="WorkerParseKind.HostsFile"/>), whose answer is validated as untrusted
/// input (<see cref="WireHostsCodec.FromWire"/>). Without a worker, the hosts content is <see cref="HijackReadState.ParserUnavailable"/>.
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
    private readonly IHostsFileOpener _hostsOpener;
    private readonly IPersistenceFileParser _parser;
    private readonly string _systemDirectory;
    private readonly Func<bool> _isSystem;
    private readonly IReadOnlyList<string> _keepHostsNames;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    /// <param name="parser">The sandboxed broker; null (no sandbox) leaves the hosts content <see cref="HijackReadState.ParserUnavailable"/>.</param>
    internal RegistryBrowserHijackSource(IPersistenceFileParser? parser, TimeProvider time, ILogger<RegistryBrowserHijackSource> logger)
        : this(new WindowsRegistryView(), new SafeHostsFileOpener(), parser ?? UnavailablePersistenceParser.NoSandbox, Environment.SystemDirectory,
            Sandbox.AppContainerName.IsLocalSystem, null, time, logger)
    {
    }

    /// <param name="keepHostsNames">
    /// Domain suffixes whose hosts entries are kept past the entry cap (<see cref="HostsNameFilter"/>); null =
    /// <see cref="HostsNameFilter.DefaultSecurityDomains"/>. The E6 rules (detection-dev) pass the list from <c>data/</c> here.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="keepHostsNames"/> is outside the filter's caps.</exception>
    internal RegistryBrowserHijackSource(IRegistryView registry, IHostsFileOpener hostsOpener, IPersistenceFileParser parser, string systemDirectory,
        Func<bool> isSystem, IReadOnlyList<string>? keepHostsNames, TimeProvider time, ILogger logger)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _hostsOpener = hostsOpener ?? throw new ArgumentNullException(nameof(hostsOpener));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _systemDirectory = string.IsNullOrWhiteSpace(systemDirectory) ? throw new ArgumentException("A system directory is needed.", nameof(systemDirectory)) : systemDirectory;
        _isSystem = isSystem ?? throw new ArgumentNullException(nameof(isSystem));
        _keepHostsNames = keepHostsNames ?? HostsNameFilter.DefaultSecurityDomains;
        if (!HostsNameFilter.IsValid(_keepHostsNames))
        {
            throw new ArgumentException("The hosts name filter is outside its caps or has an invalid suffix.", nameof(keepHostsNames));
        }

        _time = time ?? throw new ArgumentNullException(nameof(time));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>The domain suffixes sent to the worker with the hosts file.</summary>
    internal IReadOnlyList<string> KeepHostsNames => _keepHostsNames;

    /// <summary>The hosts file read: <c>&lt;system directory&gt;\drivers\etc\hosts</c>.</summary>
    internal string HostsPath => Path.Join(_systemDirectory, @"drivers\etc\hosts");

    public async Task<BrowserHijackSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return await Task.Run(() => CollectAsync(cancellationToken), cancellationToken).ConfigureAwait(false);
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

    internal async Task<BrowserHijackSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        var collectedAt = _time.GetUtcNow();
        var machine = ReadSettings(RegistryRoot.LocalMachine, InternetSettingsPath);
        var policy = ReadSettings(RegistryRoot.LocalMachine, PolicyInternetSettingsPath);
        var winHttp = ReadWinHttp();
        cancellationToken.ThrowIfCancellationRequested();

        var users = ReadUsers(out var usersRead, out bool usersTruncated, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        var hosts = await ReadHostsAsync(cancellationToken).ConfigureAwait(false);
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
            result.Add(ReadAccount(sid, isServiceAccount: true));
        }

        state = listState;
        result.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Sid, b.Sid));
        return result;
    }

    /// <summary>
    /// One account's keys. The hive itself is opened first and kept open while its keys are read (E6 review M3): a hive that is
    /// gone (a logoff since the listing) is NotLoaded, never a missing key that would read as "no proxy".
    /// </summary>
    private UserProxySettings ReadAccount(string sid, bool isServiceAccount)
    {
        try
        {
            using var hive = _registry.Open(RegistryRoot.Users, sid);
            if (hive is null)
            {
                return NotLoaded(sid, isServiceAccount);
            }

            return new UserProxySettings(sid, HiveLoaded: true, isServiceAccount,
                ReadSettings(RegistryRoot.Users, sid + @"\" + InternetSettingsPath),
                ReadSettings(RegistryRoot.Users, sid + @"\" + PolicyInternetSettingsPath));
        }
        catch (Exception ex) when (IsReadFailure(ex))
        {
            var unknown = ProxySettings.Unknown(StateOf(ex), "The hive can't be opened.");
            return new UserProxySettings(sid, HiveLoaded: true, isServiceAccount, unknown, unknown);
        }
    }

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
                ProxyEnable = Number(key, "ProxyEnable", unreadable, ref cut),
                ProxyServer = Text(key, "ProxyServer", unreadable, ref cut),
                ProxyOverride = Text(key, "ProxyOverride", unreadable, ref cut),
                AutoConfigUrl = Text(key, "AutoConfigURL", unreadable, ref cut),
                ProxySettingsPerUser = Number(key, "ProxySettingsPerUser", unreadable, ref cut),
            };

            ConnectionSettingsBlob? blob = null;
            using (var connections = key.OpenSubKey(ConnectionsSubKey))
            {
                if (connections is not null && Sized(connections, DefaultConnectionValue, unreadable, ConnectionsSubKey + @"\" + DefaultConnectionValue, ref cut) is { } data)
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
            if (connections?.ValueSize(WinHttpValue) > ProxySettings.MaxStoredBytes)
            {
                return new WinHttpProxySettings { Read = HijackReadState.Available, TooLarge = true };
            }

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

    internal async Task<HostsFileSnapshot> ReadHostsAsync(CancellationToken cancellationToken)
    {
        var path = HostsPath;
        var (dbState, dbRaw, dbExpanded, dbRedirected) = ReadDataBasePath();
        var snapshot = new HostsFileSnapshot
        {
            Read = HijackReadState.Failed,
            Path = path,
            DataBasePathRead = dbState,
            DataBasePath = dbRaw,
            DataBasePathExpanded = dbExpanded,
            DataBasePathRedirected = dbRedirected,
        };

        HostsFileOpen opened;
        try
        {
            opened = _hostsOpener.Open(path);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return snapshot with { Detail = ex.GetType().Name };
        }

        using (opened)
        {
            snapshot = snapshot with
            {
                Read = opened.State,
                Detail = Detail(opened.Detail),
                Length = opened.Length,
                LastWriteTime = opened.LastWriteTime,
                OwnerSid = opened.OwnerSid,
                NumberOfLinks = opened.NumberOfLinks,
                WritableByNonAdmins = opened.WritableByNonAdmins,
                OwnerIsTrusted = opened.OwnerSid is null ? null : TrustedOwners.Contains(opened.OwnerSid),
                ContentTruncated = opened.Length > HostsFileSnapshot.MaxBytes,
            };
            if (opened.State != HijackReadState.Available || opened.Handle is null)
            {
                return snapshot with { Read = opened.State == HijackReadState.Available ? HijackReadState.Failed : opened.State };
            }

            var (state, detail, content) = await ParseInWorkerAsync(opened.Handle, path, cancellationToken).ConfigureAwait(false);
            return snapshot with
            {
                Read = state,
                Detail = Detail(detail),
                Content = content,
                ContentTruncated = snapshot.ContentTruncated || (content?.InputTruncated ?? false),
            };
        }
    }

    /// <summary>The hosts handle through the sandboxed worker; the broker already validated its answer (untrusted input).</summary>
    private async Task<(HijackReadState State, string? Detail, HostsParseResult? Content)> ParseInWorkerAsync(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle, string path, CancellationToken cancellationToken)
    {
        IReadOnlyList<PersistenceParseResult> results;
        try
        {
            results = await _parser.ParseBatchAsync([new PersistenceParseInput(handle, WorkerParseKind.HostsFile, path, _keepHostsNames)], null, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or OutOfMemoryException))
        {
            return (HijackReadState.Failed, $"The sandboxed parser failed ({ex.GetType().Name}).", null);
        }

        var result = results.Count == 1 ? results[0] : null;
        return result switch
        {
            { Status: PersistenceParseStatus.Parsed, Hosts: { } hosts } => (HijackReadState.Available, null, hosts),
            { Status: PersistenceParseStatus.Unavailable } => (HijackReadState.ParserUnavailable, result.Message, null),
            { Status: PersistenceParseStatus.Malformed } => (HijackReadState.Failed, result.Message, null),
            _ => (HijackReadState.Failed, "The sandboxed parser gave no hosts answer.", null),
        };
    }

    private static string? Detail(string? text) => text is null ? null : SafeText.SingleLine(text, 256) is { Length: > 0 } line ? line : null;

    /// <summary>
    /// <c>Tcpip\Parameters\DataBasePath</c>: the folder the resolver takes the hosts file from. Redirected unless it is the stored
    /// default, or expands (machine environment from the registry) to <c>&lt;system directory&gt;\drivers\etc</c>.
    /// </summary>
    private (HijackReadState State, string? Raw, string? Expanded, bool? Redirected) ReadDataBasePath()
    {
        try
        {
            using var key = _registry.Open(RegistryRoot.LocalMachine, TcpipParametersPath);
            if (key?.ValueSize("DataBasePath") > ProxySettings.MaxStoredBytes)
            {
                return (HijackReadState.Available, null, null, true); // not read; certainly not the default
            }

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

    /// <summary>
    /// The value, unless it doesn't exist (null) or is stored larger than <see cref="ProxySettings.MaxStoredBytes"/> (E6 review M5):
    /// then it isn't read at all, is listed as unreadable and sets <paramref name="cut"/>.
    /// </summary>
    private static RegistryData? Sized(IRegistryKeyReader key, string name, List<string> unreadable, string label, ref bool cut)
    {
        if (key.ValueSize(name) > ProxySettings.MaxStoredBytes)
        {
            unreadable.Add(label);
            cut = true;
            return null;
        }

        return key.Value(name);
    }

    private static long? Number(IRegistryKeyReader key, string name, List<string> unreadable, ref bool cut)
    {
        if (Sized(key, name, unreadable, name, ref cut) is not { } data)
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
        if (Sized(key, name, unreadable, name, ref cut) is not { } data)
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
