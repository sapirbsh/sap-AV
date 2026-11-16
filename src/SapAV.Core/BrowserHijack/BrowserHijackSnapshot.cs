namespace SapAV.Core.BrowserHijack;

/// <summary>
/// Whether one part of the browser-hijack snapshot (ROADMAP E6) could be read. Every value other than <see cref="Available"/>
/// means the values of that part are <b>unknown</b>, never "not set": a rule must not read "no proxy" or "no hosts entries"
/// from an unknown part.
/// </summary>
public enum HijackReadState
{
    /// <summary>Read. For a registry key, a missing key or value is a known "not set" (see <see cref="ProxySettings.KeyExists"/>).</summary>
    Available,

    /// <summary>The file doesn't exist (hosts). Known: Windows then has no hosts entries.</summary>
    NotFound,

    /// <summary>The user's registry hive isn't loaded (the user isn't logged on); the engine never loads NTUSER.DAT. Unknown.</summary>
    NotLoaded,

    /// <summary>The caller isn't allowed to read it. Unknown.</summary>
    AccessDenied,

    /// <summary>A junction / symbolic link on the way to the file; not followed (itself a hijack sign for <c>drivers\etc</c>). Unknown.</summary>
    Redirected,

    /// <summary>The path is on a network location; the engine doesn't contact servers. Unknown.</summary>
    Remote,

    /// <summary>The file is held exclusively (or an oplock would have to be broken). Unknown.</summary>
    Locked,

    /// <summary>Any other failure (including a hosts file the sandboxed parser refused or failed on); the part's <c>Detail</c> says what. Unknown.</summary>
    Failed,

    /// <summary>
    /// The sandboxed scan worker that parses the hosts file isn't available (no sandbox, or it can't start): the file was opened
    /// but not parsed. The engine never parses it itself (B5 rule). Unknown.
    /// </summary>
    ParserUnavailable,
}

/// <summary>
/// One WinINet "Internet Settings" key (per user, machine-wide, or its Group Policy twin), as stored. Every string is raw in the
/// <see cref="Text.SafeText.Identifier"/> style (controls become U+FFFD, nothing trimmed), capped at <see cref="MaxValueLength"/>.
/// </summary>
/// <remarks>
/// When <see cref="Read"/> is <see cref="HijackReadState.Available"/>, a null value means "not set" (Windows' default applies).
/// Otherwise every value is unknown. A value that exists with a type the collector can't read (e.g. <c>ProxyServer</c> as
/// REG_BINARY) is listed in <see cref="UnreadableValues"/> instead of silently reading as "not set".
/// </remarks>
public sealed record ProxySettings
{
    public const int MaxValueLength = 4096;

    /// <summary>A registry value stored larger than this (bytes) isn't read at all: it is listed in <see cref="UnreadableValues"/> and sets <see cref="Truncated"/>.</summary>
    public const int MaxStoredBytes = 64 * 1024;

    /// <summary>A key whose values are unknown.</summary>
    public static ProxySettings Unknown(HijackReadState state, string? detail = null)
    {
        if (state == HijackReadState.Available)
        {
            throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown settings need a non-Available state.");
        }

        return new ProxySettings { Read = state, Detail = detail };
    }

    /// <summary>A key that was read and doesn't exist: every value is "not set".</summary>
    public static ProxySettings Missing { get; } = new() { Read = HijackReadState.Available, KeyExists = false };

    public required HijackReadState Read { get; init; }

    /// <summary>A short reason when <see cref="Read"/> isn't Available (sanitized, capped).</summary>
    public string? Detail { get; init; }

    /// <summary>True when the key exists (only meaningful when <see cref="Read"/> is Available).</summary>
    public bool KeyExists { get; init; }

    /// <summary><c>ProxyEnable</c> (REG_DWORD, or a number in a string); null = not set or unknown.</summary>
    public long? ProxyEnable { get; init; }

    /// <summary><c>ProxyServer</c>, e.g. <c>127.0.0.1:8080</c> or <c>http=host:port;https=host:port</c>.</summary>
    public string? ProxyServer { get; init; }

    /// <summary><c>ProxyOverride</c>: the bypass list.</summary>
    public string? ProxyOverride { get; init; }

    /// <summary><c>AutoConfigURL</c>: a PAC script URL (a classic hijack: a remote or <c>file://</c> PAC routes chosen sites).</summary>
    public string? AutoConfigUrl { get; init; }

    /// <summary><c>ProxySettingsPerUser</c> (Group Policy key only): 0 = one machine-wide proxy for every user; null = not set.</summary>
    public long? ProxySettingsPerUser { get; init; }

    /// <summary>
    /// <c>Connections\DefaultConnectionSettings</c>, the binary blob WinINet actually uses (its flags can enable a proxy or PAC
    /// even when <see cref="ProxyEnable"/> says 0). Null = not set (or unknown, see <see cref="Read"/>).
    /// </summary>
    public ConnectionSettingsBlob? DefaultConnection { get; init; }

    /// <summary>Names of values that exist with a type that couldn't be read, or over <see cref="MaxStoredBytes"/> (capped); their content is unknown.</summary>
    public IReadOnlyList<string> UnreadableValues { get; init; } = [];

    /// <summary>True when a value was cut at <see cref="MaxValueLength"/>. A multi-kilobyte proxy value is odd in itself.</summary>
    public bool Truncated { get; init; }

    /// <summary>
    /// True when this key turns a proxy or PAC on (<see cref="ProxyEnable"/> non-zero with a server, an
    /// <see cref="AutoConfigUrl"/>, or the blob's proxy / PAC flags); false when it was read and does none of that; null when
    /// unknown (not read, or an unreadable value or a blob that didn't parse leaves it open).
    /// </summary>
    public bool? ConfiguresProxy
    {
        get
        {
            if (Read != HijackReadState.Available)
            {
                return null;
            }

            if ((ProxyEnable is { } enable && enable != 0 && !string.IsNullOrEmpty(ProxyServer)) || !string.IsNullOrEmpty(AutoConfigUrl)
                || DefaultConnection?.ProxyEnabled == true || DefaultConnection?.AutoConfigEnabled == true)
            {
                return true;
            }

            return UnreadableValues.Count > 0 || (DefaultConnection is not null && DefaultConnection.Status != BlobParseStatus.Parsed) ? null : false;
        }
    }
}

/// <summary>The proxy settings of one account under <c>HKEY_USERS</c>.</summary>
/// <param name="Sid">The account's SID (a user, or SYSTEM / LocalService / NetworkService).</param>
/// <param name="HiveLoaded">False for a profile in ProfileList whose hive isn't loaded: <see cref="Settings"/> and <see cref="Policy"/> are NotLoaded (unknown).</param>
/// <param name="IsServiceAccount">S-1-5-18 / 19 / 20: services running as these accounts use this proxy.</param>
/// <param name="Settings"><c>HKU\&lt;SID&gt;\Software\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</param>
/// <param name="Policy"><c>HKU\&lt;SID&gt;\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</param>
public sealed record UserProxySettings(string Sid, bool HiveLoaded, bool IsServiceAccount, ProxySettings Settings, ProxySettings Policy);

/// <summary>The machine-wide WinHTTP proxy (<c>netsh winhttp show proxy</c>), used by services and many updaters.</summary>
public sealed record WinHttpProxySettings
{
    public static WinHttpProxySettings Unknown(HijackReadState state, string? detail = null) => state == HijackReadState.Available
        ? throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown settings need a non-Available state.")
        : new WinHttpProxySettings { Read = state, Detail = detail };

    public required HijackReadState Read { get; init; }

    public string? Detail { get; init; }

    /// <summary>
    /// <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings</c>, parsed; null when the
    /// value isn't set (direct access) or unknown (see <see cref="Read"/>).
    /// </summary>
    public ConnectionSettingsBlob? Settings { get; init; }

    /// <summary>True when the value exists but isn't REG_BINARY (unknown content).</summary>
    public bool UnexpectedType { get; init; }

    /// <summary>True when the value is larger than <see cref="ProxySettings.MaxStoredBytes"/> and wasn't read (unknown content, and odd in itself).</summary>
    public bool TooLarge { get; init; }

    /// <summary>True when a WinHTTP proxy is set, false when it is known not to be, null when unknown.</summary>
    public bool? ConfiguresProxy => Read != HijackReadState.Available || UnexpectedType || TooLarge ? null
        : Settings is null ? false
        : Settings.ProxyEnabled == true || !string.IsNullOrEmpty(Settings.ProxyServer) ? true
        : Settings.Status != BlobParseStatus.Parsed ? null
        : false;
}

/// <summary>
/// The hosts file Windows' resolver reads (ROADMAP E6), plus where the registry says the resolver looks for it.
/// </summary>
public sealed record HostsFileSnapshot
{
    /// <summary>The read cap: the file is read up to this many bytes; a longer file sets <see cref="ContentTruncated"/>.</summary>
    public const int MaxBytes = 1024 * 1024;

    /// <summary>How reading the file at <see cref="Path"/> went (opened by the engine, parsed by the sandboxed worker). Only <see cref="HijackReadState.Available"/> fills <see cref="Content"/>.</summary>
    public required HijackReadState Read { get; init; }

    public string? Detail { get; init; }

    /// <summary>The file that was read: <c>&lt;system directory&gt;\drivers\etc\hosts</c> (never taken from DataBasePath).</summary>
    public required string Path { get; init; }

    /// <summary>The file's size in bytes, or null when unknown.</summary>
    public long? Length { get; init; }

    /// <summary>Last write time (UTC), or null when unknown.</summary>
    public DateTimeOffset? LastWriteTime { get; init; }

    /// <summary>The owner's SID string, or null when unknown.</summary>
    public string? OwnerSid { get; init; }

    /// <summary>True when the owner is SYSTEM, Administrators or TrustedInstaller; false for anyone else; null when unknown.</summary>
    public bool? OwnerIsTrusted { get; init; }

    /// <summary>The file's hard-link count (more than 1: another name can change it), or null when unknown.</summary>
    public uint? NumberOfLinks { get; init; }

    /// <summary>True when the DACL lets a non-administrator write or delete the file (a hijack enabler); null when unknown.</summary>
    public bool? WritableByNonAdmins { get; init; }

    /// <summary>True when the file is larger than <see cref="MaxBytes"/> and only the start was parsed. Suspicious in itself.</summary>
    public bool ContentTruncated { get; init; }

    /// <summary>The parsed entries (only when <see cref="Read"/> is Available).</summary>
    public HostsParseResult? Content { get; init; }

    /// <summary>How reading <c>Tcpip\Parameters\DataBasePath</c> went.</summary>
    public HijackReadState DataBasePathRead { get; init; }

    /// <summary><c>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath</c> as stored (unexpanded), or null when not set.</summary>
    public string? DataBasePath { get; init; }

    /// <summary><see cref="DataBasePath"/> expanded with the machine environment from the registry, or null.</summary>
    public string? DataBasePathExpanded { get; init; }

    /// <summary>
    /// True when DataBasePath points somewhere other than <c>&lt;system directory&gt;\drivers\etc</c>: the resolver then reads a
    /// different hosts file than <see cref="Path"/>, itself a hijack sign. False when it is the default or not set; null when unknown.
    /// </summary>
    public bool? DataBasePathRedirected { get; init; }
}

/// <summary>
/// A read-only snapshot of the settings a browser hijack changes (ROADMAP E6): per-user and machine proxy / PAC settings, the
/// WinHTTP proxy and the hosts file. The input for the browser-hijack rules (E6, detection-dev) and the scan checks (E7).
/// </summary>
/// <remarks>
/// Each part has its own read state; anything not read is unknown, never a guessed default. All strings are untrusted
/// (malware chose them) and kept raw but capped; truncation (<see cref="UsersTruncated"/>, <see cref="ProxySettings.Truncated"/>,
/// <see cref="HostsFileSnapshot.ContentTruncated"/>, <see cref="HostsParseResult.EntriesTruncated"/>) is itself a signal.
/// </remarks>
public sealed record BrowserHijackSnapshot
{
    /// <summary>At most this many accounts are listed (a padded ProfileList can't take the engine's memory).</summary>
    public const int MaxUsers = 256;

    public required DateTimeOffset CollectedAt { get; init; }

    /// <summary>Whether the collector ran as LocalSystem (null when unknown). Not as SYSTEM, other users' hives may be denied.</summary>
    public bool? CollectedAsSystem { get; init; }

    /// <summary>How listing the profiles and loaded hives went. Not Available: <see cref="Users"/> may be incomplete.</summary>
    public HijackReadState UsersRead { get; init; }

    /// <summary>One entry per user profile (loaded or not) and per loaded service-account hive, ordered by SID.</summary>
    public IReadOnlyList<UserProxySettings> Users { get; init; } = [];

    /// <summary>True when there were more than <see cref="MaxUsers"/> accounts. Suspicious.</summary>
    public bool UsersTruncated { get; init; }

    /// <summary><c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings</c> (used for everyone when <see cref="ProxyIsMachineWide"/>).</summary>
    public required ProxySettings MachineSettings { get; init; }

    /// <summary><c>HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings</c>.</summary>
    public required ProxySettings MachinePolicy { get; init; }

    public required WinHttpProxySettings WinHttp { get; init; }

    public required HostsFileSnapshot Hosts { get; init; }

    /// <summary>True when Group Policy sets <c>ProxySettingsPerUser</c> = 0 (one machine-wide proxy); false when it doesn't; null when unknown.</summary>
    public bool? ProxyIsMachineWide =>
        MachinePolicy.Read != HijackReadState.Available || MachinePolicy.UnreadableValues.Contains("ProxySettingsPerUser", StringComparer.OrdinalIgnoreCase)
            ? null
            : MachinePolicy.ProxySettingsPerUser == 0;
}
