using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Hashing;

/// <summary>Whether an object lies inside a registered Cloud Files sync root (section C follow-up review H-D).</summary>
public enum SyncRootStatus
{
    /// <summary>The Cloud Files API says no registered sync root contains it: no provider exists that could be asked to recall it.</summary>
    NotInSyncRoot,

    /// <summary>A registered sync root (OneDrive, another provider) contains it: a real placeholder.</summary>
    InSyncRoot,

    /// <summary>The API couldn't tell (not available, an unexpected error). Treated as a placeholder, and counted as not covered.</summary>
    Unknown,
}

/// <summary>What <see cref="FilePlaceholder.Classify"/> found.</summary>
public enum PlaceholderKind
{
    /// <summary>Doesn't look like a placeholder.</summary>
    None,

    /// <summary>Looks like one and a registered sync root contains it: skipped (its content may not be local).</summary>
    InSyncRoot,

    /// <summary>Looks like one, but whether a sync root contains it is unknown: skipped, and the scan isn't complete.</summary>
    Unconfirmed,

    /// <summary>Looks like one, but no sync root contains it (a user-set look): no provider can recall it, so it is read / walked.</summary>
    OutsideSyncRoot,
}

/// <summary>Asks whether a handle's object is inside a registered sync root. Fake it in tests.</summary>
public interface ISyncRootProbe
{
    /// <summary>Never throws for an API problem (that is <see cref="SyncRootStatus.Unknown"/>).</summary>
    SyncRootStatus Check(SafeFileHandle handle);
}

/// <summary>
/// The real probe: <c>CfGetSyncRootInfoByHandle</c> (cldapi.dll, Windows 10 1709+). It reads the sync root's registration
/// only; nothing is fetched, recalled or sent to the provider.
/// </summary>
public sealed class CloudSyncRootProbe : ISyncRootProbe
{
    /// <summary>HRESULT_FROM_WIN32(ERROR_CLOUD_FILE_NOT_IN_SYNC_ROOT), what the API returns outside every sync root.</summary>
    internal const int NotInSyncRootHresult = unchecked((int)0x80070186);

    private const int SyncRootInfoBasic = 0; // CF_SYNC_ROOT_INFO_BASIC: CF_SYNC_ROOT_BASIC_INFO { LARGE_INTEGER SyncRootFileId; }

    public static CloudSyncRootProbe Instance { get; } = new();

    public SyncRootStatus Check(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid || handle.IsClosed)
        {
            return SyncRootStatus.Unknown;
        }

        try
        {
            long fileId = 0;
            int hr = CfGetSyncRootInfoByHandle(handle, SyncRootInfoBasic, ref fileId, sizeof(long), out _);
            return Classify(hr);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return SyncRootStatus.Unknown; // no Cloud Files API on this Windows (Server Core, older builds)
        }
    }

    /// <summary>S_OK (or any success, e.g. a buffer that only holds the first field) is in a sync root; "not in one" is the only no.</summary>
    internal static SyncRootStatus Classify(int hresult) => hresult switch
    {
        >= 0 => SyncRootStatus.InSyncRoot,
        NotInSyncRootHresult => SyncRootStatus.NotInSyncRoot,
        _ => SyncRootStatus.Unknown,
    };

    [DllImport("cldapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int CfGetSyncRootInfoByHandle(SafeFileHandle fileHandle, int infoClass, ref long infoBuffer, int infoBufferLength, out int returnedLength);
}
