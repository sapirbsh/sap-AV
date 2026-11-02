using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Hashing;

/// <summary>
/// Is a file or folder a cloud / HSM placeholder whose content isn't on the disk (section C review H3, follow-up review H-D)?
/// Reading or listing a real one could make the provider download it, so scans skip and count them.
/// </summary>
/// <remarks>
/// <para><b>Two steps.</b> <see cref="IsPlaceholder"/> says what the attributes look like: RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS,
/// or Offline together with a cloud-files / HSM reparse tag. That is <b>not</b> proof: any standard user can put a cloud or HSM
/// reparse tag (FSCTL_SET_REPARSE_POINT) and Offline on their own file or folder, and the files in such a folder still open
/// and run. So only <see cref="IsConfirmedPlaceholder"/> (the look, plus the Cloud Files API confirming a registered sync root
/// on the opened handle, <see cref="ISyncRootProbe"/>) may make a scan skip something. Outside every sync root there is no
/// provider that could recall anything, so the object is opened with FILE_OPEN_NO_RECALL and scanned like any other.</para>
/// <para><b>Plain Offline is not a placeholder.</b> <c>attrib +O</c> on a file or folder never hides anything from a scan:
/// those files are opened with FILE_OPEN_NO_RECALL and scanned, those folders walked, and the attribute is a weak heuristic
/// signal. A cloud tag without Offline or a recall attribute is a hydrated file: its content is local and it is scanned.</para>
/// </remarks>
public static class FilePlaceholder
{
    /// <summary>FILE_ATTRIBUTE_RECALL_ON_OPEN.</summary>
    public const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;

    /// <summary>FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.</summary>
    public const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;

    private const uint TagHsm = 0xC0000004;
    private const uint TagHsm2 = 0x80000006;
    private const uint TagOneDrive = 0x80000021;
    private const uint TagCloudBase = 0x9000001A;
    private const uint TagCloudMask = 0xFFFF0FFF; // IO_REPARSE_TAG_CLOUD_1 ... CLOUD_F differ in bits 12-15

    private static readonly AsyncLocal<bool> s_offlineIsPlaceholder = new();

    /// <summary>
    /// True when the attributes <b>look</b> like a placeholder (see the class remarks); a user can set this look, so it never
    /// decides a skip alone. <paramref name="reparseTag"/> counts only with ReparsePoint.
    /// </summary>
    public static bool IsPlaceholder(FileAttributes attributes, uint reparseTag)
    {
        if ((attributes & (RecallOnOpen | RecallOnDataAccess)) != 0)
        {
            return true;
        }

        if (!attributes.HasFlag(FileAttributes.Offline))
        {
            return false;
        }

        return s_offlineIsPlaceholder.Value || (attributes.HasFlag(FileAttributes.ReparsePoint) && IsCloudOrHsmTag(reparseTag));
    }

    /// <summary>
    /// A placeholder a scan may skip: it looks like one and the Cloud Files API doesn't rule out a sync root for
    /// <paramref name="handle"/> (in one, or the API can't tell). Outside every sync root it is false: read it with no recall.
    /// </summary>
    public static bool IsConfirmedPlaceholder(SafeFileHandle handle, FileAttributes attributes, uint reparseTag, ISyncRootProbe? probe = null) =>
        Classify(handle, attributes, reparseTag, probe) is PlaceholderKind.InSyncRoot or PlaceholderKind.Unconfirmed;

    /// <summary>What an object with these attributes is, asking the Cloud Files API about <paramref name="handle"/> only when it looks like a placeholder.</summary>
    public static PlaceholderKind Classify(SafeFileHandle handle, FileAttributes attributes, uint reparseTag, ISyncRootProbe? probe = null)
    {
        if (!IsPlaceholder(attributes, reparseTag))
        {
            return PlaceholderKind.None;
        }

        if (s_offlineIsPlaceholder.Value && probe is null)
        {
            return PlaceholderKind.InSyncRoot; // the test seam stands in for a real sync root, unless the test gives its own probe
        }

        return (probe ?? CloudSyncRootProbe.Instance).Check(handle) switch
        {
            SyncRootStatus.InSyncRoot => PlaceholderKind.InSyncRoot,
            SyncRootStatus.NotInSyncRoot => PlaceholderKind.OutsideSyncRoot,
            _ => PlaceholderKind.Unconfirmed,
        };
    }

    /// <summary>Offline without looking like a placeholder: the attribute alone (<c>attrib +O</c>), which the file's content doesn't back up.</summary>
    public static bool IsPlainOffline(FileAttributes attributes, uint reparseTag) =>
        attributes.HasFlag(FileAttributes.Offline) && !IsPlaceholder(attributes, reparseTag);

    /// <summary>A cloud-files (OneDrive and other sync providers) or HSM reparse tag.</summary>
    public static bool IsCloudOrHsmTag(uint tag) =>
        tag is TagHsm or TagHsm2 or TagOneDrive || (tag & TagCloudMask) == TagCloudBase;

    /// <summary>
    /// Test seam: a real placeholder needs a registered sync root, so tests of the skip paths stand one in with the Offline
    /// attribute (<see cref="File.SetAttributes(string, FileAttributes)"/>) inside this scope; such files and folders count as
    /// confirmed unless the caller passes its own <see cref="ISyncRootProbe"/>. (A real user-tagged folder can't stand in: with a
    /// cloud tag and Offline the cloud filter refuses every open of it, and nothing under an HSM tag opens without an HSM filter.)
    /// Per async flow; never set in production.
    /// </summary>
    internal static IDisposable OfflineIsPlaceholderForTests()
    {
        s_offlineIsPlaceholder.Value = true;
        return new Scope();
    }

    /// <summary>True inside <see cref="OfflineIsPlaceholderForTests"/> (always false in production).</summary>
    internal static bool TestSeamActive => s_offlineIsPlaceholder.Value;

    private sealed class Scope : IDisposable
    {
        public void Dispose() => s_offlineIsPlaceholder.Value = false;
    }
}
