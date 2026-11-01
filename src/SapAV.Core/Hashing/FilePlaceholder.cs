namespace SapAV.Core.Hashing;

/// <summary>
/// Is a file or folder a cloud / HSM placeholder whose content isn't on the disk (section C review H3)? Reading or listing
/// one could make the provider download it, so scans skip and count them. Decided by what a standard user can't simply set:
/// RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS, or Offline together with a cloud-files / HSM reparse tag.
/// </summary>
/// <remarks>
/// <b>Plain Offline is not a placeholder.</b> Any standard user can run <c>attrib +O</c> on their own file or folder, and
/// such an exe still runs, so plain Offline must never hide anything from a scan: those files are opened with FILE_OPEN_NO_RECALL
/// and scanned, those folders walked, and the attribute is a weak heuristic signal. A cloud tag without Offline or a recall
/// attribute is a hydrated file: its content is local and it is scanned like any other.
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

    /// <summary>True when the content isn't local: see the class remarks. <paramref name="reparseTag"/> counts only with ReparsePoint.</summary>
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

    /// <summary>Offline without being a placeholder: the attribute alone (<c>attrib +O</c>), which the file's content doesn't back up.</summary>
    public static bool IsPlainOffline(FileAttributes attributes, uint reparseTag) =>
        attributes.HasFlag(FileAttributes.Offline) && !IsPlaceholder(attributes, reparseTag);

    /// <summary>A cloud-files (OneDrive and other sync providers) or HSM reparse tag.</summary>
    public static bool IsCloudOrHsmTag(uint tag) =>
        tag is TagHsm or TagHsm2 or TagOneDrive || (tag & TagCloudMask) == TagCloudBase;

    /// <summary>
    /// Test seam: a real placeholder needs a registered sync root, so tests of the skip paths stand one in with the Offline
    /// attribute (<see cref="File.SetAttributes(string, FileAttributes)"/>) inside this scope. Per async flow; never set in production.
    /// </summary>
    internal static IDisposable OfflineIsPlaceholderForTests()
    {
        s_offlineIsPlaceholder.Value = true;
        return new Scope();
    }

    private sealed class Scope : IDisposable
    {
        public void Dispose() => s_offlineIsPlaceholder.Value = false;
    }
}
