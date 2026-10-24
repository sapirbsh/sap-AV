using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Scanning;
using SapAV.Engine.Pipe.Native;
using SapAV.Engine.Scanning;
using SapAV.Engine.Scanning.Native;

namespace SapAV.Engine.Pipe;

/// <summary>Result of checking a client's access to a file system object.</summary>
public enum AccessDecision
{
    Granted,
    Denied,
    NotFound,

    /// <summary>The object isn't the expected one (a different file object at the path now).</summary>
    Mismatch,

    /// <summary>The path goes through a junction, symlink or mount point (or is one), or is on a network drive: refused.</summary>
    Redirected,
}

/// <summary>
/// Access checks with a <b>client's</b> token against objects the engine opens itself (B4). The engine never opens a
/// client-supplied path while impersonating (the client controls its own drive-letter mappings), and never with a
/// following open (review B4 M2: an intermediate symlink could send SYSTEM to a remote server). The object is opened as
/// the engine with <see cref="SafeTree"/> (component by component, no reparse point followed, name surrogates refused),
/// for READ_CONTROL + attributes only; its descriptor is read from that handle and AccessCheck runs with the client
/// token. Anything that can't be determined is Denied (fails closed).
/// </summary>
internal static class ClientAccess
{
    /// <summary>
    /// Opens <paramref name="path"/> safely (see the class remarks); null with the decision when it can't be opened.
    /// </summary>
    public static SafeFileHandle? OpenForCheck(string path, out AccessDecision failure)
    {
        var handle = SafeTree.Open(path, SafeTree.InspectAccess, SafeTree.ShareAll, 0, out var why, out _);
        failure = why switch
        {
            SafeTreeFailure.None => AccessDecision.Granted,
            SafeTreeFailure.NotFound => AccessDecision.NotFound,
            SafeTreeFailure.Redirected or SafeTreeFailure.Unsupported => AccessDecision.Redirected,
            _ => AccessDecision.Denied,
        };
        return handle;
    }

    /// <summary>
    /// Checks <paramref name="desiredAccess"/> on <paramref name="path"/>. With <paramref name="expected"/>, the opened object
    /// must be that file (volume serial + 128-bit file ID), so the check is bound to the scanned object.
    /// </summary>
    public static AccessDecision Check(IClientIdentity client, string path, uint desiredAccess, FileIdentity? expected = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        using var handle = OpenForCheck(path, out var failure);
        if (handle is null)
        {
            return failure;
        }

        if (expected is not null && !expected.IsSameObject(FileIdentity.TryCapture(handle)))
        {
            return AccessDecision.Mismatch;
        }

        return IsGranted(client, handle, desiredAccess) ? AccessDecision.Granted : AccessDecision.Denied;
    }

    /// <summary>AccessCheck against the descriptor of an open handle (opened with READ_CONTROL).</summary>
    public static bool IsGranted(IClientIdentity client, System.Runtime.InteropServices.SafeHandle handle, uint desiredAccess)
    {
        var sd = PipeNative.TryReadFileSecurity(handle);
        return sd is not null && client.IsGranted(sd, desiredAccess);
    }

    /// <summary>The client may read (files) or list (folders) <paramref name="path"/>: FILE_READ_DATA / FILE_LIST_DIRECTORY.</summary>
    public static AccessDecision CanReadOrList(IClientIdentity client, string path) => Check(client, path, PipeNative.FileReadData);

    /// <summary>
    /// The client could delete the scanned file itself: DELETE on the file, or FILE_DELETE_CHILD on its folder
    /// (review B2 follow-up Medium: who may request a quarantine).
    /// </summary>
    public static AccessDecision CanDelete(IClientIdentity client, FileScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Identity is not { } identity)
        {
            return AccessDecision.Denied;
        }

        string path = report.Result.Item.Path;
        var onFile = Check(client, path, PipeNative.Delete, identity);
        if (onFile is AccessDecision.Granted or AccessDecision.NotFound or AccessDecision.Mismatch or AccessDecision.Redirected)
        {
            return onFile;
        }

        string? parent = ParentOf(path);
        return parent is not null && Check(client, parent, PipeNative.FileDeleteChild) == AccessDecision.Granted
            ? AccessDecision.Granted
            : AccessDecision.Denied;
    }

    /// <summary>The client may create a file in the folder of <paramref name="originalPath"/> (FILE_ADD_FILE; review B2 M5).</summary>
    public static AccessDecision CanAddFileNextTo(IClientIdentity client, string originalPath)
    {
        string? parent = ParentOf(originalPath);
        return parent is null ? AccessDecision.Denied : Check(client, parent, PipeNative.FileAddFile);
    }

    /// <summary>The folder of a path (exact: trailing dots and spaces kept), or null.</summary>
    internal static string? ParentOf(string path)
    {
        string? exact = ExactPath.ToExtended(path);
        if (exact is null || exact.Length <= 7 || !exact.StartsWith(@"\\?\", StringComparison.Ordinal) || exact[5] != ':')
        {
            return null; // \\?\C:\ itself has no parent; UNC is never used here
        }

        int cut = exact.LastIndexOf('\\');
        return cut == 6 ? exact[..7] : exact[..cut];
    }
}

/// <summary>The <see cref="IScanAccessCheck"/> of a job a standard user requested; owns a copy of the client's token.</summary>
internal sealed class ClientScanAccess(IClientIdentity client) : IScanAccessCheck, IDisposable
{
    private const uint ShareAll = ScanNative.FileShareRead | ScanNative.FileShareWrite | ScanNative.FileShareDelete;

    public bool CanList(SafeFileHandle directory) => ClientAccess.IsGranted(client, directory, PipeNative.FileReadData);

    public bool CanRead(SafeFileHandle handle)
    {
        using var control = ScanNative.ReOpen(handle, PipeNative.ReadControl, ShareAll, out _);
        return control is not null && ClientAccess.IsGranted(client, control, PipeNative.FileReadData);
    }

    public void Dispose() => client.Dispose();
}
