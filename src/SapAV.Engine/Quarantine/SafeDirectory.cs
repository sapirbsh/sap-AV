using Microsoft.Win32.SafeHandles;
using SapAV.Core.Quarantine;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

/// <summary>Why <see cref="SafeDirectory.TryOpen"/> refused a directory.</summary>
public enum SafeDirectoryFailure
{
    None,

    /// <summary>The path isn't a usable drive-letter path, or the drive is a network drive.</summary>
    Unsupported,

    /// <summary>A component doesn't exist (the folder was deleted or renamed).</summary>
    NotFound,

    /// <summary>A component is a reparse point (junction, symlink, mount point) or not a directory.</summary>
    Redirected,

    /// <summary>The opened directory's final path isn't the expected one.</summary>
    PathMismatch,

    /// <summary>Access denied, sharing violation or another error opening a component.</summary>
    Error,
}

/// <summary>
/// Opens a directory for SYSTEM-privileged file creation <b>without ever following a reparse point</b>: the volume
/// root is opened with <c>FILE_FLAG_OPEN_REPARSE_POINT</c>, then each component relative to the previous handle with
/// <c>NtCreateFile(RootDirectory, FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE)</c>, and each one must report neither
/// <c>FILE_ATTRIBUTE_REPARSE_POINT</c> nor a non-directory. Finally the handle's final path must equal the
/// expected path (case-insensitive).
/// </summary>
/// <remarks>
/// Callers create files <b>relative to the returned handle</b>, so a later swap of any component (rename, junction)
/// can't redirect the write: the handle names the directory object, which a user can only move into places they
/// can already write.
/// </remarks>
public static class SafeDirectory
{
    private const uint ComponentAccess = N.FileReadAttributes | N.FileTraverse;
    private const uint ShareAll = N.ShareRead | N.ShareWrite | N.ShareDelete;

    /// <summary>
    /// Opens <paramref name="directoryPath"/> (<c>X:\a\b</c> or <c>X:\</c>). On success the caller owns the handle.
    /// </summary>
    public static SafeFileHandle? TryOpen(string directoryPath, out SafeDirectoryFailure failure, out string reason)
    {
        ArgumentNullException.ThrowIfNull(directoryPath);
        var trimmed = directoryPath.TrimEnd('\\');
        if (trimmed.Length == 2 && char.IsAsciiLetter(trimmed[0]) && trimmed[1] == ':')
        {
            return OpenVolumeRoot(trimmed[0], out failure, out reason);
        }

        // Validate as if it were a file path: same component rules.
        if (!QuarantinePath.TryValidateOriginalPath(trimmed, out var why))
        {
            failure = SafeDirectoryFailure.Unsupported;
            reason = $"Unsupported directory path: {why}.";
            return null;
        }

        var (drive, directories, last) = QuarantinePath.Split(trimmed);
        var current = OpenVolumeRoot(drive[0], out failure, out reason);
        if (current is null)
        {
            return null;
        }

        foreach (var component in directories.Append(last))
        {
            var next = OpenComponent(current, component, out failure, out reason);
            current.Dispose();
            if (next is null)
            {
                return null;
            }

            current = next;
        }

        var final = N.GetFinalDosPath(current);
        if (final is null || !string.Equals(final.TrimEnd('\\'), trimmed, StringComparison.OrdinalIgnoreCase))
        {
            current.Dispose();
            failure = SafeDirectoryFailure.PathMismatch;
            reason = $"The opened directory's final path ({final ?? "unknown"}) is not {trimmed}.";
            return null;
        }

        failure = SafeDirectoryFailure.None;
        reason = string.Empty;
        return current;
    }

    /// <summary>True if the object behind <paramref name="handle"/> is a plain directory (not a reparse point).</summary>
    public static bool IsPlainDirectory(SafeFileHandle handle) =>
        N.TryGetAttributeTag(handle, out uint attributes, out _)
        && (attributes & N.FileAttributeDirectory) != 0
        && (attributes & N.FileAttributeReparsePoint) == 0;

    private static SafeFileHandle? OpenVolumeRoot(char drive, out SafeDirectoryFailure failure, out string reason)
    {
        string root = $"{char.ToUpperInvariant(drive)}:\\";
        uint type = GetDriveType(root);
        if (type is 0 /* unknown */ or 1 /* no root */ or 4 /* remote */)
        {
            failure = type == 4 ? SafeDirectoryFailure.Unsupported : SafeDirectoryFailure.NotFound;
            reason = $"Drive {root} is {(type == 4 ? "a network drive" : "not available")}.";
            return null;
        }

        var handle = N.OpenDirectoryNoReparse(@"\\?\" + root, ComponentAccess, ShareAll, out int error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            (failure, reason) = Map(error, root);
            return null;
        }

        failure = SafeDirectoryFailure.None;
        reason = string.Empty;
        return handle;
    }

    private static SafeFileHandle? OpenComponent(SafeFileHandle parent, string name, out SafeDirectoryFailure failure, out string reason)
    {
        var handle = N.OpenRelative(parent, name, ComponentAccess, ShareAll, N.FileOpen,
            N.FileOpenReparsePoint, out int error, N.ObjCaseInsensitive | N.ObjDontReparse);
        if (handle is null)
        {
            (failure, reason) = error == N.ErrorDirectory
                ? (SafeDirectoryFailure.Redirected, $"'{name}' is not a directory.")
                : Map(error, name);
            return null;
        }

        if (!N.TryGetAttributeTag(handle, out uint attributes, out uint tag))
        {
            handle.Dispose();
            failure = SafeDirectoryFailure.Error;
            reason = $"Could not read the attributes of '{name}'.";
            return null;
        }

        if ((attributes & N.FileAttributeReparsePoint) != 0 || (attributes & N.FileAttributeDirectory) == 0)
        {
            handle.Dispose();
            failure = SafeDirectoryFailure.Redirected;
            reason = (attributes & N.FileAttributeReparsePoint) != 0
                ? $"'{name}' is a reparse point (tag 0x{tag:X8}: junction, symbolic link or mount point); refusing to follow it."
                : $"'{name}' is not a directory.";
            return null;
        }

        failure = SafeDirectoryFailure.None;
        reason = string.Empty;
        return handle;
    }

    private static (SafeDirectoryFailure, string) Map(int error, string what) => error switch
    {
        N.ErrorFileNotFound or N.ErrorPathNotFound => (SafeDirectoryFailure.NotFound, $"'{what}' does not exist."),
        N.ErrorReparsePointEncountered => (SafeDirectoryFailure.Redirected, $"'{what}' is reached through a reparse point."),
        _ => (SafeDirectoryFailure.Error, $"Could not open '{what}' (Win32 error {error})."),
    };

    [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "GetDriveTypeW",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetDriveType(string root);
}
