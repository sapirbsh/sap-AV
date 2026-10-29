using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Scanning;

/// <summary>Where an open file or folder lives, as far as the handle can tell.</summary>
internal enum FileLocation
{
    Local,

    /// <summary>On a remote file system (SMB / the network redirector).</summary>
    Remote,

    /// <summary>The query failed in an unexpected way: treated like Remote (fails closed).</summary>
    Unknown,
}

/// <summary>Classifies open handles as local or remote (ROADMAP A2 W-A). Fake it in tests (no SMB share needed).</summary>
internal interface IRemoteFileProbe
{
    FileLocation Classify(SafeHandle handle);
}

/// <summary>
/// ROADMAP A2 W-A / B3 M1: after a file or folder is opened for scanning, <c>GetFileInformationByHandleEx(FileRemoteProtocolInfo)</c>
/// says whether it is on a remote file system. Only network redirectors implement that class: it succeeds for remote
/// objects, and local file systems fail it with ERROR_INVALID_PARAMETER (or ERROR_INVALID_FUNCTION / ERROR_NOT_SUPPORTED).
/// Any other failure is <see cref="FileLocation.Unknown"/>, and the engine refuses it like a remote file.
/// </summary>
/// <remarks>
/// <b>This check can't prevent SMB authentication.</b> When it runs, the open has already happened, so if the object
/// was remote, SYSTEM has already authenticated to that server (machine-account NTLM, with a relay risk on domain-joined
/// machines). What prevents that is the open itself: <see cref="SafeTree"/> never follows a reparse point
/// (OBJ_DONT_REPARSE, name surrogates refused), refuses UNC paths and network drive letters, and opens files relative to
/// verified local folder handles, so a link can't send the engine to a server. This probe is defense in depth: whatever
/// slips past the open is never <i>scanned or reported</i> as a local file, unless the job explicitly allows remote files
/// (an administrator-only option, off by default). Deployment: also restrict outgoing NTLM and require SMB signing.
/// <para>Review C1 L4: the "local" error codes (87 / 1 / 50) are verified on NTFS only. Any other answer is logged <b>once per
/// volume</b> with its error code (<see cref="Logger"/>), so a local file system that answers differently (ReFS / Dev Drive,
/// FAT, exFAT, UDF) shows up as one clear log line instead of a silent coverage gap.</para>
/// </remarks>
internal sealed unsafe class RemoteFileProbe : IRemoteFileProbe
{
    private const int FileRemoteProtocolInfoClass = 13;
    private const int ErrorInvalidFunction = 1;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;

    /// <summary>sizeof(FILE_REMOTE_PROTOCOL_INFO).</summary>
    private const int InfoSize = 116;

    private readonly Func<SafeHandle, (bool Succeeded, int Error)> _query;
    private readonly Func<SafeHandle, ulong?> _volumeOf;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<ulong, int> _unknown = new();

    /// <param name="query">Test seam: the FileRemoteProtocolInfo query.</param>
    /// <param name="volumeOf">Test seam: the handle's volume serial.</param>
    internal RemoteFileProbe(Func<SafeHandle, (bool Succeeded, int Error)>? query = null, Func<SafeHandle, ulong?>? volumeOf = null)
    {
        _query = query ?? Query;
        _volumeOf = volumeOf ?? VolumeOf;
    }

    public static RemoteFileProbe Instance { get; } = new();

    /// <summary>Where Unknown answers are logged (the engine sets it at startup; null = not logged).</summary>
    internal ILogger? Logger { get; set; }

    /// <summary>Volumes that gave an unexpected answer, with the first error code (for the log and tests).</summary>
    internal IReadOnlyDictionary<ulong, int> UnknownVolumes => _unknown;

    public FileLocation Classify(SafeHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var (ok, error) = _query(handle);
        var location = Classify(ok, error);
        if (location == FileLocation.Unknown)
        {
            ulong volume = _volumeOf(handle) ?? 0;
            if (_unknown.TryAdd(volume, error))
            {
                Logger?.LogWarning("The remote-file check gave an unexpected answer (Win32 error {Error}) on volume {Volume:x16}; files there are " +
                    "treated as remote and not scanned. If this is a local file system (ReFS, FAT, exFAT, UDF), the check needs this code.",
                    error, volume);
            }
        }

        return location;
    }

    private static (bool Succeeded, int Error) Query(SafeHandle handle)
    {
        byte* buffer = stackalloc byte[InfoSize];
        bool ok = GetFileInformationByHandleEx(handle, FileRemoteProtocolInfoClass, buffer, InfoSize);
        return (ok, ok ? 0 : Marshal.GetLastPInvokeError());
    }

    private static ulong? VolumeOf(SafeHandle handle) =>
        handle is Microsoft.Win32.SafeHandles.SafeFileHandle file && Core.Hashing.NativeFile.TryGetFileId(file, out ulong serial, out _) ? serial : null;

    /// <summary>The classification of one query outcome (pure; tested directly).</summary>
    internal static FileLocation Classify(bool succeeded, int win32Error) =>
        succeeded ? FileLocation.Remote
        : win32Error is ErrorInvalidParameter or ErrorInvalidFunction or ErrorNotSupported ? FileLocation.Local
        : FileLocation.Unknown;

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeHandle file, int fileInformationClass, void* info, uint bufferSize);
}
