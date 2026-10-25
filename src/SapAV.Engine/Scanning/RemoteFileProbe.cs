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
/// </remarks>
internal sealed unsafe class RemoteFileProbe : IRemoteFileProbe
{
    private const int FileRemoteProtocolInfoClass = 13;
    private const int ErrorInvalidFunction = 1;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;

    /// <summary>sizeof(FILE_REMOTE_PROTOCOL_INFO).</summary>
    private const int InfoSize = 116;

    public static RemoteFileProbe Instance { get; } = new();

    public FileLocation Classify(SafeHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        byte* buffer = stackalloc byte[InfoSize];
        bool ok = GetFileInformationByHandleEx(handle, FileRemoteProtocolInfoClass, buffer, InfoSize);
        return Classify(ok, ok ? 0 : Marshal.GetLastPInvokeError());
    }

    /// <summary>The classification of one query outcome (pure; tested directly).</summary>
    internal static FileLocation Classify(bool succeeded, int win32Error) =>
        succeeded ? FileLocation.Remote
        : win32Error is ErrorInvalidParameter or ErrorInvalidFunction or ErrorNotSupported ? FileLocation.Local
        : FileLocation.Unknown;

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeHandle file, int fileInformationClass, void* info, uint bufferSize);
}
