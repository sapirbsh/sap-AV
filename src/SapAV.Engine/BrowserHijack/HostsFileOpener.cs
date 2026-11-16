using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.BrowserHijack;
using SapAV.Core.Hashing;
using SapAV.Engine.Scanning;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.BrowserHijack;

/// <summary>
/// The hosts file opened for the scan worker (E6): the read-only handle (owned here: dispose it) and the metadata read from that
/// handle. The engine never reads the content; the handle goes to the sandboxed worker (B5).
/// </summary>
internal sealed class HostsFileOpen : IDisposable
{
    private HostsFileOpen(HijackReadState state, string? detail, SafeFileHandle? handle, long? length, DateTimeOffset? lastWriteTime, string? ownerSid)
    {
        State = state;
        Detail = detail;
        Handle = handle;
        Length = length;
        LastWriteTime = lastWriteTime;
        OwnerSid = ownerSid;
    }

    public HijackReadState State { get; }

    public string? Detail { get; }

    /// <summary>The open file when <see cref="State"/> is Available; null otherwise.</summary>
    public SafeFileHandle? Handle { get; }

    public long? Length { get; }

    public DateTimeOffset? LastWriteTime { get; }

    public string? OwnerSid { get; }

    /// <summary>E6 review M4: the file's hard-link count from the same handle, or null.</summary>
    public uint? NumberOfLinks { get; init; }

    /// <summary>E6 review M4: true when the DACL lets a non-administrator write or delete the file; null when unknown.</summary>
    public bool? WritableByNonAdmins { get; init; }

    public static HostsFileOpen Failed(HijackReadState state, string? detail) => new(state, detail, null, null, null, null);

    public static HostsFileOpen Opened(
        SafeFileHandle handle, long length, DateTimeOffset lastWriteTime, string? ownerSid, uint? numberOfLinks = null, bool? writableByNonAdmins = null) =>
        new(HijackReadState.Available, null, handle ?? throw new ArgumentNullException(nameof(handle)), length, lastWriteTime, ownerSid)
        {
            NumberOfLinks = numberOfLinks,
            WritableByNonAdmins = writableByNonAdmins,
        };

    public void Dispose() => Handle?.Dispose();
}

/// <summary>Opens the hosts file (fake in tests). Read-only; never throws for I/O.</summary>
internal interface IHostsFileOpener
{
    HostsFileOpen Open(string path);
}

/// <summary>
/// The real <see cref="IHostsFileOpener"/>: the hardened open (<see cref="SafeTree"/>: component by component, no reparse point
/// followed, name surrogates and remote paths refused, no recall of a cloud file, never waiting on an oplock), read access only,
/// a regular disk file only (<see cref="SecureFile.Validate"/>). Owner and last-write time come from the same handle; the content
/// is read only by the scan worker the handle is brokered to.
/// </summary>
internal sealed class SafeHostsFileOpener(int lockedAttempts = 3, TimeSpan? lockedDelay = null) : IHostsFileOpener
{
    private const uint Options = N.FileNonDirectoryFile | SafeTree.OpenNoRecall | N.FileCompleteIfOplocked;

    /// <summary>Delete, plus the rights that modify a file (write / append data, WRITE_DAC, WRITE_OWNER, generic write / all).</summary>
    private const int WriteOrDeleteRights = Persistence.AclPathWritability.ModifyFileRights | 0x00010000 /* DELETE */;

    private readonly TimeSpan _lockedDelay = lockedDelay ?? TimeSpan.FromMilliseconds(100);

    public HostsFileOpen Open(string path)
    {
        SafeFileHandle? handle = null;
        SafeTreeFailure failure = SafeTreeFailure.None;
        int error = 0;
        // E6 review M2: a Locked open (sharing violation, or an oplock / lease that would have to be broken) is retried briefly.
        for (int attempt = 1; attempt <= Math.Max(1, lockedAttempts); attempt++)
        {
            handle = SafeTree.Open(path, N.GenericRead, SafeTree.ShareAll, Options, out failure, out error);
            if (handle is not null || failure != SafeTreeFailure.Locked || attempt == lockedAttempts)
            {
                break;
            }

            Thread.Sleep(_lockedDelay);
        }

        if (handle is null)
        {
            return HostsFileOpen.Failed(Map(failure), failure == SafeTreeFailure.Locked
                ? $"The hosts file is in use: an oplock or lease is held, or it is open without read sharing (Win32 error {error}, {lockedAttempts} attempts)."
                : $"The hosts file can't be opened ({failure}, Win32 error {error}).");
        }

        try
        {
            if (!SecureFile.Validate(handle, out var invalid, out _))
            {
                handle.Dispose();
                return HostsFileOpen.Failed(HijackReadState.Failed, Core.Text.SafeText.SingleLine(invalid.Message ?? "Not a regular file.", 256));
            }

            long length = RandomAccess.GetLength(handle);
            var lastWrite = new DateTimeOffset(File.GetLastWriteTimeUtc(handle), TimeSpan.Zero);
            var descriptor = Pipe.Native.PipeNative.TryReadFileSecurity(handle);
            bool? writable = descriptor is null ? null : new Persistence.AclPathWritability().Evaluate(descriptor, WriteOrDeleteRights) switch
            {
                Core.Persistence.Writability.UserWritable => true,
                Core.Persistence.Writability.AdminOnly => false,
                _ => null,
            };
            return HostsFileOpen.Opened(handle, length, lastWrite, Owner(descriptor), Links(handle), writable);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            handle.Dispose();
            return HostsFileOpen.Failed(ex is UnauthorizedAccessException ? HijackReadState.AccessDenied : HijackReadState.Failed,
                $"The hosts file's metadata can't be read ({ex.GetType().Name}).");
        }
    }

    private static uint? Links(SafeFileHandle handle)
    {
        try
        {
            return N.GetFileInformation(handle).NumberOfLinks;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static string? Owner(byte[]? descriptor)
    {
        if (descriptor is null)
        {
            return null;
        }

        try
        {
            return new RawSecurityDescriptor(descriptor, 0).Owner?.Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static HijackReadState Map(SafeTreeFailure failure) => failure switch
    {
        SafeTreeFailure.NotFound => HijackReadState.NotFound,
        SafeTreeFailure.AccessDenied => HijackReadState.AccessDenied,
        SafeTreeFailure.Redirected => HijackReadState.Redirected,
        SafeTreeFailure.Remote => HijackReadState.Remote,
        SafeTreeFailure.Locked => HijackReadState.Locked,
        _ => HijackReadState.Failed,
    };
}
