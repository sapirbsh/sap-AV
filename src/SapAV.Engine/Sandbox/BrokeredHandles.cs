using System.Runtime.InteropServices;
using SapAV.Engine.Sandbox.Native;

namespace SapAV.Engine.Sandbox;

/// <summary>Whether a worker still holds a brokered file object after the broker closed its copies there.</summary>
internal enum BrokeredHandleState
{
    /// <summary>The broker's own handle is the only one left on every object.</summary>
    Released,

    /// <summary>Some other handle (a copy the worker made) still refers to one of the objects.</summary>
    StillHeld,

    /// <summary>The count couldn't be read: treat the worker as untrustworthy, but don't blame the file.</summary>
    Unknown,
}

/// <summary>
/// Review M-A: the exact check that no copy of a brokered handle survives a request. The broker opened each file
/// object itself and is the only legitimate holder, so after <see cref="WorkerProcess.CloseInWorker"/> the kernel's
/// system-wide HandleCount (<c>NtQueryObject(ObjectBasicInformation)</c>) on each must be exactly 1. Nothing the worker
/// does with its own handle table (closing a dummy handle, racing an enumeration) changes that number.
/// </summary>
/// <remarks>
/// Not covered: a section (file mapping) created from the brokered handle holds a pointer reference, not a handle,
/// so it isn't counted. The duplicated handle is read-only, so such a section can only expose content the worker was
/// given anyway; worker recycling (<see cref="SandboxOptions.MaxFilesPerWorker"/>, lifetime) bounds how long it lives.
/// </remarks>
internal static class BrokeredHandles
{
    public static BrokeredHandleState Check(params SafeHandle?[] handles)
    {
        foreach (var handle in handles)
        {
            if (handle is null)
            {
                continue;
            }

            if (SystemHandleCount(handle) is not { } count)
            {
                return BrokeredHandleState.Unknown;
            }

            if (count != 1)
            {
                return BrokeredHandleState.StillHeld;
            }
        }

        return BrokeredHandleState.Released;
    }

    /// <summary>The object's system-wide handle count, or null if it can't be read.</summary>
    public static unsafe uint? SystemHandleCount(SafeHandle handle)
    {
        if (handle.IsInvalid || handle.IsClosed)
        {
            return null;
        }

        SandboxNative.ObjectBasicInformation info;
        int status = SandboxNative.NtQueryObject(handle, 0 /* ObjectBasicInformation */, &info,
            (uint)sizeof(SandboxNative.ObjectBasicInformation), out _);
        return status >= 0 ? info.HandleCount : null;
    }
}
