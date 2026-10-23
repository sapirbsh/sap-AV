using System.Runtime.InteropServices;
using System.Security.Principal;
using SapAV.Engine.Sandbox.Native;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// The scan worker's AppContainer profile (default name <c>sap-AV.ScanWorker</c>), created with <b>no capabilities</b>:
/// no network (internetClient, privateNetworkClientServer, ...), no library or device access. Its SID is derived from
/// the name, so it is the same every run.
/// </summary>
internal static class AppContainerProfile
{
    public const string DefaultName = "sap-AV.ScanWorker";

    /// <summary>Creates the profile if needed and returns its AppContainer SID (<c>S-1-15-2-...</c>).</summary>
    /// <exception cref="SandboxUnavailableException">The profile can't be created or derived.</exception>
    public static SecurityIdentifier Ensure(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        int hr = SandboxNative.CreateAppContainerProfile(name, name, "sap-AV sandboxed scan worker (no capabilities)", IntPtr.Zero, 0, out IntPtr sid);
        if (hr == SandboxNative.HResultAlreadyExists)
        {
            hr = SandboxNative.DeriveAppContainerSidFromAppContainerName(name, out sid);
        }

        if (hr < 0)
        {
            throw new SandboxUnavailableException($"Could not create or derive the AppContainer profile '{name}' (HRESULT 0x{hr:X8}).");
        }

        try
        {
            return new SecurityIdentifier(sid);
        }
        finally
        {
            SandboxNative.FreeSid(sid);
        }
    }

    /// <summary>Deletes the profile (tests clean up their throwaway profiles). False if it didn't exist.</summary>
    public static bool Delete(string name)
    {
        int hr = SandboxNative.DeleteAppContainerProfile(name);
        if (hr < 0 && hr != SandboxNative.HResultFileNotFound)
        {
            throw new SandboxUnavailableException($"Could not delete the AppContainer profile '{name}' (HRESULT 0x{hr:X8}).");
        }

        return hr >= 0;
    }

    /// <summary>The SID the profile would have, without creating it.</summary>
    public static SecurityIdentifier Derive(string name)
    {
        int hr = SandboxNative.DeriveAppContainerSidFromAppContainerName(name, out IntPtr sid);
        if (hr < 0)
        {
            throw new SandboxUnavailableException($"Could not derive the AppContainer SID for '{name}' (HRESULT 0x{hr:X8}).");
        }

        try
        {
            return new SecurityIdentifier(sid);
        }
        finally
        {
            SandboxNative.FreeSid(sid);
        }
    }

    /// <summary>Native copy of <paramref name="sid"/> for SECURITY_CAPABILITIES; free with <see cref="Marshal.FreeHGlobal"/>.</summary>
    public static IntPtr ToNative(SecurityIdentifier sid)
    {
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        var p = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, p, bytes.Length);
        return p;
    }
}

/// <summary>The sandbox can't be set up on this machine (no AppContainer support, a missing worker, a failed ACL grant).</summary>
public sealed class SandboxUnavailableException : Exception
{
    public SandboxUnavailableException(string message)
        : base(message)
    {
    }

    public SandboxUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
