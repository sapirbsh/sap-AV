using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Quarantine.Native;

namespace SapAV.Engine.Quarantine;

/// <summary>Supplies the metadata HMAC key for a store. Faked in tests.</summary>
public interface IQuarantineKeyProvider
{
    /// <summary>The key (at least 32 bytes) for the store at <paramref name="storeRoot"/>, created on first use.</summary>
    /// <exception cref="QuarantineStoreException">The key can't be created, read or trusted.</exception>
    byte[] GetOrCreateKey(string storeRoot, QuarantineAccessPolicy policy);
}

/// <summary>
/// Keeps a random 32-byte HMAC key in <c>&lt;store&gt;\metadata.key</c>, protected with <b>machine-scope DPAPI</b>
/// (plus a fixed purpose string as entropy).
/// </summary>
/// <remarks>
/// Machine-scope DPAPI binds the key to this Windows installation (a copied store can't be re-signed elsewhere);
/// on the machine itself, the protection is the store ACL (SYSTEM + Administrators). The key file's owner must be
/// trusted (<see cref="QuarantineAccessPolicy.IsTrustedOwner"/>), so a key planted by someone else is refused.
/// </remarks>
public sealed class DpapiQuarantineKeyProvider : IQuarantineKeyProvider
{
    public const string KeyFileName = "metadata.key";
    private const int KeyBytes = 32;
    private const int MaxBlobBytes = 4096;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("sap-AV quarantine metadata HMAC key v1");

    /// <inheritdoc/>
    public byte[] GetOrCreateKey(string storeRoot, QuarantineAccessPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(storeRoot);
        ArgumentNullException.ThrowIfNull(policy);
        string path = Path.Combine(storeRoot, KeyFileName);
        try
        {
            return File.Exists(path) ? Load(path, policy) : Create(path, policy);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException
            or System.ComponentModel.Win32Exception)
        {
            throw new QuarantineStoreException($"The quarantine metadata key ({path}) can't be used: {ex.Message}", ex);
        }
    }

    private static byte[] Create(string path, QuarantineAccessPolicy policy)
    {
        var key = RandomNumberGenerator.GetBytes(KeyBytes);
        var blob = QuarantineNative.ProtectMachine(key, Entropy);
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(blob);
            stream.Flush(flushToDisk: true);
            return key;
        }
        catch (IOException) when (File.Exists(path))
        {
            return Load(path, policy); // created concurrently
        }
    }

    private static byte[] Load(string path, QuarantineAccessPolicy policy)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.None);
        EnsureTrustedOwner(stream.SafeFileHandle, policy, path);
        if (stream.Length is 0 or > MaxBlobBytes)
        {
            throw new QuarantineStoreException($"The quarantine metadata key ({path}) has an invalid size.");
        }

        var blob = new byte[stream.Length];
        stream.ReadExactly(blob);
        var key = QuarantineNative.UnprotectMachine(blob, Entropy);
        if (key.Length != KeyBytes)
        {
            throw new QuarantineStoreException($"The quarantine metadata key ({path}) has an invalid length.");
        }

        return key;
    }

    private static void EnsureTrustedOwner(SafeFileHandle handle, QuarantineAccessPolicy policy, string path)
    {
        var sd = QuarantineNative.TryGetSecurity(handle, QuarantineNative.OwnerSecurityInformation, out int error)
            ?? throw new QuarantineStoreException($"Can't read the owner of {path} (Win32 error {error}).");
        var owner = new System.Security.AccessControl.RawSecurityDescriptor(sd, 0).Owner;
        if (!policy.IsTrustedOwner(owner))
        {
            throw new QuarantineStoreException(
                $"The quarantine metadata key ({path}) is owned by {owner?.Value ?? "nobody"}, not SYSTEM/Administrators; refusing it.");
        }
    }
}

/// <summary>The quarantine store can't be used (bad ACL, reparse point, untrusted key, ...).</summary>
public sealed class QuarantineStoreException(string message, Exception? inner = null) : Exception(message, inner);
