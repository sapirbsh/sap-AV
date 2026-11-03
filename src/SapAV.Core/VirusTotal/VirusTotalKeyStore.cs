using System.ComponentModel;
using System.Text;

namespace SapAV.Core.VirusTotal;

/// <summary>Outcome of <see cref="VirusTotalKeyStore.Set"/>.</summary>
public enum SetKeyResult
{
    Saved,

    /// <summary>The value doesn't look like an API key (wrong length or characters); nothing was stored.</summary>
    InvalidFormat,

    /// <summary>The file couldn't be written; see <see cref="VirusTotalKeyStore.LastProblem"/>.</summary>
    Failed,
}

/// <summary>
/// The end user's VirusTotal API key (ROADMAP feature 3): <c>vt-apikey.bin</c> in the given folder, protected with machine-scope
/// DPAPI plus a purpose entropy. The engine runs as SYSTEM and keeps the folder ACL'd to SYSTEM + Administrators (D3); tests use temp
/// folders.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><see cref="HasKey"/> answers "key set / not set" without exposing the key (for the pipe status to the GUI).</item>
/// <item><see cref="GetKey"/> returns an opaque <see cref="VirusTotalApiKey"/> whose plaintext only SapAV.Core's client reads.</item>
/// <item>A corrupt, oversized, foreign (other machine / other entropy) or malformed blob counts as "no key", never an exception.</item>
/// <item>The decrypted key is kept in memory after the first read; <see cref="Set"/> and <see cref="Clear"/> update it.</item>
/// </list>
/// Thread-safe.
/// </remarks>
public sealed class VirusTotalKeyStore : IVirusTotalKeySource
{
    public const string FileName = "vt-apikey.bin";
    private const int MaxBlobBytes = 4096;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("sap-AV VirusTotal API key v1");

    private readonly string _path;
    private readonly Lock _lock = new();
    private bool _loaded;
    private VirusTotalApiKey? _key;
    private string? _lastProblem;

    public VirusTotalKeyStore(string folder)
    {
        ArgumentNullException.ThrowIfNull(folder);
        _path = Path.Combine(folder, FileName);
    }

    /// <summary>True if a usable key is stored. Doesn't reveal it.</summary>
    public bool HasKey => GetKey() is not null;

    /// <summary>The last problem (engine text, never key material), or null.</summary>
    public string? LastProblem => Volatile.Read(ref _lastProblem);

    /// <inheritdoc/>
    public VirusTotalApiKey? GetKey()
    {
        lock (_lock)
        {
            if (!_loaded)
            {
                _key = Load();
                _loaded = true;
            }

            return _key;
        }
    }

    /// <summary>Validates and stores <paramref name="value"/> (trimmed), replacing any previous key.</summary>
    public SetKeyResult Set(string? value)
    {
        var key = VirusTotalApiKey.TryCreate(value);
        if (key is null)
        {
            return SetKeyResult.InvalidFormat;
        }

        lock (_lock)
        {
            string temp = _path + ".tmp";
            try
            {
                File.WriteAllBytes(temp, MachineDpapi.Protect(Encoding.UTF8.GetBytes(key.Value), Entropy));
                File.Move(temp, _path, overwrite: true);
                _key = key;
                _loaded = true;
                Volatile.Write(ref _lastProblem, null);
                return SetKeyResult.Saved;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
            {
                TryDelete(temp);
                Volatile.Write(ref _lastProblem, $"The VirusTotal API key could not be saved ({ex.GetType().Name}).");
                return SetKeyResult.Failed;
            }
        }
    }

    /// <summary>Removes the stored key. Returns false if the file couldn't be deleted (see <see cref="LastProblem"/>).</summary>
    public bool Clear()
    {
        lock (_lock)
        {
            _key = null;
            _loaded = true;
            try
            {
                File.Delete(_path);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _loaded = false; // re-read next time: the file may still be there
                Volatile.Write(ref _lastProblem, $"The VirusTotal API key could not be removed ({ex.GetType().Name}).");
                return false;
            }
        }
    }

    private VirusTotalApiKey? Load()
    {
        try
        {
            var info = new FileInfo(_path);
            if (!info.Exists)
            {
                return null;
            }

            if (info.Length is 0 or > MaxBlobBytes)
            {
                Volatile.Write(ref _lastProblem, "The stored VirusTotal API key has an invalid size; treated as no key.");
                return null;
            }

            var plain = MachineDpapi.Unprotect(File.ReadAllBytes(_path), Entropy);
            try
            {
                var key = VirusTotalApiKey.TryCreate(Encoding.UTF8.GetString(plain));
                if (key is null)
                {
                    Volatile.Write(ref _lastProblem, "The stored VirusTotal API key is malformed; treated as no key.");
                }

                return key;
            }
            finally
            {
                Array.Clear(plain);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
        {
            Volatile.Write(ref _lastProblem, $"The stored VirusTotal API key could not be read ({ex.GetType().Name}); treated as no key.");
            return null;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
