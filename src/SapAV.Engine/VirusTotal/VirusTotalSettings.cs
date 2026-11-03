using System.Text.Json;
using SapAV.Core.VirusTotal;

namespace SapAV.Engine.VirusTotal;

/// <summary>
/// The user's VirusTotal switch, <c>vt-settings.json</c> in the protected VirusTotal folder (off until an administrator turns it
/// on over the pipe, ROADMAP feature 3). A missing, unreadable or malformed file is "off": the lookup never turns itself on.
/// </summary>
internal static class VirusTotalSettings
{
    public const string FileName = "vt-settings.json";
    private const int MaxBytes = 4096;

    private sealed record Stored(bool Enabled);

    public static bool LoadEnabled(string folder, out string? problem)
    {
        problem = null;
        string path = Path.Combine(folder, FileName);
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return false;
            }

            if (info.Length > MaxBytes)
            {
                problem = "The VirusTotal settings file is too large; VirusTotal stays off.";
                return false;
            }

            return JsonSerializer.Deserialize<Stored>(File.ReadAllBytes(path))?.Enabled ?? false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            problem = $"The VirusTotal settings could not be read ({ex.GetType().Name}); VirusTotal stays off.";
            return false;
        }
    }

    /// <exception cref="IOException">The file couldn't be written.</exception>
    /// <exception cref="UnauthorizedAccessException">The file couldn't be written.</exception>
    public static void SaveEnabled(string folder, bool enabled)
    {
        string path = Path.Combine(folder, FileName);
        string temp = path + ".tmp";
        File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(new Stored(enabled)));
        File.Move(temp, path, overwrite: true);
    }
}

/// <summary>
/// The key the engine uses: the stored key (<see cref="VirusTotalKeyStore"/>), or, only in a console run, the development
/// environment variable (D3 decision: never under the service or as SYSTEM, <see cref="EngineAccount.AllowsDevelopmentKey"/>).
/// </summary>
internal sealed class EngineKeySource(VirusTotalKeyStore store, bool allowEnvironment) : IVirusTotalKeySource
{
    public VirusTotalKeyStore Store { get; } = store;

    public VirusTotalApiKey? GetKey() => Store.GetKey() ?? EnvironmentKey();

    /// <summary>True when the key in use is the environment one.</summary>
    public bool FromEnvironment => Store.GetKey() is null && EnvironmentKey() is not null;

    private VirusTotalApiKey? EnvironmentKey() => allowEnvironment ? VirusTotalApiKey.FromEnvironment() : null;
}
