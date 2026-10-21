using System.Reflection;

namespace SapAV.Engine;

/// <summary>Facts about the running engine, e.g. for <see cref="Core.Alerts.Alert.EngineVersion"/>.</summary>
public static class EngineInfo
{
    /// <summary>
    /// The engine's informational version (e.g. <c>1.0.0+3b681a8...</c>), reduced to the characters and length
    /// <see cref="Core.Alerts.Alert"/> accepts, so building an alert never fails because of it.
    /// </summary>
    public static string Version { get; } = Normalize(
        typeof(EngineInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    private static string Normalize(string? version)
    {
        var allowed = new string((version ?? string.Empty)
            .Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '+' or '_')
            .Take(Core.Alerts.Alert.MaxEngineVersionLength)
            .ToArray());
        return allowed.Length == 0 ? "0.0.0" : allowed;
    }
}
