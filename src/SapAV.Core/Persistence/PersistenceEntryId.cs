using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SapAV.Core.Persistence;

/// <summary>
/// D5: the ID a client names an autostart entry by for Block &amp; remove (in alerts and scan findings):
/// <c>pe1-&lt;Kind&gt;-&lt;m|u&gt;-&lt;32 hex&gt;</c>. The hex part is a SHA-256 over what the entry <b>stores</b> (kind, scope,
/// location, value name, command line, enabled state, service start type, COM class), so an entry that changed in any of those
/// has another ID. The engine never acts on what an ID says: it re-collects the entry's scope and acts only on an entry whose
/// own ID equals the requested one (the TOCTOU guard). The kind and the m (machine) / u (user) letter only tell it which
/// scope to collect; the user's SID is deliberately not in the ID (it isn't shown to everyone who sees a finding).
/// </summary>
public static partial class PersistenceEntryId
{
    public const string Prefix = "pe1-";

    /// <summary>The ID of <paramref name="entry"/> as collected now.</summary>
    public static string Compute(PersistenceEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        string canonical = string.Join('\n',
            "sap-AV persistence entry v1",
            entry.Kind.ToString(),
            entry.UserSid ?? "machine",
            entry.Location,
            entry.ValueName ?? "\0",
            entry.CommandLine,
            entry.Enabled ? "1" : "0",
            entry.ServiceStart?.ToString() ?? string.Empty,
            entry.ComClassId?.ToString("B") ?? string.Empty);
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.UTF8.GetBytes(canonical), hash);
        return $"{Prefix}{entry.Kind}-{(entry.IsMachineScope ? 'm' : 'u')}-{Convert.ToHexStringLower(hash[..16])}";
    }

    /// <summary>Parses an ID's kind and scope letter; false for anything that isn't exactly an ID (format only, nothing trusted).</summary>
    public static bool TryParse(string? id, out PersistenceKind kind, out bool machineScope)
    {
        kind = default;
        machineScope = false;
        if (id is null || id.Length > 80 || IdRegex().Match(id) is not { Success: true } match
            || !Enum.TryParse(match.Groups["kind"].Value, ignoreCase: false, out kind) || !Enum.IsDefined(kind))
        {
            return false;
        }

        machineScope = match.Groups["scope"].Value == "m";
        return true;
    }

    [GeneratedRegex(@"\Ape1-(?<kind>[A-Za-z]{1,32})-(?<scope>[mu])-[0-9a-f]{32}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdRegex();
}
