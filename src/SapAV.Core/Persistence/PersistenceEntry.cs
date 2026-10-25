using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SapAV.Core.Text;

namespace SapAV.Core.Persistence;

/// <summary>
/// One autostart entry found by a persistence collector (ROADMAP C2): where it is, what it says, and what it runs.
/// The contract between the collectors (C2), the judgement (C3), Quick / Full Scan (C4 / C6), real-time monitoring (D4)
/// and Block &amp; remove (D5).
/// </summary>
/// <remarks>
/// <para>
/// Immutable and validated as a whole in the constructor (also from JSON, any property order): an invalid value throws
/// <see cref="ArgumentException"/> (or a subclass). In JSON, <c>Kind</c> and <c>Enabled</c> are required and enums are
/// exact names (<see cref="System.Text.Json.JsonException"/> otherwise), like the A1 models. <c>TechniqueId</c> is
/// written for readers but derived from <see cref="Kind"/>, never read back.
/// </para>
/// <para>
/// Text from the entry is untrusted (anyone who can write the key / folder chose it): <see cref="Location"/> and
/// <see cref="ValueName"/> keep their characters but controls become U+FFFD and they are capped; <see cref="CommandLine"/>
/// is one sanitized line (<see cref="SafeText.SingleLine"/>), capped at <see cref="MaxCommandLineLength"/> (a cut sets
/// <see cref="ResolutionFlag.CommandLineTruncated"/>). The resolution was computed from the raw value, before sanitizing.
/// </para>
/// <para>
/// For C3 / C4: scan <see cref="ResolvedCommand.TargetPath"/> and, when set, <see cref="ResolvedCommand.HostPath"/>,
/// through the hardened scan open (SafeScanOpen). The collector never opened either of them.
/// </para>
/// </remarks>
public sealed partial record PersistenceEntry
{
    public const int MaxLocationLength = 2048;
    public const int MaxValueNameLength = 1024;
    public const int MaxCommandLineLength = 8192;

    [JsonConstructor]
    public PersistenceEntry(
        PersistenceKind kind,
        string? userSid,
        string location,
        string? valueName,
        string commandLine,
        ResolvedCommand resolution,
        bool enabled,
        ServiceStartType? serviceStart = null,
        Guid? comClassId = null)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Undefined persistence kind.");
        }

        if (userSid is not null && !IsSid(userSid))
        {
            throw new ArgumentException("The user scope must be a SID (S-1-...).", nameof(userSid));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(location);
        ArgumentNullException.ThrowIfNull(commandLine);
        ArgumentNullException.ThrowIfNull(resolution);
        if (serviceStart is { } start && (kind != PersistenceKind.Service || !Enum.IsDefined(start)))
        {
            throw new ArgumentException("A service start type must be a defined value on a Service entry.", nameof(serviceStart));
        }

        if (comClassId is not null && kind != PersistenceKind.ScheduledTask)
        {
            throw new ArgumentException("A COM class ID belongs to a ScheduledTask entry.", nameof(comClassId));
        }

        Kind = kind;
        UserSid = userSid;
        Location = PersistenceText.Identifier(location, MaxLocationLength);
        ValueName = valueName is null ? null : PersistenceText.Identifier(valueName, MaxValueNameLength);
        CommandLine = SafeText.SingleLine(commandLine, MaxCommandLineLength);
        Resolution = commandLine.Length > MaxCommandLineLength && !resolution.HasFlag(ResolutionFlag.CommandLineTruncated)
            ? resolution.WithFlags(ResolutionFlag.CommandLineTruncated)
            : resolution;
        Enabled = enabled;
        ServiceStart = serviceStart;
        ComClassId = comClassId;
    }

    [JsonRequired]
    [JsonInclude]
    public PersistenceKind Kind { get; private init; }

    /// <summary>The user whose hive / profile / environment the entry belongs to; null for a machine-wide entry.</summary>
    public string? UserSid { get; }

    /// <summary>
    /// The container: a registry key (<c>HKLM\...</c> or <c>HKU\&lt;SID&gt;\...</c>), a task path (<c>\Folder\Name</c>) or a
    /// Startup folder path.
    /// </summary>
    public string Location { get; }

    /// <summary>The value name (registry), file name (Startup folder) or action (task, e.g. <c>Exec[0]</c>); null when none.</summary>
    public string? ValueName { get; }

    /// <summary>The command as stored (a shortcut's or task's program and arguments joined), sanitized and capped.</summary>
    public string CommandLine { get; }

    public ResolvedCommand Resolution { get; }

    /// <summary>
    /// False when Windows won't run the entry as it stands (a Disabled service, a disabled task, a startup item turned off
    /// in Task Manager, a SilentProcessExit monitor without its GlobalFlag). Still reported: it can be switched back on.
    /// </summary>
    [JsonRequired]
    [JsonInclude]
    public bool Enabled { get; private init; }

    /// <summary>Service entries only: the <c>Start</c> value.</summary>
    public ServiceStartType? ServiceStart { get; }

    /// <summary>Scheduled-task COM handler actions only: the handler's CLSID.</summary>
    public Guid? ComClassId { get; }

    /// <summary>The primary MITRE technique of <see cref="Kind"/> (X1).</summary>
    public string TechniqueId => PersistenceKinds.TechniqueId(Kind);

    [JsonIgnore]
    public bool IsMachineScope => UserSid is null;

    /// <summary>A stable identity for baselines (D4) and undo (D5): kind, scope, location and value name (case-insensitive).</summary>
    [JsonIgnore]
    public string Key => string.Join('|', Kind, UserSid ?? "machine", Location.ToUpperInvariant(), ValueName?.ToUpperInvariant() ?? string.Empty);

    /// <summary>True for a SID string (<c>S-1-&lt;authority&gt;-&lt;sub&gt;...</c>, at most 15 sub-authorities).</summary>
    public static bool IsSid(string? value) => value is not null && SidRegex().IsMatch(value);

    [GeneratedRegex(@"\AS-1-[0-9]{1,13}(-[0-9]{1,10}){1,15}\z", RegexOptions.CultureInvariant)]
    private static partial Regex SidRegex();
}
