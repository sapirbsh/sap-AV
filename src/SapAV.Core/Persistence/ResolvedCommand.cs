using System.Text.Json.Serialization;
using SapAV.Core.Text;

namespace SapAV.Core.Persistence;

/// <summary>
/// What a persistence command line runs (ROADMAP C2): the target file, or no target and why. Nothing here was opened or
/// executed; C3 / C4 scan <see cref="TargetPath"/> (and <see cref="HostPath"/>) through the hardened scan open.
/// </summary>
/// <remarks>
/// Exactly one of <see cref="TargetPath"/> and <see cref="UnresolvedReason"/> is set. Paths are normalized, fully
/// qualified local drive paths (<c>C:\…</c>, or <c>\\?\C:\…</c> when a name needs it); a network path is never a target.
/// Immutable (no <c>with</c>): every value is checked together in the constructor, also from JSON, so an invalid
/// combination throws <see cref="ArgumentException"/> (or a subclass) whatever the property order.
/// </remarks>
public sealed record ResolvedCommand
{
    /// <summary>Longest <see cref="Arguments"/> kept (longer ones are cut and end with an ellipsis).</summary>
    public const int MaxArgumentsLength = 8192;

    /// <summary>Most <see cref="Additional"/> commands kept.</summary>
    public const int MaxAdditional = 16;

    [JsonConstructor]
    public ResolvedCommand(
        string? targetPath, TargetUnresolvedReason? unresolvedReason, string? hostPath, string? arguments, IReadOnlyList<ResolutionFlag>? flags,
        IReadOnlyList<ResolvedCommand>? additional = null)
    {
        if ((targetPath is null) == (unresolvedReason is null))
        {
            throw new ArgumentException("Exactly one of the target path and the unresolved reason must be set.", nameof(targetPath));
        }

        if (targetPath is not null && !PersistenceText.IsNormalizedLocalPath(targetPath))
        {
            throw new ArgumentException("The target path must be a normalized, fully qualified local path.", nameof(targetPath));
        }

        if (unresolvedReason is { } reason && !Enum.IsDefined(reason))
        {
            throw new ArgumentOutOfRangeException(nameof(unresolvedReason), reason, "Undefined unresolved reason.");
        }

        if (hostPath is not null && !PersistenceText.IsNormalizedLocalPath(hostPath))
        {
            throw new ArgumentException("The host path must be a normalized, fully qualified local path.", nameof(hostPath));
        }

        var list = (flags ?? []).ToArray();
        if (list.Any(f => !Enum.IsDefined(f)))
        {
            throw new ArgumentOutOfRangeException(nameof(flags), "Undefined resolution flag.");
        }

        var others = (additional ?? []).ToArray();
        if (others.Length > MaxAdditional || others.Any(a => a is null || a.Additional.Count > 0))
        {
            throw new ArgumentException($"At most {MaxAdditional} additional commands, and they must be flat.", nameof(additional));
        }

        TargetPath = targetPath;
        UnresolvedReason = unresolvedReason;
        HostPath = hostPath;
        Arguments = SafeText.SingleLine(arguments ?? string.Empty, MaxArgumentsLength);
        Flags = Array.AsReadOnly(list.Distinct().Order().ToArray());
        Additional = Array.AsReadOnly(others);
    }

    /// <summary>A command that runs <paramref name="targetPath"/>.</summary>
    public static ResolvedCommand Resolved(
        string targetPath, string arguments = "", string? hostPath = null, IEnumerable<ResolutionFlag>? flags = null) =>
        new(targetPath, null, hostPath, arguments, flags?.ToArray());

    /// <summary>A command without a target file.</summary>
    public static ResolvedCommand Unresolved(
        TargetUnresolvedReason reason, string? hostPath = null, string arguments = "", IEnumerable<ResolutionFlag>? flags = null) =>
        new(null, reason, hostPath, arguments, flags?.ToArray());

    /// <summary>The file that carries the payload (the program, or the DLL / script a host runs); null when unresolved.</summary>
    public string? TargetPath { get; }

    /// <summary>Why there is no <see cref="TargetPath"/>; null when resolved.</summary>
    public TargetUnresolvedReason? UnresolvedReason { get; }

    /// <summary>The system host that runs the target (rundll32, cmd, powershell, ...), when one was unwrapped.</summary>
    public string? HostPath { get; }

    /// <summary>The arguments after the target (one sanitized line, capped; may be empty).</summary>
    public string Arguments { get; }

    /// <summary>
    /// What else this entry runs (section C review H4): the other commands of a <c>&amp;</c> / <c>&amp;&amp;</c> / <c>||</c> chain, or the
    /// other targets a mismatched shortcut names. Each is resolved on its own and flat. C3 scans and judges them all.
    /// </summary>
    public IReadOnlyList<ResolvedCommand> Additional { get; }

    /// <summary>Distinct flags in enum order (may be empty).</summary>
    public IReadOnlyList<ResolutionFlag> Flags { get; }

    [JsonIgnore]
    public bool IsResolved => TargetPath is not null;

    public bool HasFlag(ResolutionFlag flag) => Flags.Contains(flag);

    /// <summary>A copy with <paramref name="added"/> flags.</summary>
    public ResolvedCommand WithFlags(params ResolutionFlag[] added) =>
        new(TargetPath, UnresolvedReason, HostPath, Arguments, [.. Flags, .. added], Additional);

    /// <summary>A copy that also runs <paramref name="others"/> (flattened); past the cap, one entry that says the rest is unknown.</summary>
    public ResolvedCommand WithAdditional(IEnumerable<ResolvedCommand> others)
    {
        var flat = Additional.Concat(others.SelectMany(o => o.Additional.Prepend(new(o.TargetPath, o.UnresolvedReason, o.HostPath, o.Arguments, o.Flags)))).ToList();
        if (flat.Count > MaxAdditional)
        {
            flat = [.. flat.Take(MaxAdditional - 1), Unresolved(TargetUnresolvedReason.SearchLimitReached)];
        }

        return new(TargetPath, UnresolvedReason, HostPath, Arguments, Flags, flat);
    }

    /// <summary>Every target path this entry can run: <see cref="TargetPath"/>, then the additional ones.</summary>
    [JsonIgnore]
    public IEnumerable<ResolvedCommand> AllCommands => Additional.Prepend(this);

    public bool Equals(ResolvedCommand? other) =>
        other is not null
        && (ReferenceEquals(this, other)
            || (string.Equals(TargetPath, other.TargetPath, StringComparison.Ordinal)
                && UnresolvedReason == other.UnresolvedReason
                && string.Equals(HostPath, other.HostPath, StringComparison.Ordinal)
                && string.Equals(Arguments, other.Arguments, StringComparison.Ordinal)
                && Flags.SequenceEqual(other.Flags)
                && Additional.SequenceEqual(other.Additional)));

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(TargetPath, StringComparer.Ordinal);
        hash.Add(UnresolvedReason);
        hash.Add(HostPath, StringComparer.Ordinal);
        hash.Add(Arguments, StringComparer.Ordinal);
        foreach (var flag in Flags)
        {
            hash.Add(flag);
        }

        return hash.ToHashCode();
    }
}
