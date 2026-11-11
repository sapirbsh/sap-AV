using System.Text.RegularExpressions;

namespace SapAV.Engine.Defender;

/// <summary>How a WMI class read went.</summary>
public enum WmiReadStatus
{
    Ok,

    /// <summary>The namespace or class doesn't exist (e.g. Defender or Security Center isn't installed).</summary>
    NotFound,

    /// <summary>The class's provider answered that its backing service isn't running (Defender: <c>0x800106BA</c>).</summary>
    ServiceNotRunning,

    AccessDenied,

    /// <summary>WMI itself isn't reachable (Winmgmt stopped or disabled, RPC failure).</summary>
    Unavailable,

    TimedOut,

    Failed,
}

/// <summary>
/// A read-only query: every instance of one WMI class, keeping only <see cref="Properties"/>. A property this class doesn't
/// have (e.g. <c>ExclusionIpAddress</c> on an older Defender) is left out of the instance, which is different from a null value.
/// </summary>
public sealed partial record WmiClassQuery
{
    public WmiClassQuery(string namespacePath, string className, IReadOnlyCollection<string> properties, TimeSpan timeout)
    {
        if (!NamespacePattern().IsMatch(namespacePath ?? string.Empty))
        {
            throw new ArgumentException("The namespace must look like root\\Name\\Name (letters, digits, underscore).", nameof(namespacePath));
        }

        if (!IdentifierPattern().IsMatch(className ?? string.Empty))
        {
            throw new ArgumentException("The class name must be a WMI identifier.", nameof(className));
        }

        ArgumentNullException.ThrowIfNull(properties);
        if (properties.Count == 0 || properties.Any(p => !IdentifierPattern().IsMatch(p ?? string.Empty)))
        {
            throw new ArgumentException("Properties must be one or more WMI identifiers.", nameof(properties));
        }

        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        NamespacePath = namespacePath!;
        ClassName = className!;
        Properties = properties;
        Timeout = timeout;
    }

    public string NamespacePath { get; }

    public string ClassName { get; }

    public IReadOnlyCollection<string> Properties { get; }

    public TimeSpan Timeout { get; }

    [GeneratedRegex(@"\A[Rr][Oo][Oo][Tt](\\[A-Za-z0-9_]+)*\z")]
    private static partial Regex NamespacePattern();

    [GeneratedRegex(@"\A[A-Za-z_][A-Za-z0-9_]{0,127}\z")]
    private static partial Regex IdentifierPattern();
}

/// <summary>
/// The result of a <see cref="WmiClassQuery"/>. Instance values are plain CLR copies (string, bool, numbers, arrays of those),
/// never live WMI objects.
/// </summary>
public sealed record WmiReadResult
{
    private WmiReadResult(WmiReadStatus status, IReadOnlyList<IReadOnlyDictionary<string, object?>> instances, string? detail)
    {
        Status = status;
        Instances = instances;
        Detail = detail;
    }

    public WmiReadStatus Status { get; }

    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Instances { get; }

    public string? Detail { get; }

    public static WmiReadResult Ok(IReadOnlyList<IReadOnlyDictionary<string, object?>> instances) =>
        new(WmiReadStatus.Ok, instances ?? throw new ArgumentNullException(nameof(instances)), null);

    public static WmiReadResult Failure(WmiReadStatus status, string? detail)
    {
        if (status == WmiReadStatus.Ok)
        {
            throw new ArgumentException("A failure needs a non-Ok status.", nameof(status));
        }

        return new(status, [], detail);
    }
}

/// <summary>Reads WMI classes. Read-only by contract: no method calls, no writes. Faked in tests.</summary>
public interface IWmiReader
{
    /// <summary>
    /// Reads every instance of the class. Failures (missing class, access denied, hung WMI past <see cref="WmiClassQuery.Timeout"/>)
    /// are results, not exceptions; only cancellation of <paramref name="cancellationToken"/> throws.
    /// </summary>
    Task<WmiReadResult> ReadAsync(WmiClassQuery query, CancellationToken cancellationToken);
}
