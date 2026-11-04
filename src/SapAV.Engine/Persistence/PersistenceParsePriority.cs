using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Persistence;

/// <summary>
/// D4 review H5: the worker priority of the definition-file parses the current collection sends (async-local, so it flows
/// into the broker's async parse). Default High (the engine's own work); a collection of a user-writable location (a user's
/// part, System32\Tasks) asks for Normal, so a user flooding it can't push real-time file scans (High) back.
/// </summary>
internal static class PersistenceParsePriority
{
    private static readonly AsyncLocal<ScanPriority?> CurrentValue = new();

    public static ScanPriority Current => CurrentValue.Value ?? ScanPriority.High;

    /// <summary>Sets the priority until the returned scope is disposed (null keeps the current one).</summary>
    public static IDisposable Use(ScanPriority? priority)
    {
        var previous = CurrentValue.Value;
        if (priority is { } value)
        {
            CurrentValue.Value = value;
        }

        return new Restore(previous);
    }

    private sealed class Restore(ScanPriority? previous) : IDisposable
    {
        public void Dispose() => CurrentValue.Value = previous;
    }
}
