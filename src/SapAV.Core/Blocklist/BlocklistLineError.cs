namespace SapAV.Core.Blocklist;

/// <summary>A blocklist line that was skipped because it isn't a valid SHA-256.</summary>
/// <param name="LineNumber">1-based line number in the source.</param>
/// <param name="Reason">Why the line was rejected (does not echo the line's content).</param>
public sealed record BlocklistLineError(int LineNumber, string Reason);
