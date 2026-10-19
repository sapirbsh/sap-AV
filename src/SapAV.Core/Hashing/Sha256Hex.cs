using System.Diagnostics.CodeAnalysis;

namespace SapAV.Core.Hashing;

/// <summary>Format helpers for SHA-256 hex strings (64 ASCII hex characters, stored lowercase).</summary>
public static class Sha256Hex
{
    /// <summary>Length of a SHA-256 hash in hex characters.</summary>
    public const int Length = 64;

    /// <summary>True if <paramref name="value"/> is exactly 64 ASCII hex characters (any case, no whitespace).</summary>
    public static bool IsValid([NotNullWhen(true)] string? value) =>
        value is { Length: Length } && value.AsSpan().ContainsAnyExcept(HexChars) is false;

    /// <summary>True if <paramref name="value"/> is exactly 64 ASCII hex characters (any case, no whitespace).</summary>
    public static bool IsValid(ReadOnlySpan<char> value) =>
        value.Length == Length && !value.ContainsAnyExcept(HexChars);

    /// <summary>
    /// Validates <paramref name="value"/> on the span and only then allocates the lowercase string.
    /// Does not trim. Never throws.
    /// </summary>
    public static bool TryNormalize(ReadOnlySpan<char> value, [NotNullWhen(true)] out string? normalized)
    {
        if (!IsValid(value))
        {
            normalized = null;
            return false;
        }

        normalized = string.Create(Length, value, static (dest, src) => src.ToLowerInvariant(dest));
        return true;
    }

    /// <summary>
    /// Validates <paramref name="value"/> and returns it in lowercase. Does not trim. Never throws.
    /// </summary>
    public static bool TryNormalize(string? value, [NotNullWhen(true)] out string? normalized)
    {
        if (!IsValid(value))
        {
            normalized = null;
            return false;
        }

        normalized = value.AsSpan().ContainsAnyInRange('A', 'F') ? value.ToLowerInvariant() : value;
        return true;
    }

    private static readonly System.Buffers.SearchValues<char> HexChars =
        System.Buffers.SearchValues.Create("0123456789abcdefABCDEF");
}
