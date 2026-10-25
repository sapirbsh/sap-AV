using SapAV.Core.Hashing;

namespace SapAV.Core.Scanning;

/// <summary>Why <see cref="ScanPathPolicy"/> refused a path.</summary>
public enum ScanPathRejection
{
    None,

    /// <summary>Null, empty or only whitespace.</summary>
    Empty,

    /// <summary>Longer than <see cref="ScanPathPolicy.MaxPathLength"/>, or a name longer than <see cref="ScanPathPolicy.MaxComponentLength"/>.</summary>
    TooLong,

    /// <summary>NUL, another control character, or a character no file name may contain (<c>&lt; &gt; " | ? *</c>).</summary>
    InvalidCharacter,

    /// <summary>Relative, drive-relative (<c>C:x</c>) or rooted without a drive (<c>\x</c>).</summary>
    NotFullyQualified,

    /// <summary>A device or object-manager namespace path (<c>\\.\…</c>, <c>\\?\…</c> other than <c>\\?\X:\…</c>, <c>\??\…</c>).</summary>
    DeviceNamespace,

    /// <summary><c>\\?\GLOBALROOT</c> / <c>\\.\GLOBALROOT</c> (any object in the NT namespace).</summary>
    GlobalRoot,

    /// <summary>A UNC or other network path (SYSTEM must never authenticate to a remote server for a user).</summary>
    Network,

    /// <summary>An alternate data stream or another <c>:</c> after the drive.</summary>
    AlternateDataStream,

    /// <summary>A reserved device name as a path component (<c>CON</c>, <c>NUL</c>, <c>COM1</c>, <c>LPT1.txt</c>, …).</summary>
    ReservedDeviceName,

    /// <summary>A <c>.</c> or <c>..</c> component in a <c>\\?\</c> path, or another form <see cref="ExactPath"/> can't keep exactly.</summary>
    Malformed,
}

/// <summary>Result of <see cref="ScanPathPolicy.Evaluate"/>.</summary>
/// <param name="NormalizedPath">The exact, normalised path (only when allowed).</param>
public readonly record struct ScanPathDecision(string? NormalizedPath, ScanPathRejection Rejection, string Reason)
{
    public bool IsAllowed => Rejection == ScanPathRejection.None && NormalizedPath is not null;
}

/// <summary>
/// Which scan paths an untrusted caller (a user over the engine pipe, ROADMAP C1 / B4) may hand to the SYSTEM engine.
/// </summary>
/// <remarks>
/// <para>Only local drive-letter paths are accepted: <c>C:\…</c>, or the exact extended form <c>\\?\C:\…</c>. Everything
/// else is refused: device and object-manager namespaces (<c>\\.\</c>, <c>\\?\GLOBALROOT</c>, <c>\\?\Volume{…}</c>,
/// <c>\??\</c>), UNC and other network paths (so SYSTEM never authenticates to a remote server on a user's behalf),
/// NUL and other control characters, wildcard / invalid characters, alternate data streams and reserved device names
/// (<c>CON</c>, <c>NUL.txt</c>, <c>COM1</c>, …; refused in every form, since a plain path would open the device).</para>
/// <para><b>Exact normalisation</b> (<see cref="ExactPath"/>, never <see cref="Path.GetFullPath(string)"/>): only
/// <c>.</c>/<c>..</c> and repeated separators are resolved, lexically, the way Win32 resolves them, so <c>..</c> can't
/// bypass exclusions or cache keys; trailing dots and spaces are kept, so <c>evil.exe.</c> stays <c>evil.exe.</c> and is
/// never confused with <c>evil.exe</c>. The result is in the form that opens exactly that name: plain when lossless,
/// <c>\\?\</c> when a name ends in a dot or space (the same form the scan walker reports).</para>
/// <para>A string policy can't see what a drive letter or a link points to: the engine still checks the drive type and
/// the caller's access on the opened object, and never follows name-surrogate reparse points.</para>
/// </remarks>
public static class ScanPathPolicy
{
    /// <summary>The Win32 maximum path length (extended form).</summary>
    public const int MaxPathLength = 32_767;

    /// <summary>The NTFS maximum name length.</summary>
    public const int MaxComponentLength = 255;

    private const string ExtendedPrefix = @"\\?\";

    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM\u00B9", "COM\u00B2", "COM\u00B3",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT\u00B9", "LPT\u00B2", "LPT\u00B3",
    };

    /// <summary>Checks and normalises one path (see the class remarks). Never throws.</summary>
    public static ScanPathDecision Evaluate(string? path) => Evaluate(path, allowNetwork: false);

    /// <summary>
    /// Like <see cref="Evaluate(string?)"/>; with <paramref name="allowNetwork"/> (A2 W-A: an administrator explicitly asked
    /// to scan remote files) a UNC path <c>\\server\share\…</c> or <c>\\?\UNC\server\share\…</c> is also accepted, with the
    /// same character, stream, reserved-name and normalisation rules. Device namespaces stay refused either way.
    /// </summary>
    public static ScanPathDecision Evaluate(string? path, bool allowNetwork)
    {
        if (allowNetwork && IsUnc(path))
        {
            return EvaluateUnc(path!);
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            return Reject(ScanPathRejection.Empty, "The path is empty.");
        }

        if (path.Length > MaxPathLength)
        {
            return Reject(ScanPathRejection.TooLong, "The path is too long.");
        }

        if (FirstInvalidCharacter(path) is { } bad)
        {
            return Reject(ScanPathRejection.InvalidCharacter, $"The path contains an invalid character (U+{(int)bad:X4}).");
        }

        if (Classify(path) is { } namespaceRejection)
        {
            return namespaceRejection;
        }

        bool extended = path.StartsWith(ExtendedPrefix, StringComparison.Ordinal);
        if (extended && path.IndexOf('/', ExtendedPrefix.Length) >= 0)
        {
            return Reject(ScanPathRejection.InvalidCharacter, "A \\\\?\\ path can't contain '/'.");
        }

        int afterDrive = extended ? ExtendedPrefix.Length + 2 : 2;
        if (path.IndexOf(':', afterDrive) >= 0)
        {
            return Reject(ScanPathRejection.AlternateDataStream, "Alternate data streams and ':' in names are not allowed.");
        }

        if (ExactPath.ToExtended(path) is not { } exact)
        {
            return Reject(ScanPathRejection.Malformed, "The path can't be normalised exactly ('.' or '..' in a \\\\?\\ path?).");
        }

        if (exact.Length > MaxPathLength)
        {
            return Reject(ScanPathRejection.TooLong, "The path is too long.");
        }

        foreach (var component in exact[(ExtendedPrefix.Length + 3)..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (component.Length > MaxComponentLength)
            {
                return Reject(ScanPathRejection.TooLong, "A name in the path is longer than 255 characters.");
            }

            if (IsReservedDeviceName(component))
            {
                return Reject(ScanPathRejection.ReservedDeviceName, "The path contains a reserved device name.");
            }
        }

        return new ScanPathDecision(ExactPath.ForOpening(exact), ScanPathRejection.None, string.Empty);
    }

    /// <summary><c>\\server\…</c> (not <c>\\.\</c> or <c>\\?\</c>) or the literal <c>\\?\UNC\…</c>; backslashes only.</summary>
    private static bool IsUnc(string? path) =>
        path is { Length: > 2 } && path.StartsWith(@"\\", StringComparison.Ordinal)
        && (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) || path[2] is not ('.' or '?' or '\\' or '/'));

    private static ScanPathDecision EvaluateUnc(string path)
    {
        if (path.Length > MaxPathLength)
        {
            return Reject(ScanPathRejection.TooLong, "The path is too long.");
        }

        if (FirstInvalidCharacter(path) is { } bad)
        {
            return Reject(ScanPathRejection.InvalidCharacter, $"The path contains an invalid character (U+{(int)bad:X4}).");
        }

        if (path.Contains('/'))
        {
            return Reject(ScanPathRejection.InvalidCharacter, "A network path must use '\\' only.");
        }

        if (path.Contains(':'))
        {
            return Reject(ScanPathRejection.AlternateDataStream, "Alternate data streams and ':' in names are not allowed.");
        }

        if (ExactPath.ToExtended(path) is not { } exact || !exact.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
        {
            return Reject(ScanPathRejection.Malformed, "The network path needs a server and a share and can't be normalised exactly.");
        }

        var components = exact[@"\\?\UNC\".Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (components.Length < 2 || components[0] is "." or "?")
        {
            return Reject(ScanPathRejection.Malformed, "The network path needs a server and a share.");
        }

        foreach (var component in components)
        {
            if (component.Length > MaxComponentLength)
            {
                return Reject(ScanPathRejection.TooLong, "A name in the path is longer than 255 characters.");
            }

            if (IsReservedDeviceName(component))
            {
                return Reject(ScanPathRejection.ReservedDeviceName, "The path contains a reserved device name.");
            }
        }

        return new ScanPathDecision(ExactPath.ForOpening(exact), ScanPathRejection.None, string.Empty);
    }

    /// <summary>
    /// True if <paramref name="component"/> names a DOS device: the part before the first dot, with trailing spaces removed,
    /// is a reserved name (<c>nul</c>, <c>NUL.txt</c>, <c>con .log</c>, <c>COM¹</c>).
    /// </summary>
    public static bool IsReservedDeviceName(string component)
    {
        ArgumentNullException.ThrowIfNull(component);
        int dot = component.IndexOf('.');
        string stem = (dot >= 0 ? component[..dot] : component).TrimEnd(' ');
        return ReservedNames.Contains(stem);
    }

    /// <summary>The namespace check, on a copy with '/' read as '\' (Win32 treats <c>//?/</c> like <c>\\?\</c>).</summary>
    private static ScanPathDecision? Classify(string path)
    {
        string slashed = path.Replace('/', '\\');
        if (slashed.StartsWith(@"\\", StringComparison.Ordinal))
        {
            if (slashed.Length >= 4 && slashed[2] is '.' or '?' && slashed[3] == '\\')
            {
                string rest = slashed[4..];
                if (rest.StartsWith("GLOBALROOT", StringComparison.OrdinalIgnoreCase))
                {
                    return Reject(ScanPathRejection.GlobalRoot, "\\\\?\\GLOBALROOT paths are not allowed.");
                }

                if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return Reject(ScanPathRejection.Network, "Network paths are not allowed.");
                }

                // Only the literal \\?\X:\ form is a plain local file path.
                bool literalExtended = path.StartsWith(ExtendedPrefix, StringComparison.Ordinal);
                if (!literalExtended || !IsDriveRooted(rest))
                {
                    return Reject(ScanPathRejection.DeviceNamespace, "Device and namespace paths are not allowed.");
                }

                return null;
            }

            return Reject(ScanPathRejection.Network, "Network (UNC) paths are not allowed.");
        }

        if (slashed.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return Reject(ScanPathRejection.DeviceNamespace, "NT namespace paths are not allowed.");
        }

        return IsDriveRooted(slashed) ? null : Reject(ScanPathRejection.NotFullyQualified, "The path must start with a drive letter (C:\\...).");
    }

    private static bool IsDriveRooted(string text) =>
        text.Length >= 3 && char.IsAsciiLetter(text[0]) && text[1] == ':' && text[2] == '\\';

    private static char? FirstInvalidCharacter(string path)
    {
        for (int i = 0; i < path.Length; i++)
        {
            char c = path[i];
            if (char.IsControl(c) || c is '<' or '>' or '"' or '|' or '*')
            {
                return c;
            }

            // '?' is allowed only as the second/third character of a leading \\?\ (classified separately).
            if (c == '?' && !(i == 2 && path.Length > 3 && path[0] is '\\' or '/' && path[1] is '\\' or '/' && path[3] is '\\' or '/'))
            {
                return c;
            }
        }

        return null;
    }

    private static ScanPathDecision Reject(ScanPathRejection why, string reason) => new(null, why, reason);
}
