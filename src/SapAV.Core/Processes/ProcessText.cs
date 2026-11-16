using SapAV.Core.Text;

namespace SapAV.Core.Processes;

/// <summary>
/// Sanitizes and caps the untrusted strings of a <see cref="ProcessEvent"/>. Command lines stay raw (nothing is removed, so
/// quoting and spacing remain evidence) except that control characters, line separators and unpaired surrogates become U+FFFD
/// (<see cref="SafeText.Identifier"/>), and trailing NULs from native buffers are dropped.
/// </summary>
/// <remarks>
/// A long command line keeps its first <see cref="CommandLineHeadChars"/> and last <see cref="CommandLineTailChars"/>
/// characters with an ellipsis between them, like the E5 exclusion lists: padding the middle can't push a miner's pool URL or
/// an encoded payload at the end out of view, and the <c>Truncated</c> flag is itself a signal. Windows allows up to 32,767
/// characters, so the cap also bounds the memory of a full event buffer.
/// </remarks>
public static class ProcessText
{
    /// <summary>At most this many characters of a command line are kept (head + ellipsis + tail).</summary>
    public const int MaxCommandLineChars = 8192;

    /// <summary>Characters kept from the end of a capped command line.</summary>
    public const int CommandLineTailChars = 2048;

    /// <summary>Characters kept from the start of a capped command line.</summary>
    public const int CommandLineHeadChars = MaxCommandLineChars - CommandLineTailChars - 1;

    /// <summary>Longest kept image path (the Win32 extended-path limit); longer values are cut.</summary>
    public const int MaxPathChars = 32767;

    /// <summary>The sanitized, capped command line and whether it was capped. Null in, null out.</summary>
    public static (string? Text, bool Truncated) CommandLine(string? raw)
    {
        if (raw is null)
        {
            return (null, false);
        }

        string text = SafeText.Identifier(raw.TrimEnd('\0'));
        if (text.Length <= MaxCommandLineChars)
        {
            return (text, false);
        }

        int headEnd = CommandLineHeadChars;
        if (char.IsHighSurrogate(text[headEnd - 1]))
        {
            headEnd--; // don't split a surrogate pair
        }

        int tailStart = text.Length - CommandLineTailChars;
        if (char.IsLowSurrogate(text[tailStart]))
        {
            tailStart++;
        }

        return (string.Concat(text.AsSpan(0, headEnd), SafeText.Ellipsis.ToString(), text.AsSpan(tailStart)), true);
    }

    /// <summary>A sanitized image path (null or empty in: null out). Never longer than <see cref="MaxPathChars"/>.</summary>
    public static string? ImagePath(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        string text = SafeText.Identifier(raw.TrimEnd('\0'));
        if (text.Length == 0)
        {
            return null;
        }

        return text.Length <= MaxPathChars ? text : text[..MaxPathChars];
    }

    /// <summary>A SID string if it has the shape S-1-…, otherwise null (it comes from a native buffer; never trusted as text).</summary>
    public static string? Sid(string? raw)
    {
        if (string.IsNullOrEmpty(raw) || raw.Length > 200 || !raw.StartsWith("S-1-", StringComparison.Ordinal))
        {
            return null;
        }

        foreach (char c in raw)
        {
            if (!(char.IsAsciiDigit(c) || c is '-' or 'S'))
            {
                return null;
            }
        }

        return raw;
    }
}
