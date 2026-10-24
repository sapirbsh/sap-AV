using System.Text;

namespace SapAV.Core.Text;

/// <summary>
/// Makes untrusted text safe for the Event Log, SIEM collectors, the pipe and the UI (ROADMAP B1 / X2).
/// </summary>
/// <remarks>
/// <para>
/// Free text (<see cref="SingleLine"/>): detection reasons and signer names are built from file names, YARA rule
/// names and certificate fields, so they can carry line breaks (log injection: a fake second log line in a
/// plain-text SIEM view), bidi overrides (visual spoofing in Event Viewer) or unpaired surrogates (which
/// System.Text.Json can't encode faithfully). Line breaks, other control characters and any other whitespace
/// (tabs, no-break spaces) become a plain space; bidi
/// controls and unpaired surrogates become U+FFFD, so the reader can see something was there; the result is
/// trimmed and capped.
/// </para>
/// <para>
/// Identifiers (<see cref="Identifier"/>), e.g. a file path: these must stay recognisable, so nothing is
/// removed and nothing is cut. Only characters that can't be logged on one line or encoded (controls,
/// U+2028/U+2029, unpaired surrogates) become U+FFFD. Bidi controls are kept as evidence: the JSON writer
/// escapes them as <c>\u202E</c>, so they can't reorder the text in a viewer.
/// </para>
/// Both functions are idempotent: sanitising an already sanitised value returns it unchanged.
/// </remarks>
public static class SafeText
{
    /// <summary>Appended when text is cut, inside the length cap.</summary>
    public const char Ellipsis = '\u2026';

    private const char Replacement = '\uFFFD';

    /// <summary>
    /// One trimmed line of at most <paramref name="maxLength"/> characters (see the remarks on the class).
    /// May return an empty string (e.g. for input that is only whitespace and controls).
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength"/> is less than 2.</exception>
    public static string SingleLine(string value, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLength, 2);

        var sb = new StringBuilder(Math.Min(value.Length, maxLength + 1));
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                sb.Append(c).Append(value[++i]);
            }
            else if (IsLineBreakOrControl(c) || char.IsWhiteSpace(c))
            {
                if (sb.Length > 0)
                {
                    sb.Append(' '); // leading whitespace is dropped here, so the early stop below can't leave only blanks
                }
            }
            else if (IsBidiControl(c) || char.IsSurrogate(c))
            {
                sb.Append(Replacement);
            }
            else
            {
                sb.Append(c);
            }

            if (sb.Length > maxLength * 2)
            {
                break; // enough to trim and cap; don't copy megabytes
            }
        }

        return Cap(sb.ToString().Trim(), maxLength);
    }

    /// <summary>
    /// The identifier with controls, U+2028/U+2029 and unpaired surrogates replaced by U+FFFD. Never cut.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    public static string Identifier(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!NeedsIdentifierFix(value))
        {
            return value;
        }

        var chars = value.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (char.IsHighSurrogate(c) && i + 1 < chars.Length && char.IsLowSurrogate(chars[i + 1]))
            {
                i++;
            }
            else if (IsLineBreakOrControl(c) || char.IsSurrogate(c))
            {
                chars[i] = Replacement;
            }
        }

        return new string(chars);
    }

    /// <summary>
    /// Free text for a display (the pipe to the GUI, ROADMAP B4 / review B1 L8): <see cref="SingleLine"/>, plus every
    /// invisible format character (<see cref="IsInvisibleFormat"/>) mapped to U+FFFD, so a zero-width or tag character
    /// can't hide or forge part of a reason. Idempotent.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength"/> is less than 2.</exception>
    public static string Display(string value, int maxLength) => MapInvisibleFormat(SingleLine(value, maxLength));

    /// <summary>
    /// <paramref name="value"/> with every invisible format character (<see cref="IsInvisibleFormat"/>) replaced by U+FFFD
    /// (a tag character, a surrogate pair, becomes one U+FFFD). Nothing else changes; never cut.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    public static string MapInvisibleFormat(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!ContainsInvisibleFormat(value))
        {
            return value;
        }

        var sb = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                int codePoint = char.ConvertToUtf32(c, value[i + 1]);
                if (IsInvisibleFormat(codePoint))
                {
                    sb.Append(Replacement);
                }
                else
                {
                    sb.Append(c).Append(value[i + 1]);
                }

                i++;
            }
            else
            {
                sb.Append(IsInvisibleFormat(c) ? Replacement : c);
            }
        }

        return sb.ToString();
    }

    /// <summary>True if the text has a bidi control or an invisible format character (a UI should isolate or escape it).</summary>
    public static bool ContainsHiddenCharacters(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return ContainsInvisibleFormat(value) || value.Any(IsBidiControl);
    }

    /// <summary>
    /// Invisible format characters that render as nothing: U+00AD (soft hyphen), U+180E, U+200B (zero-width space),
    /// U+2060-2064 (word joiner, invisible operators), U+FEFF (BOM / ZWNBSP), U+FFF9-FFFB (interlinear annotation) and the
    /// tag characters U+E0000-E007F. ZWJ / ZWNJ (U+200C/D) are kept: emoji and several scripts need them.
    /// </summary>
    public static bool IsInvisibleFormat(int codePoint) =>
        codePoint is 0x00AD or 0x180E or 0x200B or (>= 0x2060 and <= 0x2064) or 0xFEFF or (>= 0xFFF9 and <= 0xFFFB)
            or (>= 0xE0000 and <= 0xE007F);

    private static bool ContainsInvisibleFormat(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                if (IsInvisibleFormat(char.ConvertToUtf32(c, value[++i])))
                {
                    return true;
                }
            }
            else if (IsInvisibleFormat(c))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>C0/C1 controls (incl. CR, LF, TAB, NEL) and the Unicode line / paragraph separators.</summary>
    public static bool IsLineBreakOrControl(char c) => char.IsControl(c) || c is '\u2028' or '\u2029';

    /// <summary>Bidi marks, embeddings, overrides and isolates (U+200E/F, U+202A-202E, U+2066-2069, U+061C).</summary>
    public static bool IsBidiControl(char c) =>
        c is '\u200E' or '\u200F' or '\u061C' or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069');

    private static bool NeedsIdentifierFix(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                i++;
            }
            else if (IsLineBreakOrControl(c) || char.IsSurrogate(c))
            {
                return true;
            }
        }

        return false;
    }

    private static string Cap(string value, int maxLength)
    {
        if (value.Length <= maxLength)
        {
            return value;
        }

        int cut = maxLength - 1;
        if (char.IsLowSurrogate(value[cut]) && char.IsHighSurrogate(value[cut - 1]))
        {
            cut--; // don't split a surrogate pair
        }

        return string.Concat(value.AsSpan(0, cut).TrimEnd(), Ellipsis.ToString());
    }
}
