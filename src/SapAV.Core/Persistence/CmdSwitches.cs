namespace SapAV.Core.Persistence;

/// <summary>
/// Reads <c>cmd.exe</c>'s own switches the way cmd does (section C follow-up review H-A): switches may be attached to each other
/// (<c>/d/q/c</c>), and <c>/c</c>, <c>/k</c> or <c>/r</c> may carry the command right after the letter (<c>/cC:\x.exe</c>). The
/// command starts at the first of them; there is no token limit, only <see cref="MaxSwitches"/>.
/// </summary>
/// <remarks>
/// Known switches: <c>/a /u /q /d /s /x /y</c>, <c>/e /f /v</c> (optionally <c>:on</c> / <c>:off</c>) and <c>/t:fg</c> (one or two
/// hex digits). Anything else before the command (a word, a quote, an unknown switch, a <c>-</c>) is <see cref="Kind.NotUnderstood"/>:
/// cmd's own reading of such text isn't something the engine can reproduce with certainty, so it is never taken as "an
/// interactive shell" (which would make the entry Microsoft-signed cmd.exe and nothing else).
/// </remarks>
internal readonly record struct CmdSwitches(CmdSwitches.Kind Outcome, int CommandStart)
{
    /// <summary>Most switches read before the command; more is <see cref="Kind.TooMany"/> (unknown, not "no command").</summary>
    public const int MaxSwitches = 64;

    public enum Kind
    {
        /// <summary>Only known switches (or none) and no <c>/c</c>, <c>/k</c>, <c>/r</c>: cmd waits for input.</summary>
        InteractiveShell,

        /// <summary><see cref="CommandStart"/> is where the command text begins (right after the letter).</summary>
        Command,

        /// <summary>Something before the command that isn't a known switch.</summary>
        NotUnderstood,

        /// <summary>More than <see cref="MaxSwitches"/> switches before the command.</summary>
        TooMany,
    }

    public static CmdSwitches Parse(string args)
    {
        int i = 0;
        for (int count = 0; ; count++)
        {
            while (i < args.Length && args[i] is ' ' or '\t')
            {
                i++;
            }

            if (i >= args.Length)
            {
                return new(Kind.InteractiveShell, args.Length);
            }

            if (count >= MaxSwitches)
            {
                return new(Kind.TooMany, i);
            }

            if (args[i] != '/' || i + 1 >= args.Length)
            {
                return new(Kind.NotUnderstood, i);
            }

            char letter = char.ToLowerInvariant(args[i + 1]);
            if (letter is 'c' or 'k' or 'r')
            {
                return new(Kind.Command, i + 2);
            }

            int next = SwitchEnd(args, i + 2, letter);
            if (next < 0)
            {
                return new(Kind.NotUnderstood, i);
            }

            i = next;
        }
    }

    /// <summary>Where a known switch with letter <paramref name="letter"/> ends (at whitespace, the next <c>/</c> or the end); -1 if it isn't one.</summary>
    private static int SwitchEnd(string args, int at, char letter)
    {
        int end = at;
        while (end < args.Length && args[end] is not (' ' or '\t' or '/'))
        {
            end++;
        }

        string value = args[at..end].ToLowerInvariant();
        bool known = letter switch
        {
            'a' or 'u' or 'q' or 'd' or 's' or 'x' or 'y' => value.Length == 0,
            'e' or 'f' or 'v' => value is "" or ":on" or ":off",
            't' => value.Length is 2 or 3 && value[0] == ':' && value[1..].All(char.IsAsciiHexDigit),
            _ => false,
        };
        return known ? end : -1;
    }
}
