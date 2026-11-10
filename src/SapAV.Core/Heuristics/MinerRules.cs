using System.Collections.Frozen;
using System.Text.RegularExpressions;
using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Heuristics;

/// <summary>What <see cref="MinerRules.AnalyzeCommandLine"/> found in a command line (E3).</summary>
/// <param name="Score">The sum of the signals' points; <see cref="MinerRules.CommandLineThreshold"/> or more is a miner.</param>
/// <param name="Reasons">One engine sentence per signal (no command-line text in them, so they are log-safe as they are).</param>
public sealed record MinerAnalysis(int Score, IReadOnlyList<string> Reasons)
{
    public static MinerAnalysis None { get; } = new(0, []);

    /// <summary>The command line runs a cryptominer (score at or over <see cref="MinerRules.CommandLineThreshold"/>).</summary>
    public bool IsMiner => Score >= MinerRules.CommandLineThreshold;

    /// <summary>Always <see cref="ThreatCategory.Miner"/>.</summary>
    public ThreatCategory Category => ThreatCategory.Miner;

    /// <summary>Always <see cref="MitreTechniqueIds.ComputeHijacking"/> (T1496.001).</summary>
    public string TechniqueId => MitreTechniqueIds.ComputeHijacking;
}

/// <summary>
/// Static cryptominer rules (E3, ROADMAP feature 11 "Cryptominers, static"): known miner program names, and miner command lines
/// (pool URLs, pool ports, miner flags). Pure string work, no I/O: the file heuristics use the name rule in the worker, the
/// persistence judgement uses the command-line rule on autostart entries, and E7 can use it on running processes' command lines.
/// </summary>
/// <remarks>
/// <para><b>Command-line points</b> (a miner at <see cref="CommandLineThreshold"/>, 60): a <c>stratum+tcp://</c> / <c>+ssl</c> /
/// <c>+tls</c> URL 60; <c>--donate-level</c> 60 (XMRig and its forks only); a Monero wallet as the user 60; the program is a known
/// miner 45; <c>-o</c> / <c>--url</c> to a pool host 30 or to a common pool port 30 (together at most 40); a mining algorithm
/// (<c>-a rx/0</c>, <c>--algo kawpow</c>) 30; <c>--coin monero</c> 30; miner tuning flags (<c>--cpu-max-threads-hint</c>,
/// <c>--randomx-1gb-pages</c>, ...) 15 each, at most 30. One of the strong signals alone is enough; the others need company, so
/// an ordinary <c>-o out.txt</c> or <c>--url https://example.com:4444</c> is not a miner.</para>
/// <para>Bounded: at most <see cref="MaxTokens"/> tokens of at most <see cref="MaxCommandLineLength"/> characters are read.</para>
/// </remarks>
public static partial class MinerRules
{
    public const int CommandLineThreshold = 60;
    public const int MaxCommandLineLength = 32 * 1024;
    public const int MaxTokens = 256;

    /// <summary>Common mining pool ports (the ROADMAP's 3333/4444/5555/7777/14444 and a few more used by Monero pools).</summary>
    public static readonly FrozenSet<int> PoolPorts = new[] { 3333, 4444, 5555, 7777, 9999, 10128, 13333, 14433, 14444, 20128, 45560, 45700 }.ToFrozenSet();

    /// <summary>Known miner program names (file name without extension, lower case).</summary>
    public static readonly FrozenSet<string> MinerNames = new[]
    {
        "xmrig", "xmrig-notls", "xmrig-cuda", "xmr-stak", "xmr-stak-rx", "xmr-stak-cpu", "nheqminer", "phoenixminer", "nbminer", "t-rex",
        "lolminer", "gminer", "teamredminer", "nanominer", "srbminer", "srbminer-multi", "cpuminer", "cpuminer-opt", "cpuminer-multi",
        "ccminer", "ethminer", "bminer", "wildrig", "wildrig-multi", "ethdcrminer64", "minerd", "cgminer", "bfgminer", "bzminer",
        "kawpowminer", "onezerominer", "rigel", "xmrminer", "jceminer", "cast_xmr-vega", "claymore",
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>Name prefixes that are miners whatever follows (<c>xmrig-6.21.0</c>, <c>SRBMiner-MULTI</c>, <c>lolMiner_x64</c>).</summary>
    private static readonly string[] MinerPrefixes =
        ["xmrig", "xmr-stak", "srbminer", "cpuminer", "teamredminer", "phoenixminer", "lolminer", "nbminer", "nanominer", "ethminer", "ccminer", "bzminer", "wildrig"];

    private static readonly FrozenSet<string> PoolHostWords = new[]
    {
        "nanopool", "moneroocean", "supportxmr", "minexmr", "2miners", "f2pool", "nicehash", "hashvault", "c3pool", "herominers",
        "unmineable", "ethermine", "hiveon", "minergate", "miningpoolhub", "woolypooly", "kryptex", "p2pool", "xmrpool", "zpool",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> Algorithms = new[]
    {
        "rx/0", "rx/wow", "rx/arq", "rx/graft", "rx/sfx", "randomx", "cn/r", "cn/half", "cn/gpu", "cn-heavy/xhv", "cryptonight", "kawpow",
        "ethash", "etchash", "autolykos2", "kheavyhash", "argon2/chukwa", "ghostrider", "astrobwt", "octopus", "beamhashiii", "equihash",
        "progpow", "firopow", "verthash", "blake3", "karlsenhash", "dynexsolve",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> Coins = new[] { "monero", "xmr", "rvn", "ravencoin", "etc", "ergo", "kas", "kaspa", "zeph", "zephyr" }
        .ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> TuningFlags = new[]
    {
        "--cpu-max-threads-hint", "--max-cpu-usage", "--randomx-1gb-pages", "--randomx-mode", "--cpu-priority", "--nicehash", "--rig-id",
        "--cuda", "--opencl", "--pause-on-active", "--pause-on-battery", "--cpu-no-yield", "--asm", "--huge-pages-jit",
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>True if <paramref name="fileName"/> (a name or path) is a known miner program (<c>xmrig.exe</c>, <c>xmrig-6.21.0</c>).</summary>
    public static bool IsMinerName(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        string name = Path.GetFileName(fileName.Trim().Trim('"')).TrimEnd(' ', '.');
        string stem = Path.GetExtension(name) is { Length: > 1 } ext && ext.Length < name.Length ? name[..^ext.Length] : name;
        stem = stem.ToLowerInvariant();
        return stem.Length > 0 && (MinerNames.Contains(stem) || MinerPrefixes.Any(p => stem.StartsWith(p, StringComparison.Ordinal)));
    }

    /// <summary>Scores <paramref name="commandLine"/> (program and arguments, or a script's text) for cryptominer signs. Never throws.</summary>
    public static MinerAnalysis AnalyzeCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return MinerAnalysis.None;
        }

        string text = commandLine.Length > MaxCommandLineLength ? commandLine[..MaxCommandLineLength] : commandLine;
        var tokens = Tokens(text);
        var reasons = new List<string>();
        int score = 0;

        if (SafeMatch(StratumRegex(), text))
        {
            Add(60, "a mining pool URL (stratum)");
        }

        if (tokens.Any(t => StartsWithOption(t, "--donate-level") || StartsWithOption(t, "--donate-lvl")))
        {
            Add(60, "the XMRig option --donate-level");
        }

        if (tokens.Count > 0 && IsMinerName(tokens[0]))
        {
            Add(45, "a known cryptominer program");
        }

        bool wallet = false, poolHost = false, poolPort = false, algo = false, coin = false;
        int tuning = 0;
        for (int i = 0; i < tokens.Count; i++)
        {
            string token = tokens[i];
            string lower = token.ToLowerInvariant();
            string? value = OptionValue(tokens, i, out string option);
            switch (option)
            {
                case "-u" or "--user" or "--wallet" or "-w" or "--userpass" or "-ewal" or "--address" when value is not null:
                    wallet |= SafeMatch(MoneroAddressRegex(), value.Split([':', '.', '+'], 2)[0]);
                    break;
                case "-o" or "--url" or "-pool" or "--pool" or "-epool" or "-s" or "--server" when value is not null:
                    var (host, port) = HostPort(value);
                    poolHost |= host is not null && IsPoolHost(host);
                    poolPort |= port is { } p && PoolPorts.Contains(p);
                    break;
                case "-a" or "--algo" or "--algorithm" when value is not null:
                    algo |= Algorithms.Contains(value.ToLowerInvariant());
                    break;
                case "--coin" or "-coin" when value is not null:
                    coin |= Coins.Contains(value.ToLowerInvariant());
                    break;
            }

            if (TuningFlags.Contains(lower.Split('=', 2)[0]))
            {
                tuning++;
            }
        }

        if (wallet)
        {
            Add(60, "a Monero wallet address as the miner user");
        }

        int pool = (poolHost ? 30 : 0) + (poolPort ? 30 : 0);
        if (pool > 0)
        {
            Add(Math.Min(pool, 40), poolHost && poolPort ? "a mining pool host and port" : poolHost ? "a mining pool host" : "a common mining pool port");
        }

        if (algo)
        {
            Add(30, "a mining algorithm option");
        }

        if (coin)
        {
            Add(30, "a mined-coin option");
        }

        if (tuning > 0)
        {
            Add(Math.Min(tuning * 15, 30), "miner tuning options");
        }

        return score == 0 ? MinerAnalysis.None : new MinerAnalysis(score, reasons.AsReadOnly());

        void Add(int points, string reason)
        {
            score += points;
            reasons.Add(reason);
        }
    }

    /// <summary>A pool host: a known pool's name in it, or the word "pool" in a label (<c>xmr-pool.example</c>, <c>pool.example</c>).</summary>
    private static bool IsPoolHost(string host)
    {
        string lower = host.ToLowerInvariant();
        return PoolHostWords.Any(w => lower.Contains(w, StringComparison.Ordinal))
            || lower.Split('.').Any(label => label.Contains("pool", StringComparison.Ordinal));
    }

    /// <summary>The option name of tokens[i] (lower case, without <c>=value</c>) and its value (attached with <c>=</c> or the next token).</summary>
    private static string? OptionValue(List<string> tokens, int i, out string option)
    {
        string token = tokens[i];
        option = string.Empty;
        if (token.Length < 2 || token[0] != '-')
        {
            return null;
        }

        int eq = token.IndexOf('=');
        if (eq > 0)
        {
            option = token[..eq].ToLowerInvariant();
            return token[(eq + 1)..];
        }

        option = token.ToLowerInvariant();
        return i + 1 < tokens.Count && !tokens[i + 1].StartsWith('-') ? tokens[i + 1] : null;
    }

    /// <summary>The host and port of <c>host:port</c>, <c>scheme://host:port/...</c> or <c>[v6]:port</c>; nulls when not that shape.</summary>
    private static (string? Host, int? Port) HostPort(string value)
    {
        string rest = value;
        int scheme = rest.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            rest = rest[(scheme + 3)..];
        }

        int slash = rest.IndexOfAny(['/', '?', '#']);
        if (slash >= 0)
        {
            rest = rest[..slash];
        }

        int at = rest.LastIndexOf('@');
        if (at >= 0)
        {
            rest = rest[(at + 1)..];
        }

        int colon = rest.LastIndexOf(':');
        if (colon <= 0 || rest.IndexOf(']') > colon)
        {
            return (rest.Length > 0 && rest.Contains('.') ? rest : null, null);
        }

        string host = rest[..colon].Trim('[', ']');
        return int.TryParse(rest.AsSpan(colon + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int port)
            && port is > 0 and <= 65535 && host.Length > 0
            ? (host, port)
            : (null, null);
    }

    private static bool StartsWithOption(string token, string option) =>
        token.Equals(option, StringComparison.OrdinalIgnoreCase) || token.StartsWith(option + "=", StringComparison.OrdinalIgnoreCase);

    /// <summary>Whitespace-separated tokens with quotes removed (enough for option spotting; not a full command-line parser).</summary>
    private static List<string> Tokens(string text)
    {
        var tokens = new List<string>();
        foreach (var raw in text.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (tokens.Count >= MaxTokens)
            {
                break;
            }

            string token = raw.Trim('"', '\'');
            if (token.Length > 0)
            {
                tokens.Add(token);
            }
        }

        return tokens;
    }

    private static bool SafeMatch(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    [GeneratedRegex(@"stratum[12]?\+(?:tcp|ssl|tls)://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex StratumRegex();

    /// <summary>A standard (4…) or subaddress (8…) Monero address: 95 base58 characters.</summary>
    [GeneratedRegex(@"\A[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex MoneroAddressRegex();
}
