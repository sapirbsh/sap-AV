using System.Collections.Frozen;
using System.Text;
using SapAV.Core.Heuristics;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Motw;
using SapAV.Core.Text;
using S = SapAV.Core.Persistence.PersistenceSignalStrength;

namespace SapAV.Core.Persistence;

/// <summary>A PowerShell <c>-EncodedCommand</c> value found in a command line (E4).</summary>
/// <param name="Display">The decoded command as one sanitized line, capped at <see cref="EncodedPowerShell.MaxDisplayLength"/>
/// (with an ellipsis when cut); null when it didn't decode.</param>
/// <param name="Problem">Why it didn't decode (engine text); null when it did.</param>
/// <param name="Text">The full decoded text (capped at <see cref="EncodedPowerShell.MaxDecodedLength"/>) for the rules to look
/// into; never shown as it is.</param>
public sealed record EncodedCommand(string? Display, string? Problem, string? Text);

/// <summary>
/// Finds and decodes PowerShell's encoded command (E4): <c>-EncodedCommand</c> and every prefix PowerShell accepts for it
/// (<c>-e</c>, <c>-ec</c>, <c>-en</c>, <c>-enc</c>, ... <c>-encodedcommand</c>, any case, with <c>-</c>, <c>/</c> or a Unicode dash),
/// whose value is Base64 of UTF-16LE text. Pure and bounded: at most <see cref="MaxEncodedLength"/> characters are decoded.
/// </summary>
public static class EncodedPowerShell
{
    public const int MaxEncodedLength = 64 * 1024;
    public const int MaxDecodedLength = 32 * 1024;
    public const int MaxDisplayLength = 160;

    /// <summary>True for a parameter name (without its dash) PowerShell reads as <c>-EncodedCommand</c>.</summary>
    public static bool IsEncodedCommandParameter(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        string n = name.ToLowerInvariant();
        return n is "e" or "ec" || (n.Length >= 2 && "encodedcommand".StartsWith(n, StringComparison.Ordinal));
    }

    /// <summary>The encoded command in PowerShell's <paramref name="arguments"/>, or null when there is none.</summary>
    public static EncodedCommand? Find(string? arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments))
        {
            return null;
        }

        var tokens = CommandLineResolver.Tokenize(arguments);
        for (int i = 0; i < tokens.Count; i++)
        {
            string value = tokens[i].Value;
            if (value.Length >= 2 && IsDash(value[0]) && IsEncodedCommandParameter(value[1..]))
            {
                return i + 1 < tokens.Count ? Decode(tokens[i + 1].Value) : new EncodedCommand(null, "the encoded command is missing", null);
            }
        }

        return null;
    }

    /// <summary>Decodes one <c>-EncodedCommand</c> value as PowerShell does (Base64, then UTF-16LE).</summary>
    public static EncodedCommand Decode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        string base64 = new(value.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (base64.Length == 0)
        {
            return new EncodedCommand(null, "the encoded command is empty", null);
        }

        if (base64.Length > MaxEncodedLength)
        {
            return new EncodedCommand(null, $"the encoded command is longer than {MaxEncodedLength} characters", null);
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            return new EncodedCommand(null, "the encoded command isn't valid Base64 (PowerShell would refuse it)", null);
        }

        string text = Encoding.Unicode.GetString(bytes, 0, bytes.Length & ~1);
        if (text.Length > MaxDecodedLength)
        {
            text = text[..MaxDecodedLength];
        }

        string display = SafeText.SingleLine(text, MaxDisplayLength);
        return display.Length == 0
            ? new EncodedCommand(null, "the encoded command decodes to nothing printable", text)
            : new EncodedCommand(display, null, text);
    }

    internal static bool IsDash(char c) => c is '-' or '/' or '–' or '—' or '―';
}

/// <summary>
/// E4: script-persistence rules (ROADMAP feature 11 "Script-based persistence"), on top of C3's <see cref="PersistenceRules.HostRule"/>.
/// All are target rules, so every command of an entry (a cmd chain's too) is checked.
/// </summary>
/// <remarks>
/// <list type="table">
/// <listheader><term>Rule</term><description>Points (strength)</description></listheader>
/// <item><term><see cref="EncodedPowerShellRule"/></term><description>an encoded command 40 (T1027.010), decoded for display; it or an
/// inline command downloads / runs code 30 (T1059.001); changes Defender 50 (strong, T1562.001, DefenderTampering); starts a miner
/// 70 (strong, T1496.001, Miner)</description></item>
/// <item><term><see cref="MshtaRule"/></term><description>inline JavaScript / VBScript 20 (strong) or a remote HTA 20 (strong) with what
/// runs shown (C3's host rule already scores those 60); a local HTA from a user-writable or risky folder 40 (strong when
/// machine-wide)</description></item>
/// <item><term><see cref="Rundll32UserFolderRule"/></term><description>rundll32 loads a library from a user-writable or risky folder 50
/// (strong when machine-wide), 20 when that library is trusted-signed; a library without a library extension 20</description></item>
/// <item><term><see cref="LauncherPayloadRule"/></term><description>a target started through a Microsoft binary's arguments
/// (<see cref="ResolutionFlag.LauncherPayload"/>) 30</description></item>
/// </list>
/// </remarks>
public static class ScriptPersistenceRules
{
    public const string EncodedPowerShellId = "encoded-powershell";
    public const string PowerShellDownloadId = "powershell-download";
    public const string PowerShellDefenderTamperingId = "powershell-defender-tampering";
    public const string MshtaScriptId = "mshta-script";
    public const string MshtaUserFolderId = "mshta-user-folder";
    public const string Rundll32UserFolderId = "rundll32-user-folder";
    public const string Rundll32NonLibraryId = "rundll32-non-library";
    public const string LauncherPayloadId = "launcher-payload";

    /// <summary>The E4 rules, in the order they run.</summary>
    public static IReadOnlyList<IPersistenceRule> All { get; } =
        [new EncodedPowerShellRule(), new MshtaRule(), new Rundll32UserFolderRule(), new LauncherPayloadRule()];

    /// <summary>Words of PowerShell that download or run code (matched as whole words, case-insensitive).</summary>
    private static readonly FrozenSet<string> DownloadWords = new[]
    {
        "iex", "invoke-expression", "downloadstring", "downloadfile", "downloaddata", "net.webclient", "invoke-webrequest", "iwr",
        "irm", "invoke-restmethod", "start-bitstransfer", "frombase64string", "-bxor", "reflection.assembly", "invoke-shellcode",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Defender cmdlets that weaken protection.</summary>
    private static readonly FrozenSet<string> DefenderWords = new[]
    {
        "add-mppreference", "set-mppreference", "-exclusionpath", "-exclusionprocess", "-exclusionextension", "-disablerealtimemonitoring",
        "-disablebehaviormonitoring", "-disableioavprotection", "uninstall-windowsfeature",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>The engine-chosen words of <paramref name="set"/> that occur as whole words in <paramref name="text"/> (at most 4).</summary>
    internal static string[] Words(string text, FrozenSet<string> set)
    {
        var found = new List<string>();
        foreach (var word in text.Split([' ', '\t', ';', '(', ')', '{', '}', '|', '&', '\'', '"', ',', '[', ']', '='], StringSplitOptions.RemoveEmptyEntries))
        {
            string w = word.TrimEnd(':');
            if (set.TryGetValue(w, out var canonical) && !found.Contains(canonical, StringComparer.OrdinalIgnoreCase))
            {
                found.Add(canonical);
            }

            if (found.Count >= 4)
            {
                break;
            }
        }

        bool url = text.Contains("http://", StringComparison.OrdinalIgnoreCase) || text.Contains("https://", StringComparison.OrdinalIgnoreCase);
        if (found.Count < 4 && url && ReferenceEquals(set, DownloadWords))
        {
            found.Add("a URL");
        }

        return [.. found];
    }

    private static bool IsPowerShell(string? host) => host is "powershell.exe" or "pwsh.exe";

    /// <summary>Encoded PowerShell (every <c>-enc</c> form), decoded for display; download cradles, Defender changes and miners in it.</summary>
    public sealed class EncodedPowerShellRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            var resolution = context.Entry.Resolution;
            // PowerShell's encoded and inline commands are InlineCommand; after -File the arguments are the script's, not PowerShell's.
            string? arguments = IsPowerShell(context.HostName)
                ? (resolution.HasFlag(ResolutionFlag.InlineCommand) ? resolution.Arguments : null)
                : PowerShellTail(context.Entry.CommandLine);
            if (arguments is null)
            {
                return;
            }

            var encoded = EncodedPowerShell.Find(arguments);
            if (encoded is not null)
            {
                context.Add(EncodedPowerShellId, 40, encoded.Display is { } shown
                        ? $"PowerShell runs a Base64-encoded command; decoded: \"{shown}\""
                        : $"PowerShell runs an encoded command, but {encoded.Problem}",
                    MitreTechniqueIds.CommandObfuscation);
            }

            // What the command does: the decoded text, or the inline command itself.
            string text = encoded?.Text ?? (resolution.HasFlag(ResolutionFlag.InlineCommand) ? arguments : string.Empty);
            if (text.Length == 0)
            {
                return;
            }

            if (Words(text, DefenderWords) is { Length: > 0 } defender)
            {
                context.Add(PowerShellDefenderTamperingId, 50, $"PowerShell changes Microsoft Defender at every start ({string.Join(", ", defender)})",
                    MitreTechniqueIds.DisableOrModifyTools, S.Strong, ThreatCategory.DefenderTampering);
            }

            if (Words(text, DownloadWords) is { Length: > 0 } download)
            {
                context.Add(PowerShellDownloadId, 30, $"PowerShell downloads or runs code from the command line ({string.Join(", ", download)})",
                    MitreTechniqueIds.PowerShell);
            }

            if (encoded?.Text is { } decoded && MinerRules.AnalyzeCommandLine(decoded) is { IsMiner: true } miner)
            {
                context.Add(PersistenceRuleIds.MinerCommandLine, 70, $"The encoded PowerShell command starts a cryptominer ({string.Join(", ", miner.Reasons)})",
                    MitreTechniqueIds.ComputeHijacking, S.Strong, ThreatCategory.Miner);
            }
        }

        /// <summary>
        /// When PowerShell wasn't unwrapped as the host (its path isn't on the known search order), the text after a
        /// <c>powershell</c> / <c>pwsh</c> word in the stored command; else null.
        /// </summary>
        private static string? PowerShellTail(string commandLine)
        {
            foreach (var name in new[] { "powershell.exe", "powershell", "pwsh.exe", "pwsh" })
            {
                int at = commandLine.IndexOf(name, StringComparison.OrdinalIgnoreCase);
                if (at >= 0)
                {
                    return commandLine[(at + name.Length)..].TrimStart('"');
                }
            }

            return null;
        }
    }

    /// <summary>mshta: what it runs (inline script, a remote HTA) shown, and local HTAs from user-writable or risky folders.</summary>
    public sealed class MshtaRule : IPersistenceTargetRule
    {
        public const int MaxShownLength = 120;

        public void Evaluate(PersistenceRuleContext context)
        {
            if (context.HostName != "mshta.exe")
            {
                return;
            }

            var resolution = context.Entry.Resolution;
            if (resolution.HasFlag(ResolutionFlag.InlineCommand))
            {
                string script = resolution.Arguments.TrimStart('"');
                string language = script.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase) ? "VBScript"
                    : script.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ? "JavaScript"
                    : "script";
                context.Add(MshtaScriptId, 20, $"mshta runs inline {language} at every start: \"{SafeText.SingleLine(script, MaxShownLength)}\"",
                    language == "VBScript" ? MitreTechniqueIds.VisualBasic : MitreTechniqueIds.JavaScript, S.Strong);
                return;
            }

            if (resolution.UnresolvedReason == TargetUnresolvedReason.RemotePayload)
            {
                string? url = CommandLineResolver.Tokenize(context.Entry.CommandLine).Select(t => t.Value)
                    .FirstOrDefault(t => t.StartsWith("http:", StringComparison.OrdinalIgnoreCase) || t.StartsWith("https:", StringComparison.OrdinalIgnoreCase));
                context.Add(MshtaScriptId, 20, url is null
                        ? "mshta loads an HTA from the network at every start"
                        : $"mshta loads an HTA from {MarkOfTheWeb.SanitizeUrlForLog(url) ?? "the network"} at every start",
                    MitreTechniqueIds.Mshta, S.Strong);
                return;
            }

            if (context.TargetPath is { } target && !context.TargetMissing && InUserFolder(context, target))
            {
                context.Add(MshtaUserFolderId, 40, $"mshta runs {context.TargetName} from a user-writable folder", MitreTechniqueIds.Mshta,
                    context.IsMachineWide ? S.Strong : S.Normal);
            }
        }
    }

    /// <summary>rundll32 loading a library from where a user can put one (no false positive on System32 libraries such as shell32).</summary>
    public sealed class Rundll32UserFolderRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (context.HostName != "rundll32.exe" || context.TargetPath is not { } target || context.TargetMissing
                || context.Entry.Resolution.HasFlag(ResolutionFlag.LauncherPayload))
            {
                return;
            }

            if (InUserFolder(context, target))
            {
                bool trusted = context.Target?.Signature?.IsTrusted == true;
                context.Add(Rundll32UserFolderId, trusted ? 20 : 50, $"rundll32 loads {context.TargetName} from a user-writable folder at every start",
                    MitreTechniqueIds.Rundll32, context.IsMachineWide && !trusted ? S.Strong : S.Normal);
            }

            if (!PersistenceRules.PeExtensions.Contains(Path.GetExtension(target)))
            {
                context.Add(Rundll32NonLibraryId, 20, $"rundll32 loads {context.TargetName}, which doesn't have a library extension", MitreTechniqueIds.Rundll32);
            }
        }
    }

    /// <summary>A target a Microsoft binary starts from its arguments (url.dll, ShellExec_RunDLL, scrobj, conhost, forfiles, pcalua, explorer, msiexec).</summary>
    public sealed class LauncherPayloadRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (!context.Entry.Resolution.HasFlag(ResolutionFlag.LauncherPayload))
            {
                return;
            }

            string host = context.HostName ?? "a Windows program";
            string technique = context.HostName switch
            {
                "rundll32.exe" => MitreTechniqueIds.Rundll32,
                "regsvr32.exe" => MitreTechniqueIds.Regsvr32,
                "msiexec.exe" => MitreTechniqueIds.Msiexec,
                "mshta.exe" => MitreTechniqueIds.Mshta,
                _ => MitreTechniqueIds.IndirectCommandExecution,
            };
            string what = context.TargetPath is not null ? context.TargetName : "its payload";
            context.Add(LauncherPayloadId, 30, $"{what} is started indirectly, through the arguments of {host}", technique);
        }
    }

    /// <summary>The target is in a folder standard users can write, or in a risky one (Temp, Downloads, Public, Recycle Bin, AppData).</summary>
    private static bool InUserFolder(PersistenceRuleContext context, string target) =>
        context.FileModifiable(target) == Writability.UserWritable
        || context.FileCreatable(target) == Writability.UserWritable
        || TargetLocations.IsHighRisk(context.TargetLocation)
        || context.TargetLocation == TargetLocation.AppData;
}
