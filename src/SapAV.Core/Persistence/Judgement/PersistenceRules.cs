using System.Collections.Frozen;
using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Signatures;
using S = SapAV.Core.Persistence.PersistenceSignalStrength;

namespace SapAV.Core.Persistence;

/// <summary>
/// The built-in C3 rules (ROADMAP C3), in the order they run. Points add up to the entry's score; 60 is Suspicious
/// (<see cref="PersistenceJudge.DefaultSuspiciousThreshold"/>). "Machine-wide" means the entry runs for every user or as
/// SYSTEM (<see cref="PersistenceRuleContext.IsMachineWide"/>). Each rule is its own small class so E4 can add or replace
/// rules without touching these.
/// </summary>
/// <remarks>
/// <list type="table">
/// <listheader><term>Rule</term><description>Points (strength)</description></listheader>
/// <item><term><see cref="TargetScanRule"/></term><description>Malicious / Suspicious target or host scan: carried over as is</description></item>
/// <item><term><see cref="LocationRule"/></term><description>machine-wide + target modifiable by users 60 (strong); machine-wide +
/// users can add files to its folder 40; per-user + user-writable 10 (weak); Temp / Downloads / Public / Recycle Bin 50 (strong
/// when machine-wide); machine-wide into AppData 20</description></item>
/// <item><term><see cref="SignatureRule"/></term><description>unsigned PE 20; broken signature 30</description></item>
/// <item><term><see cref="IfeoRule"/></term><description>IFEO Debugger 60; on an accessibility program 90 (strong, T1546.008); on
/// a security / system tool 80 (strong); SilentProcessExit monitor 60, on a security tool 80 (strong)</description></item>
/// <item><term><see cref="WinlogonRule"/></term><description>Shell other than explorer.exe, Userinit other than userinit.exe,
/// or any extra program: 70 (strong)</description></item>
/// <item><term><see cref="MissingTargetRule"/></term><description>missing target 20; users can create it: machine-wide 60
/// (strong), per-user 30</description></item>
/// <item><term><see cref="UnquotedPathRule"/></term><description>a shorter path users can create: machine-wide 60 (strong),
/// per-user 30 (T1574.009); otherwise 5 (weak)</description></item>
/// <item><term><see cref="HostRule"/></term><description>host (weak): rundll32 / cmd 10, regsvr32 / powershell / script host 20,
/// mshta 40; inline code: mshta / rundll32 script 60 (strong), powershell 30 (hidden window + encoded command 60, strong), other 20;
/// remote payload, or a UNC / device target 60 (strong)</description></item>
/// <item><term><see cref="ComOverrideRule"/></term><description>a task's COM handler from the user's own classes: 60 (strong, T1546.015)</description></item>
/// <item><term><see cref="ShortcutMismatchRule"/></term><description>a shortcut whose sources name different files: 60 (strong)</description></item>
/// </list>
/// </remarks>
public static class PersistenceRules
{
    /// <summary>Executable-image extensions the unsigned rule applies to (scripts are rarely signed).</summary>
    public static readonly FrozenSet<string> PeExtensions = new[]
    {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".drv", ".efi", ".ax", ".tsp",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Accessibility programs reachable from the logon screen (an IFEO Debugger on them is a SYSTEM backdoor).</summary>
    public static readonly FrozenSet<string> AccessibilityPrograms = new[]
    {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Security and system tools malware blocks or replaces through IFEO (task managers, editors, Defender, sap-AV).</summary>
    public static readonly FrozenSet<string> SecurityTools = new[]
    {
        "taskmgr.exe", "procexp.exe", "procexp64.exe", "procexp64a.exe", "procmon.exe", "procmon64.exe", "autoruns.exe", "autoruns64.exe",
        "tcpview.exe", "processhacker.exe", "systeminformer.exe", "perfmon.exe", "resmon.exe", "regedit.exe", "regedt32.exe",
        "msconfig.exe", "mmc.exe", "eventvwr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe", "msmpeng.exe",
        "mpcmdrun.exe", "msascuil.exe", "msascui.exe", "mpuxsrv.exe", "nissrv.exe", "securityhealthservice.exe",
        "securityhealthsystray.exe", "securityhealthhost.exe", "smartscreen.exe", "windowsdefender.exe", "mrt.exe", "wuauclt.exe",
        "sapav.app.exe", "sapav.engine.exe", "sapav.scanworker.exe",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every built-in rule, in order.</summary>
    public static IReadOnlyList<IPersistenceRule> Default { get; } =
    [
        new TargetScanRule(), new LocationRule(), new SignatureRule(), new IfeoRule(), new WinlogonRule(), new MissingTargetRule(),
        new UnquotedPathRule(), new HostRule(), new ComOverrideRule(), new ShortcutMismatchRule(),
    ];

    /// <summary>
    /// The image an IFEO / SilentProcessExit entry is about: the subkey after <c>Image File Execution Options\</c> or
    /// <c>SilentProcessExit\</c> in <see cref="PersistenceEntry.Location"/>; null if neither is there.
    /// </summary>
    public static string? IfeoImage(string location)
    {
        foreach (var marker in new[] { @"\Image File Execution Options\", @"\SilentProcessExit\" })
        {
            int at = location.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (at >= 0)
            {
                string rest = location[(at + marker.Length)..];
                int end = rest.IndexOf('\\');
                string image = end < 0 ? rest : rest[..end];
                return image.Length == 0 ? null : image;
            }
        }

        return null;
    }

    /// <summary>
    /// The paths CreateProcess tries before <paramref name="targetPath"/> when it is given unquoted: each prefix ending at a
    /// space (inside the path, after the drive root), with <c>.exe</c> appended when it has no extension. At most 16.
    /// </summary>
    public static IReadOnlyList<string> UnquotedCandidates(string targetPath)
    {
        ArgumentNullException.ThrowIfNull(targetPath);
        string plain = ExactPath.StripPrefix(targetPath);
        var result = new List<string>();
        for (int i = 3; i < plain.Length && result.Count < 16; i++)
        {
            if (plain[i] != ' ' || plain[i - 1] is ' ' or '\\')
            {
                continue;
            }

            string prefix = plain[..i];
            string name = prefix[(prefix.LastIndexOf('\\') + 1)..];
            result.Add(Path.HasExtension(name) ? prefix : prefix + ".exe");
        }

        return result;
    }

    /// <summary>Malicious / Suspicious target or host scan results are carried over (detections keep their own technique).</summary>
    public sealed class TargetScanRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            foreach (var (report, fromHost) in new[] { (context.Target, false), (context.Host, true) })
            {
                if (report?.Result is { Status: Models.ScanStatus.Scanned } result)
                {
                    foreach (var detection in result.Detections)
                    {
                        context.Carry(detection, fromHost);
                    }
                }
            }

            if (context.TargetMissing)
            {
                return; // confirmed: nothing to scan
            }

            if (context.TargetPath is null)
            {
                NoTarget(context);
            }
            else if (context.Target is null || context.Target.Result.Status != Models.ScanStatus.Scanned)
            {
                NotScanned(context);
            }
        }

        /// <summary>Section C review H4: nothing resolved, and nothing says nothing runs: that is Unverified, never Clean.</summary>
        private static void NoTarget(PersistenceRuleContext context)
        {
            var reason = context.Entry.Resolution.UnresolvedReason;
            if (reason is TargetUnresolvedReason.EmptyCommand or TargetUnresolvedReason.ComClassNotRegistered)
            {
                return; // nothing runs
            }

            context.AddUnverified($"What this entry runs isn't known or has no file to scan ({reason}).", KindOf(reason));
        }

        /// <summary>
        /// M3: a cap or a resolver limit is a gap in the scan; everything else here is how the entry is written (inline code, a
        /// URL / network / device path, a relative or unknown path, no file named), which no scan could verify.
        /// </summary>
        internal static UnverifiedKind KindOf(TargetUnresolvedReason? reason) => reason switch
        {
            TargetUnresolvedReason.SearchLimitReached or TargetUnresolvedReason.NestingTooDeep or TargetUnresolvedReason.HostArgumentsNotUnderstood
                or null => UnverifiedKind.Coverage,
            _ => UnverifiedKind.Inherent,
        };

        private static void NotScanned(PersistenceRuleContext context)
        {
            var report = context.Target;
            string why = report is null ? "it wasn't scanned" : $"it couldn't be scanned ({report.Result.Status})";
            context.Add(PersistenceRuleIds.TargetNotScanned, 0, $"The autostart target {context.TargetName} has no verdict: {why}.");
            context.AddUnverified($"{context.TargetName}: {why}.", UnverifiedKind.Coverage); // M3: the scan didn't reach it

            // A program that SYSTEM can't read or reach, but that the entry still starts, is a signal by itself.
            string? unreadable = report?.Hash.FailureReason switch
            {
                HashFailureReason.AccessDenied => "its permissions deny the scanner",
                HashFailureReason.NotRegularFile => "it is behind a link or isn't a regular local file",
                _ => null,
            };
            if (unreadable is not null)
            {
                context.Add(PersistenceRuleIds.TargetUnreadable, 20, $"The autostart target {context.TargetName} can't be scanned: {unreadable}");
            }
        }
    }

    /// <summary>Where the target lives: who can write it (ACL) and how risky the folder is (name), weighted by scope.</summary>
    public sealed class LocationRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (context.TargetPath is not { } target || context.TargetMissing)
            {
                return; // a missing target is MissingTargetRule's
            }

            string? service = context.Entry.Kind == PersistenceKind.Service ? MitreTechniqueIds.ServicesFilePermissionsWeakness : null;
            var file = context.FileModifiable(target);
            var folder = context.FileCreatable(target);
            if (context.IsMachineWide)
            {
                if (file == Writability.UserWritable)
                {
                    context.Add(PersistenceRuleIds.TargetUserModifiable, 60,
                        $"Standard users can modify {context.TargetName}, which runs for every user or as SYSTEM (privilege escalation)",
                        service, S.Strong);
                }
                else if (folder == Writability.UserWritable)
                {
                    context.Add(PersistenceRuleIds.TargetFolderUserWritable, 40,
                        $"Standard users can add files to the folder of {context.TargetName}, which runs for every user or as SYSTEM (file planting, DLL hijacking)",
                        service);
                }
            }
            else if (file == Writability.UserWritable || folder == Writability.UserWritable)
            {
                context.Add(PersistenceRuleIds.TargetInUserFolder, 10, $"{context.TargetName} is in a user-writable folder", null, S.Weak);
            }

            if (TargetLocations.IsHighRisk(context.TargetLocation))
            {
                context.Add(PersistenceRuleIds.TargetRiskyFolder, 50,
                    $"{context.TargetName} starts automatically from the {Describe(context.TargetLocation)} folder",
                    null, context.IsMachineWide ? S.Strong : S.Normal);
            }
            else if (context.TargetLocation == TargetLocation.AppData && context.IsMachineWide)
            {
                context.Add(PersistenceRuleIds.TargetRiskyFolder, 20, $"A machine-wide autostart runs {context.TargetName} from a user's AppData folder");
            }
        }

        private static string Describe(TargetLocation location) => location switch
        {
            TargetLocation.RecycleBin => "Recycle Bin",
            _ => location.ToString(),
        };
    }

    /// <summary>An unsigned or badly signed program that starts automatically: a weak signal that needs company.</summary>
    public sealed class SignatureRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (context.TargetPath is not { } target || !PeExtensions.Contains(Path.GetExtension(target))
                || context.Target?.Signature is not { IsChecked: true } signature || signature.IsTrusted)
            {
                return;
            }

            if (signature.HasBrokenSignature)
            {
                context.Add(PersistenceRuleIds.TargetBrokenSignature, 30, $"{context.TargetName} has a signature that doesn't verify");
            }
            else if (signature.FailureReason == SignatureFailureReason.NotSigned)
            {
                context.Add(PersistenceRuleIds.TargetUnsigned, 20, $"{context.TargetName} is not signed");
            }
        }
    }

    /// <summary>Image File Execution Options: a Debugger replaces the program; a SilentProcessExit monitor runs on its exit.</summary>
    public sealed class IfeoRule : IPersistenceRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            var kind = context.Entry.Kind;
            if (kind is not (PersistenceKind.IfeoDebugger or PersistenceKind.IfeoSilentProcessExit))
            {
                return;
            }

            string image = IfeoImage(context.Entry.Location) ?? "a program";
            string runs = context.TargetName;
            if (kind == PersistenceKind.IfeoSilentProcessExit)
            {
                bool tool = SecurityTools.Contains(image);
                context.Add(PersistenceRuleIds.SilentProcessExitMonitor, tool ? 80 : 60,
                    $"A SilentProcessExit monitor on {(tool ? "the security / system tool " : string.Empty)}{image} runs {runs} whenever it exits",
                    null, tool ? S.Strong : S.Normal);
                return;
            }

            if (AccessibilityPrograms.Contains(image))
            {
                context.Add(PersistenceRuleIds.IfeoDebugger, 90,
                    $"An IFEO Debugger on the accessibility program {image} runs {runs} instead, also from the logon screen (as SYSTEM)",
                    MitreTechniqueIds.AccessibilityFeatures, S.Strong);
            }
            else if (SecurityTools.Contains(image))
            {
                context.Add(PersistenceRuleIds.IfeoDebugger, 80,
                    $"An IFEO Debugger on the security / system tool {image} runs {runs} instead (the tool is blocked or replaced)", null, S.Strong);
            }
            else
            {
                context.Add(PersistenceRuleIds.IfeoDebugger, 60, $"An IFEO Debugger on {image} runs {runs} instead whenever {image} starts");
            }
        }
    }

    /// <summary>Winlogon Shell must be explorer.exe and Userinit must be userinit.exe, with nothing added.</summary>
    public sealed class WinlogonRule : IPersistenceRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            var (kind, valueName) = (context.Entry.Kind, context.Entry.ValueName);
            if (kind is not (PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit))
            {
                return;
            }

            bool shell = kind == PersistenceKind.WinlogonShell;
            string expectedName = shell ? "explorer.exe" : "userinit.exe";
            string? expected = context.Options.SystemRoot is { } root
                ? Path.Join(ExactPath.StripPrefix(root).TrimEnd('\\'), shell ? "explorer.exe" : @"System32\userinit.exe")
                : null;
            bool first = string.Equals(valueName, shell ? "Shell" : "Userinit", StringComparison.OrdinalIgnoreCase);
            bool isDefault = first && context.TargetPath is { } target && (expected is null
                ? string.Equals(Path.GetFileName(target), expectedName, StringComparison.OrdinalIgnoreCase)
                : string.Equals(ExactPath.StripPrefix(target), expected, StringComparison.OrdinalIgnoreCase));
            // Review C M9: the default has no arguments and nothing else to run ("explorer.exe /x" isn't the default shell).
            if (isDefault && string.IsNullOrWhiteSpace(context.Entry.Resolution.Arguments) && context.Entry.Resolution.Additional.Count == 0)
            {
                return;
            }

            string what = shell ? "Shell" : "Userinit";
            string reason = first
                ? $"Winlogon {what} runs {context.TargetName} instead of {expectedName}"
                : $"Winlogon {what} also runs {context.TargetName} at every logon (besides {expectedName})";
            context.Add(PersistenceRuleIds.WinlogonModified, 70, reason, null, S.Strong);
        }
    }

    /// <summary>A dangling autostart: harmless until someone creates the missing file, so the ACL decides.</summary>
    public sealed class MissingTargetRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (!context.TargetMissing)
            {
                return;
            }

            if (context.TargetPath is { } target && context.FileCreatable(target) == Writability.UserWritable)
            {
                string? service = context.Entry.Kind == PersistenceKind.Service ? MitreTechniqueIds.ServicesFilePermissionsWeakness : null;
                context.Add(PersistenceRuleIds.MissingTargetHijackable, context.IsMachineWide ? 60 : 30,
                    $"The autostart target {context.TargetName} doesn't exist, and standard users can create it (anyone can take over the entry)",
                    service, context.IsMachineWide ? S.Strong : S.Normal);
                return;
            }

            context.Add(PersistenceRuleIds.MissingTarget, 20, $"The autostart target {context.TargetName} doesn't exist (a leftover entry)");
        }
    }

    /// <summary>An unquoted path with spaces is a hijack only if a standard user can create one of the shorter paths.</summary>
    public sealed class UnquotedPathRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (!context.Entry.Resolution.HasFlag(ResolutionFlag.UnquotedPathWithSpaces) || context.TargetPath is not { } target)
            {
                return;
            }

            var hijack = UnquotedCandidates(target).FirstOrDefault(c => context.FileCreatable(c) == Writability.UserWritable);
            if (hijack is not null)
            {
                context.Add(PersistenceRuleIds.UnquotedPathHijackable, context.IsMachineWide ? 60 : 30,
                    $"The program path isn't quoted and has spaces, and standard users can create {hijack}, which would run instead",
                    MitreTechniqueIds.PathInterceptionByUnquotedPath, context.IsMachineWide ? S.Strong : S.Normal);
                return;
            }

            context.Add(PersistenceRuleIds.UnquotedPath, 5,
                "The program path isn't quoted and has spaces (not exploitable now: standard users can't create a shorter path)",
                MitreTechniqueIds.PathInterceptionByUnquotedPath, S.Weak);
        }
    }

    /// <summary>
    /// A system host runs the payload (rundll32, regsvr32, cmd, powershell, script hosts, mshta): a basic signal now; E4 adds
    /// the decoding rules (encoded PowerShell, mshta / rundll32 from user folders).
    /// </summary>
    public sealed class HostRule : IPersistenceTargetRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            var flags = context.Entry.Resolution;
            string? host = context.HostName;
            string? technique = host switch
            {
                "rundll32.exe" => MitreTechniqueIds.Rundll32,
                "regsvr32.exe" => MitreTechniqueIds.Regsvr32,
                "mshta.exe" => MitreTechniqueIds.Mshta,
                "powershell.exe" or "pwsh.exe" => MitreTechniqueIds.PowerShell,
                "cmd.exe" => MitreTechniqueIds.WindowsCommandShell,
                "wscript.exe" or "cscript.exe" => context.TargetPath is { } script
                    && Path.GetExtension(script).ToLowerInvariant() is ".js" or ".jse" ? MitreTechniqueIds.JavaScript : MitreTechniqueIds.VisualBasic,
                _ => null,
            };

            if (host is not null && flags.HasFlag(ResolutionFlag.InterpreterHost))
            {
                int points = host switch
                {
                    "rundll32.exe" or "cmd.exe" => 10,
                    "mshta.exe" => 40,
                    _ => 20,
                };
                context.Add(PersistenceRuleIds.InterpreterHost, points, $"Runs through {host}", technique, S.Weak);
            }

            if (flags.HasFlag(ResolutionFlag.InlineCommand))
            {
                bool script = host is "mshta.exe" or "rundll32.exe";
                bool stealth = flags.HasFlag(ResolutionFlag.HiddenWindow) && flags.HasFlag(ResolutionFlag.EncodedCommand);
                int points = script || stealth ? 60 : host is "powershell.exe" or "pwsh.exe" ? 30 : 20;
                context.Add(PersistenceRuleIds.InlineCommand, points, stealth
                    ? $"{host ?? "The host"} runs an encoded command in a hidden window from the autostart entry itself (no file to scan)"
                    : $"{host ?? "The host"} runs inline {(script ? "script" : "commands")} from the autostart entry itself (no file to scan)",
                    technique, script || stealth ? S.Strong : S.Normal);
            }

            if (flags.HasFlag(ResolutionFlag.RemotePayload))
            {
                string? remote = host is "regsvr32.exe" ? MitreTechniqueIds.Regsvr32 : host is "mshta.exe" ? MitreTechniqueIds.Mshta : null;
                string reason = context.Entry.Resolution.UnresolvedReason == TargetUnresolvedReason.DevicePath
                    ? $"{host ?? "The entry"} runs a device path at every start, where no file can be scanned"
                    : $"{host ?? "The entry"} loads its payload from the network at every start";
                context.Add(PersistenceRuleIds.RemotePayload, 60, reason, remote, S.Strong);
            }
        }
    }

    /// <summary>A shortcut whose sources name different files: what it shows isn't necessarily what it runs. Every candidate is scanned.</summary>
    public sealed class ShortcutMismatchRule : IPersistenceRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (context.Entry.Resolution.HasFlag(ResolutionFlag.ShortcutTargetMismatch))
            {
                context.Add(PersistenceRuleIds.ShortcutTargetMismatch, 60,
                    "The shortcut's target differs between its sources, so what it shows may not be what it runs", MitreTechniqueIds.ShortcutModification, S.Strong);
            }
        }
    }

    /// <summary>A scheduled task's COM handler resolved from the user's own classes, which override the machine's.</summary>
    public sealed class ComOverrideRule : IPersistenceRule
    {
        public void Evaluate(PersistenceRuleContext context)
        {
            if (context.Entry.Resolution.HasFlag(ResolutionFlag.UserComOverride))
            {
                context.Add(PersistenceRuleIds.UserComOverride, 60,
                    $"The task's COM handler {context.Entry.ComClassId?.ToString("B") ?? string.Empty} is registered in the user's own classes, overriding the machine's (COM hijacking)",
                    MitreTechniqueIds.ComponentObjectModelHijacking, S.Strong);
            }
        }
    }
}
