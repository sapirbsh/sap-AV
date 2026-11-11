using SapAV.Core.Models;

namespace SapAV.Core.Defender;

/// <summary>
/// The Defender-tampering rules (ROADMAP E5, threat pack "Defender tampering"): a pure function from a
/// <see cref="DefenderStatusSnapshot"/> to findings. No I/O, no machine state, nothing is changed.
/// </summary>
/// <remarks>
/// <para><b>Unknown is never benign, and never an alarm.</b> A failed read, a Hidden / Unknown list or a null flag gives no finding
/// and is listed in <see cref="DefenderAssessment.Unverified"/>, so the outcome is Unverified rather than Clean. The exceptions are
/// the tamper signs below, which are about the read state itself.</para>
/// <para><b>Exclusions</b> (every known list, whatever the protection state; one finding per flagged entry, at most
/// <see cref="MaxExclusionFindingsPerList"/> per list plus one summary):</para>
/// <list type="bullet">
/// <item>Path: a drive / everything, or a whole user-writable root (all profiles, a profile, AppData and its Roaming / Local /
/// LocalLow, Temp, Downloads, Public, ProgramData) → Malicious; a whole system folder (Windows, System32, Program Files) or a
/// narrower folder inside a profile, Temp or the Recycle Bin → Suspicious (developer folders can be legitimate). Program folders,
/// ProgramData subfolders, shares and documented Hyper-V defaults → nothing.</item>
/// <item>Extension: every file, or a program / script extension (exe, dll, scr, ps1, vbs, js, bat, cmd, hta, ...) → Malicious.</item>
/// <item>Process: every process, or an interpreter / script host / LOLBin / Windows host (powershell, cmd, wscript, mshta,
/// rundll32, regsvr32, explorer, svchost, ...) → Malicious; a wildcard over a whole user-writable root or drive → Malicious; a
/// program in a user-writable folder → Suspicious.</item>
/// </list>
/// <para><b>Protection</b> (only when Defender should be protecting: Security Center confirms no other antivirus is active,
/// <see cref="DefenderStatusSnapshot.ThirdPartyAntivirusActive"/> false). Confirmed third-party antivirus → expected, no finding;
/// unknown → Unverified. Antivirus or real-time protection off → Malicious; on-access, behaviour monitoring, IOAV or tamper
/// protection off, or a preference set to off that tamper protection is overriding → Suspicious; passive mode without another
/// antivirus → Suspicious.</para>
/// <para><b>Tamper signs</b>: on a client SKU (<see cref="DefenderStatusSnapshot.DefenderExpected"/>), Defender's classes missing
/// (NotInstalled; Suspicious when another antivirus is active, else Malicious) or its service stopped (ServiceNotRunning; nothing
/// when another antivirus is confirmed active, Malicious when confirmed none, else Suspicious); exclusion lists hidden from SYSTEM;
/// a truncated (padded) exclusion list → Suspicious.</para>
/// <para>Every finding is <see cref="ThreatCategory.DefenderTampering"/>, T1562.001, never quarantined, and says the user decides.
/// Removing exclusions is E11's user-confirmed "Remove threat".</para>
/// </remarks>
public static class DefenderRules
{
    public const int MaxExclusionFindingsPerList = 50;

    public static DefenderAssessment Evaluate(DefenderStatusSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var findings = new List<DefenderFinding>();
        var unverified = new List<string>();
        bool? thirdParty = snapshot.ThirdPartyAntivirusActive;

        bool handedOver = CheckPresence(snapshot, thirdParty, findings, unverified, out bool notApplicable);
        if (!notApplicable)
        {
            CheckProtection(snapshot, thirdParty, findings, unverified);
        }

        CheckExclusions(snapshot, findings, unverified, reportUnknownLists: !notApplicable && !handedOver);

        if (snapshot.ExclusionsHiddenFromSystem)
        {
            findings.Add(Tamper(DefenderRuleIds.ExclusionsHiddenFromSystem, Verdict.Suspicious,
                "Defender hid its exclusion lists even from SYSTEM, which it normally shows them to. Something may be hiding exclusions."));
        }

        return new DefenderAssessment(findings, unverified, notApplicable && findings.Count == 0);
    }

    /// <summary>Defender missing or stopped. True when Defender is confirmed to have handed over to another antivirus.</summary>
    private static bool CheckPresence(DefenderStatusSnapshot s, bool? thirdParty, List<DefenderFinding> findings, List<string> unverified,
        out bool notApplicable)
    {
        notApplicable = false;
        switch (s.ComputerStatusRead)
        {
            case DefenderReadState.Available:
                return thirdParty == true && s.Protection.RunningMode is DefenderRunningMode.Passive or DefenderRunningMode.SideBySidePassive
                    or DefenderRunningMode.EdrBlock;

            case DefenderReadState.NotInstalled when s.DefenderExpected == true:
                findings.Add(Tamper(DefenderRuleIds.DefenderMissing, thirdParty == true ? Verdict.Suspicious : Verdict.Malicious,
                    "Microsoft Defender is part of this Windows edition, but its status classes are missing: it may have been removed or broken."
                    + (thirdParty == true ? " Another antivirus is active." : " No other antivirus was confirmed active, so this PC may be unprotected.")));
                return false;

            case DefenderReadState.NotInstalled when s.DefenderExpected == false:
                notApplicable = true; // a Server SKU without the Defender feature
                return false;

            case DefenderReadState.NotInstalled:
                unverified.Add("Microsoft Defender's status classes don't exist, and it is unknown whether this Windows edition includes Defender.");
                return false;

            case DefenderReadState.ServiceNotRunning when thirdParty == true:
                return true; // another antivirus took over: expected

            case DefenderReadState.ServiceNotRunning when s.DefenderExpected == true:
                findings.Add(Tamper(DefenderRuleIds.DefenderServiceStopped, thirdParty == false ? Verdict.Malicious : Verdict.Suspicious,
                    "Microsoft Defender's service isn't running"
                    + (thirdParty == false
                        ? " and no other antivirus is active, so this PC is unprotected."
                        : ", and it couldn't be confirmed that another antivirus is active.")));
                return false;

            case DefenderReadState.ServiceNotRunning:
                unverified.Add("Microsoft Defender's service isn't running; it couldn't be confirmed whether another antivirus protects this PC.");
                return false;

            default:
                unverified.Add($"Microsoft Defender's status couldn't be read ({s.ComputerStatusRead}).");
                return false;
        }
    }

    private static void CheckProtection(DefenderStatusSnapshot s, bool? thirdParty, List<DefenderFinding> findings, List<string> unverified)
    {
        bool statusKnown = s.ComputerStatusRead == DefenderReadState.Available;
        bool prefsKnown = s.PreferenceRead == DefenderReadState.Available;
        if (!statusKnown && !prefsKnown)
        {
            return; // nothing to judge; the read state was reported by CheckPresence
        }

        var p = statusKnown ? s.Protection : DefenderProtectionState.Unknown;
        var pref = prefsKnown ? s.Preferences : DefenderPreferenceFlags.Unknown;

        if (statusKnown && p.RunningMode is DefenderRunningMode.Passive or DefenderRunningMode.SideBySidePassive or DefenderRunningMode.EdrBlock)
        {
            if (thirdParty == false)
            {
                findings.Add(Protection(DefenderRuleIds.PassiveWithoutOtherAntivirus, Verdict.Suspicious,
                    $"Microsoft Defender is in passive mode ({p.RunningMode}), but no other antivirus is active, so this PC may be unprotected."));
            }
            else if (thirdParty is null)
            {
                unverified.Add("Microsoft Defender is in passive mode; it couldn't be confirmed that another antivirus is active.");
            }

            return; // components are expected to be off in passive mode
        }

        var off = new List<(string Rule, Verdict Verdict, string Reason)>();
        if (p.AntivirusEnabled == false || p.AntimalwareServiceEnabled == false)
        {
            off.Add((DefenderRuleIds.AntivirusOff, Verdict.Malicious, "Microsoft Defender Antivirus is turned off."));
        }

        Component(off, DefenderRuleIds.RealTimeProtectionOff, "Real-time protection", p.RealTimeProtectionEnabled, pref.RealtimeMonitoringDisabled,
            Verdict.Malicious);
        if (p.RealTimeProtectionEnabled != false && p.OnAccessProtectionEnabled == false)
        {
            off.Add((DefenderRuleIds.RealTimeProtectionOff, Verdict.Suspicious, "On-access scanning (part of real-time protection) is off."));
        }

        Component(off, DefenderRuleIds.BehaviorMonitoringOff, "Behaviour monitoring", p.BehaviorMonitorEnabled, pref.BehaviorMonitoringDisabled,
            Verdict.Suspicious);
        Component(off, DefenderRuleIds.IoavProtectionOff, "Scanning of downloaded files and attachments (IOAV)", p.IoavProtectionEnabled,
            pref.IoavProtectionDisabled, Verdict.Suspicious);
        if (p.TamperProtected == false)
        {
            off.Add((DefenderRuleIds.TamperProtectionOff, Verdict.Suspicious,
                "Tamper protection is off, so programs with admin rights can change Defender's settings."));
        }

        if (off.Count == 0)
        {
            if (statusKnown && p.RealTimeProtectionEnabled is null && p.AntivirusEnabled is null)
            {
                unverified.Add("Microsoft Defender's protection state couldn't be read (the values are missing).");
            }

            return;
        }

        switch (thirdParty)
        {
            case true:
                return; // another antivirus is active: Defender's components being off is expected
            case false:
                foreach (var (rule, verdict, reason) in off)
                {
                    findings.Add(Protection(rule, verdict, reason + " No other antivirus is active."));
                }

                return;
            default:
                unverified.Add($"{off[0].Reason} It couldn't be confirmed whether another antivirus is active, so this may be expected.");
                return;
        }
    }

    private static void Component(List<(string, Verdict, string)> off, string rule, string name, bool? enabled, bool? disabledInPreferences,
        Verdict whenOff)
    {
        if (enabled == false)
        {
            off.Add((rule, whenOff, $"{name} is off."));
        }
        else if (disabledInPreferences == true)
        {
            off.Add((rule, Verdict.Suspicious, enabled == true
                ? $"{name} is set to off in Defender's settings (tamper protection is keeping it on)."
                : $"{name} is set to off in Defender's settings."));
        }
    }

    private static void CheckExclusions(DefenderStatusSnapshot s, List<DefenderFinding> findings, List<string> unverified, bool reportUnknownLists)
    {
        CheckList(s.Exclusions.Paths, DefenderExclusionKind.Path, "path", findings, unverified, reportUnknownLists);
        CheckList(s.Exclusions.Extensions, DefenderExclusionKind.Extension, "extension", findings, unverified, reportUnknownLists);
        CheckList(s.Exclusions.Processes, DefenderExclusionKind.Process, "process", findings, unverified, reportUnknownLists);
    }

    private static void CheckList(DefenderExclusionList list, DefenderExclusionKind kind, string noun, List<DefenderFinding> findings,
        List<string> unverified, bool reportUnknown)
    {
        switch (list.State)
        {
            case DefenderExclusionListState.Hidden:
                unverified.Add($"Defender's {noun} exclusions are hidden, so they couldn't be checked.");
                return;
            case DefenderExclusionListState.Unknown:
                if (reportUnknown)
                {
                    unverified.Add($"Defender's {noun} exclusions couldn't be read, so they weren't checked.");
                }

                return;
        }

        string from = list.Source == DefenderExclusionSource.Registry ? " (read from the registry)" : string.Empty;
        if (list.Truncated)
        {
            bool padded = list.TotalCount > DefenderExclusionList.MaxItems;
            findings.Add(new DefenderFinding(DefenderRuleIds.ExclusionListTruncated, Verdict.Suspicious, DefenderFindingKind.TamperSign,
                (padded
                    ? $"Defender's {noun} exclusion list has {list.TotalCount} entries{from}. Normal setups have a handful; a padded list can hide a harmful entry."
                    : $"Defender's {noun} exclusion list has an entry longer than {DefenderExclusionList.MaxItemLength} characters{from}, which is unusual.")
                + " " + DefenderFinding.UserDecides, exclusionSource: list.Source));
            if (padded)
            {
                unverified.Add($"{list.TotalCount - list.Items.Count} of {list.TotalCount} {noun} exclusions weren't checked (the list is too long).");
            }
        }

        var flagged = new List<DefenderFinding>();
        foreach (var item in list.Items)
        {
            var finding = kind switch
            {
                DefenderExclusionKind.Path => JudgePath(item, from, list.Source, unverified),
                DefenderExclusionKind.Extension => JudgeExtension(item, from, list.Source),
                DefenderExclusionKind.Process => JudgeProcess(item, from, list.Source, unverified),
                _ => null,
            };

            if (finding is not null)
            {
                flagged.Add(finding);
            }
        }

        var ordered = flagged.OrderByDescending(f => f.Verdict).ToList(); // stable: list order within a verdict
        findings.AddRange(ordered.Take(MaxExclusionFindingsPerList));
        if (ordered.Count > MaxExclusionFindingsPerList)
        {
            var rest = ordered.Skip(MaxExclusionFindingsPerList).ToList();
            findings.Add(new DefenderFinding(DefenderRuleIds.MoreFlaggedExclusions, rest.Max(f => f.Verdict), DefenderFindingKind.Exclusion,
                $"{rest.Count} more risky {noun} exclusions{from} aren't listed one by one. " + DefenderFinding.UserDecides,
                kind, exclusionSource: list.Source));
        }
    }

    private static DefenderFinding? JudgePath(string item, string from, DefenderExclusionSource source, List<string> unverified)
    {
        var c = DefenderExclusionPatterns.ClassifyPath(item);
        string d = DefenderExclusionList.ForDisplay(item);
        if (c.UnknownVariable && c.Breadth == ExclusionBreadth.None)
        {
            unverified.Add($"The path exclusion \"{d}\" uses an unknown environment variable, so it couldn't be judged.");
            return null;
        }

        var (rule, verdict, text) = c.Breadth switch
        {
            ExclusionBreadth.Everything => (DefenderRuleIds.PathExcludesEverything, Verdict.Malicious,
                $"The path exclusion \"{d}\"{from} covers {c.Label}, so Defender scans nothing there."),
            ExclusionBreadth.Broad => (DefenderRuleIds.PathBroadUserFolder, Verdict.Malicious,
                $"The path exclusion \"{d}\"{from} covers {c.Label}, where downloaded and dropped programs live, so malware there isn't scanned."),
            ExclusionBreadth.SystemFolder => (DefenderRuleIds.PathSystemFolder, Verdict.Suspicious,
                $"The path exclusion \"{d}\"{from} covers {c.Label}, so programs placed there aren't scanned."),
            ExclusionBreadth.UserFolder => (DefenderRuleIds.PathInUserFolder, Verdict.Suspicious,
                $"The path exclusion \"{d}\"{from} is {c.Label}, so files saved there aren't scanned. Developer and app folders can be legitimate."),
            _ => (string.Empty, Verdict.Clean, string.Empty),
        };

        return verdict == Verdict.Clean ? null : Exclusion(rule, verdict, text, DefenderExclusionKind.Path, item, source);
    }

    private static DefenderFinding? JudgeExtension(string item, string from, DefenderExclusionSource source)
    {
        if (DefenderExclusionPatterns.NormalizeExtension(item) is not { } ext)
        {
            return null;
        }

        string d = DefenderExclusionList.ForDisplay(item);
        if (DefenderExclusionPatterns.ExtensionCoversEverything(ext))
        {
            return Exclusion(DefenderRuleIds.ExtensionExcludesEverything, Verdict.Malicious,
                $"The extension exclusion \"{d}\"{from} covers every file type, so Defender scans nothing.", DefenderExclusionKind.Extension, item, source);
        }

        return DefenderExclusionPatterns.RiskyExtensionCovered(ext) is { } risky
            ? Exclusion(DefenderRuleIds.ExtensionRisky, Verdict.Malicious,
                $"The extension exclusion \"{d}\"{from} covers {risky} files, which Windows runs as programs or scripts, so no such file is scanned anywhere.",
                DefenderExclusionKind.Extension, item, source)
            : null;
    }

    private static DefenderFinding? JudgeProcess(string item, string from, DefenderExclusionSource source, List<string> unverified)
    {
        var (name, hasFolder) = DefenderExclusionPatterns.SplitProcess(item);
        string d = DefenderExclusionList.ForDisplay(item);
        bool allNames = DefenderExclusionPatterns.ProcessNameCoversEverything(name);
        if (allNames && !hasFolder)
        {
            return Exclusion(DefenderRuleIds.ProcessExcludesEverything, Verdict.Malicious,
                $"The process exclusion \"{d}\"{from} covers every process, so Defender scans no file any program opens.",
                DefenderExclusionKind.Process, item, source);
        }

        if (!allNames && DefenderExclusionPatterns.InterpreterCovered(name) is { } interpreter)
        {
            return Exclusion(DefenderRuleIds.ProcessInterpreter, Verdict.Malicious,
                $"The process exclusion \"{d}\"{from} covers {interpreter}, so scripts and DLLs it opens, including an attacker's, aren't scanned.",
                DefenderExclusionKind.Process, item, source);
        }

        if (!hasFolder)
        {
            return null;
        }

        var c = DefenderExclusionPatterns.ClassifyPath(item);
        if (c.UnknownVariable && c.Breadth == ExclusionBreadth.None)
        {
            unverified.Add($"The process exclusion \"{d}\" uses an unknown environment variable, so it couldn't be judged.");
            return null;
        }

        return c.Breadth switch
        {
            ExclusionBreadth.Everything or ExclusionBreadth.Broad => Exclusion(DefenderRuleIds.ProcessBroadFolder, Verdict.Malicious,
                $"The process exclusion \"{d}\"{from} covers every program in {c.Label}, so files they open aren't scanned.",
                DefenderExclusionKind.Process, item, source),
            ExclusionBreadth.UserFolder => Exclusion(DefenderRuleIds.ProcessInUserFolder, Verdict.Suspicious,
                $"The process exclusion \"{d}\"{from} is a program in {c.Label}, so files it opens aren't scanned. Some apps install there legitimately.",
                DefenderExclusionKind.Process, item, source),
            _ => null,
        };
    }

    private static DefenderFinding Exclusion(string rule, Verdict verdict, string text, DefenderExclusionKind kind, string item,
        DefenderExclusionSource source) =>
        new(rule, verdict, DefenderFindingKind.Exclusion, text + " " + DefenderFinding.UserDecides, kind, item, source);

    private static DefenderFinding Protection(string rule, Verdict verdict, string text) =>
        new(rule, verdict, DefenderFindingKind.ProtectionDisabled, text + " " + DefenderFinding.UserDecides);

    private static DefenderFinding Tamper(string rule, Verdict verdict, string text) =>
        new(rule, verdict, DefenderFindingKind.TamperSign, text + " " + DefenderFinding.UserDecides);
}
