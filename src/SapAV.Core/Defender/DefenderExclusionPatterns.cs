using System.Collections.Frozen;
using System.Text;
using SapAV.Core.Heuristics;

namespace SapAV.Core.Defender;

/// <summary>How much of the file system an exclusion path (or an excluded process's folder) covers, worst last.</summary>
public enum ExclusionBreadth
{
    /// <summary>Nothing the rules flag (a program folder, a network share, an unrecognised path, a documented default).</summary>
    None,

    /// <summary>Inside a folder standard users can write to (a user profile, Temp, the Recycle Bin), but narrow.</summary>
    UserFolder,

    /// <summary>A whole system folder (Windows, System32, Program Files).</summary>
    SystemFolder,

    /// <summary>A whole user-writable root: all profiles, one profile, AppData, Temp, Downloads, Public, ProgramData.</summary>
    Broad,

    /// <summary>A whole drive, or everything (<c>*</c>, <c>C:\</c>, <c>C:\*</c>).</summary>
    Everything,
}

/// <summary>The breadth of one exclusion path, with a short display label for the matched location.</summary>
/// <param name="UnknownVariable">The path uses an environment variable the rules don't know, so it couldn't be judged.</param>
public readonly record struct PathClassification(ExclusionBreadth Breadth, string Label, bool UnknownVariable = false)
{
    public static PathClassification None { get; } = new(ExclusionBreadth.None, string.Empty);
}

/// <summary>
/// Pure string classification of Defender exclusion entries (E5): paths, extensions and processes. No file-system access and no
/// use of this machine's environment, so the result is the same as SYSTEM, as a user, and in tests.
/// </summary>
/// <remarks>
/// <para><b>Paths</b> are normalized the way Windows would read them before matching: quotes and outer whitespace removed, <c>/</c>
/// as <c>\</c>; <c>\\?\</c>, <c>\??\</c>, <c>\\.\</c>, <c>\\?\UNC\</c>, volume-GUID and <c>\Device\HarddiskVolumeN</c> prefixes stripped;
/// <c>\\localhost\C$</c>-style admin shares read as the drive; repeated, trailing, <c>.</c> and <c>..</c> components resolved; trailing
/// dots/spaces of a component dropped. Known environment variables (<c>%TEMP%</c>, <c>%USERPROFILE%</c>, <c>%AppData%</c>, ...) map to
/// the folder they name for <b>any</b> user; an unknown variable is reported as "can't judge". Matching is by whole components,
/// case-insensitive, so <c>AppDataBackup</c> is not <c>AppData</c>.</para>
/// <para><b>Wildcards</b> are read worst-case: a trailing component starting with <c>*</c> (<c>*</c>, <c>*.*</c>, <c>*.exe</c>) covers its
/// whole folder, and a component with <c>*</c> / <c>?</c> (or an 8.3 short name such as <c>APPDAT~1</c>) matches every known folder name
/// it could match. So <c>C:\*</c> is the whole drive and <c>C:\Users\*\AppData</c> is every user's AppData.</para>
/// </remarks>
public static class DefenderExclusionPatterns
{
    /// <summary>Extensions whose exclusion lets programs and scripts skip scanning (Windows runs them directly).</summary>
    public static readonly FrozenSet<string> RiskyExtensions = FileNameRules.ExecutableExtensions
        .Concat(FileNameRules.ImageExtensions)
        .Concat([".psd1", ".msc", ".application", ".appref-ms", ".gadget", ".chm", ".xll", ".sct", ".wsc", ".ws", ".msix", ".appx", ".appxbundle", ".msixbundle"])
        .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Interpreters, script hosts, LOLBins and Windows host processes (name without extension, lower case): files they open
    /// include whatever script or DLL an attacker hands them, so excluding them switches scanning off for that payload.
    /// </summary>
    public static readonly FrozenSet<string> InterpreterProcesses = new[]
    {
        "powershell", "pwsh", "powershell_ise", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec",
        "installutil", "regasm", "regsvcs", "cmstp", "msxsl", "wmic", "forfiles", "explorer", "svchost", "dllhost",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private const string AnyUser = "<user>"; // '<' can't be in a Windows file name, so this never collides with a real component

    private static readonly FrozenDictionary<string, string> Variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["USERPROFILE"] = @"C:\Users\" + AnyUser,
        ["HOMEPATH"] = @"\Users\" + AnyUser,
        ["HOMEDRIVE"] = "C:",
        ["SYSTEMDRIVE"] = "C:",
        ["USERNAME"] = AnyUser,
        ["APPDATA"] = @"C:\Users\" + AnyUser + @"\AppData\Roaming",
        ["LOCALAPPDATA"] = @"C:\Users\" + AnyUser + @"\AppData\Local",
        ["TEMP"] = @"C:\Users\" + AnyUser + @"\AppData\Local\Temp",
        ["TMP"] = @"C:\Users\" + AnyUser + @"\AppData\Local\Temp",
        ["ONEDRIVE"] = @"C:\Users\" + AnyUser + @"\OneDrive",
        ["PUBLIC"] = @"C:\Users\Public",
        ["PROGRAMDATA"] = @"C:\ProgramData",
        ["ALLUSERSPROFILE"] = @"C:\ProgramData",
        ["SYSTEMROOT"] = @"C:\Windows",
        ["WINDIR"] = @"C:\Windows",
        ["PROGRAMFILES"] = @"C:\Program Files",
        ["PROGRAMW6432"] = @"C:\Program Files",
        ["PROGRAMFILES(X86)"] = @"C:\Program Files (x86)",
        ["COMMONPROGRAMFILES"] = @"C:\Program Files\Common Files",
        ["COMMONPROGRAMFILES(X86)"] = @"C:\Program Files (x86)\Common Files",
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private enum Match
    {
        Exact,
        Under,
    }

    private sealed record Template(string[] Parts, Match Match, ExclusionBreadth Breadth, string Label);

    private const string U = "\0u"; // a template component that matches any user name

    private static readonly Template[] Templates =
    [
        new(["Users"], Match.Exact, ExclusionBreadth.Broad, "every user profile"),
        new(["Users", U], Match.Exact, ExclusionBreadth.Broad, "a whole user profile or the Public folder"),
        new(["Users", U, "AppData"], Match.Exact, ExclusionBreadth.Broad, "a user's whole AppData folder"),
        new(["Users", U, "AppData", "Roaming"], Match.Exact, ExclusionBreadth.Broad, "a user's whole AppData\\Roaming folder"),
        new(["Users", U, "AppData", "Local"], Match.Exact, ExclusionBreadth.Broad, "a user's whole AppData\\Local folder"),
        new(["Users", U, "AppData", "LocalLow"], Match.Exact, ExclusionBreadth.Broad, "a user's whole AppData\\LocalLow folder"),
        new(["Users", U, "AppData", "Local", "Temp"], Match.Exact, ExclusionBreadth.Broad, "a user's whole Temp folder"),
        new(["Users", U, "Downloads"], Match.Exact, ExclusionBreadth.Broad, "a user's whole Downloads folder"),
        new(["ProgramData"], Match.Exact, ExclusionBreadth.Broad, "the whole ProgramData folder"),
        new(["Windows", "Temp"], Match.Exact, ExclusionBreadth.Broad, "the whole Windows Temp folder"),
        new(["Windows", "SystemTemp"], Match.Exact, ExclusionBreadth.Broad, "the whole Windows SystemTemp folder"),
        new(["Windows"], Match.Exact, ExclusionBreadth.SystemFolder, "the whole Windows folder"),
        new(["Windows", "System32"], Match.Exact, ExclusionBreadth.SystemFolder, "the whole System32 folder"),
        new(["Windows", "SysWOW64"], Match.Exact, ExclusionBreadth.SystemFolder, "the whole SysWOW64 folder"),
        new(["Program Files"], Match.Exact, ExclusionBreadth.SystemFolder, "the whole Program Files folder"),
        new(["Program Files (x86)"], Match.Exact, ExclusionBreadth.SystemFolder, "the whole Program Files (x86) folder"),
        new(["$Recycle.Bin"], Match.Exact, ExclusionBreadth.UserFolder, "the Recycle Bin"),
        new(["Users", U], Match.Under, ExclusionBreadth.UserFolder, "a folder inside a user profile (writable by that user)"),
        new(["Windows", "Temp"], Match.Under, ExclusionBreadth.UserFolder, "a folder inside the Windows Temp folder"),
        new(["Windows", "SystemTemp"], Match.Under, ExclusionBreadth.UserFolder, "a folder inside the Windows SystemTemp folder"),
        new(["$Recycle.Bin"], Match.Under, ExclusionBreadth.UserFolder, "a folder inside the Recycle Bin"),
    ];

    /// <summary>
    /// Microsoft-documented default exclusions (Hyper-V's recommended antivirus exclusions) that sit in a user-writable folder.
    /// Matched only for wildcard-free paths, exactly or below; they never lower a broader match.
    /// </summary>
    private static readonly string[][] DocumentedDefaults =
    [
        ["Users", "Public", "Documents", "Hyper-V", "Virtual Hard Disks"],
    ];

    /// <summary>Classifies an exclusion path (or an excluded process's full path). Never throws for odd input.</summary>
    public static PathClassification ClassifyPath(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (!TryNormalize(item, out var parts, out bool unknownVariable))
        {
            return unknownVariable ? PathClassification.None with { UnknownVariable = true } : PathClassification.None;
        }

        if (parts.Count == 0)
        {
            return new PathClassification(ExclusionBreadth.Everything, "an entire drive", unknownVariable);
        }

        var best = PathClassification.None;
        foreach (var template in Templates)
        {
            if (template.Breadth > best.Breadth && Matches(parts, template))
            {
                best = new PathClassification(template.Breadth, template.Label);
            }
        }

        if (best.Breadth == ExclusionBreadth.UserFolder && IsDocumentedDefault(parts))
        {
            best = PathClassification.None;
        }

        return best with { UnknownVariable = unknownVariable };
    }

    /// <summary>
    /// The extension an <c>ExclusionExtension</c> entry names, without leading <c>*</c> / <c>.</c> (empty = every file), or null when the
    /// entry is blank. Wildcards are kept.
    /// </summary>
    public static string? NormalizeExtension(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        string s = item.Trim().Trim('"').Trim().TrimEnd('.', ' ');
        if (s.Length == 0)
        {
            return null;
        }

        int start = 0;
        while (start < s.Length && s[start] is '*' or '.')
        {
            start++;
        }

        // "*" / "*.*" / ".*": every extension; "*.exe" / ".exe" / "exe": exe.
        return start == s.Length && s.Contains('*') ? string.Empty : s[start..];
    }

    /// <summary>True when an extension entry (normalized by <see cref="NormalizeExtension"/>) covers every file.</summary>
    public static bool ExtensionCoversEverything(string normalized) =>
        normalized.Length == 0 || normalized.All(c => c is '*' or '?');

    /// <summary>The risky extension an extension entry covers (wildcards matched worst-case), or null.</summary>
    public static string? RiskyExtensionCovered(string normalized)
    {
        ArgumentNullException.ThrowIfNull(normalized);
        if (normalized.Length == 0)
        {
            return null;
        }

        if (!IsWildcard(normalized))
        {
            return RiskyExtensions.Contains("." + normalized) ? "." + normalized.ToLowerInvariant() : null;
        }

        return RiskyExtensions.Order(StringComparer.Ordinal).FirstOrDefault(e => Glob(normalized, e[1..]));
    }

    /// <summary>
    /// The process name an <c>ExclusionProcess</c> entry names (its last component, without quotes), and whether it has a folder part.
    /// </summary>
    public static (string Name, bool HasFolder) SplitProcess(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        string s = item.Trim().Trim('"').Trim().Replace('/', '\\').TrimEnd('\\', ' ', '.');
        int slash = s.LastIndexOf('\\');
        return slash < 0 ? (s, false) : (s[(slash + 1)..], true);
    }

    /// <summary>True when a process name (from <see cref="SplitProcess"/>) is <c>*</c>, <c>*.*</c> or <c>*.exe</c>: every process.</summary>
    public static bool ProcessNameCoversEverything(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        string stem = StripProgramExtension(name);
        return stem.Length > 0 && stem.All(c => c is '*' or '?') && stem.Contains('*');
    }

    /// <summary>The interpreter / host a process name matches (wildcards matched worst-case, case-insensitive), or null.</summary>
    public static string? InterpreterCovered(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        string stem = StripProgramExtension(name);
        if (stem.Length == 0)
        {
            return null;
        }

        if (!IsWildcard(stem))
        {
            return InterpreterProcesses.Contains(stem) ? stem.ToLowerInvariant() + ".exe" : null;
        }

        return InterpreterProcesses.Order(StringComparer.Ordinal).FirstOrDefault(p => Glob(stem, p)) is { } hit ? hit + ".exe" : null;
    }

    private static string StripProgramExtension(string name)
    {
        string s = name.Trim().TrimEnd('.', ' ');
        foreach (var ext in (string[])[".exe", ".com", ".*"])
        {
            if (s.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                return s[..^ext.Length];
            }
        }

        return s;
    }

    private static bool IsDocumentedDefault(List<string> parts)
    {
        if (parts.Any(IsWildcard) || parts.Contains(AnyUser))
        {
            return false;
        }

        return DocumentedDefaults.Any(d => parts.Count >= d.Length && d.Select((p, i) => p.Equals(parts[i], StringComparison.OrdinalIgnoreCase)).All(x => x));
    }

    private static bool Matches(List<string> parts, Template template)
    {
        int n = template.Parts.Length;
        if (template.Match == Match.Exact ? parts.Count != n : parts.Count <= n)
        {
            return false;
        }

        for (int i = 0; i < n; i++)
        {
            if (!ComponentMatches(parts[i], template.Parts[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ComponentMatches(string part, string templatePart)
    {
        if (templatePart == U)
        {
            return true;
        }

        if (part == AnyUser)
        {
            return false;
        }

        return IsWildcard(part) ? Glob(part, templatePart) : part.Equals(templatePart, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsWildcard(string s) => s.AsSpan().ContainsAny('*', '?');

    /// <summary>
    /// Normalizes a path to its components below the drive (see the class remarks). False when it isn't a local absolute path
    /// (relative, a remote share) or uses an unknown variable.
    /// </summary>
    private static bool TryNormalize(string item, out List<string> parts, out bool unknownVariable)
    {
        parts = [];
        unknownVariable = false;
        string s = item.Trim().Trim('"').Trim().Replace('/', '\\');
        if (s.Length == 0)
        {
            return false;
        }

        s = ExpandVariables(s, ref unknownVariable);
        if (unknownVariable && s.StartsWith('%'))
        {
            return false; // the root itself is unknown
        }

        s = StripDevicePrefix(s);
        if (s.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // \\host\share\...: only a loopback admin share (\\localhost\C$) is local.
            var unc = s[2..].Split('\\', 3);
            if (unc.Length < 2 || !IsLoopback(unc[0]) || unc[1].Length != 2 || unc[1][1] != '$' || !char.IsAsciiLetter(unc[1][0]))
            {
                return false;
            }

            s = unc[1][0] + ":" + (unc.Length == 3 ? @"\" + unc[2] : string.Empty);
        }

        string rest;
        if (s.Length >= 2 && s[1] == ':' && (char.IsAsciiLetter(s[0]) || s[0] is '*' or '?'))
        {
            rest = s[2..];
        }
        else if (s[0] == '\\')
        {
            rest = s; // rooted on the current drive
        }
        else if (s == "*" || s.StartsWith(@"*\", StringComparison.Ordinal) || s == "*.*")
        {
            rest = s.Length <= 3 && !s.Contains('\\') ? string.Empty : s[2..]; // "*" or "*\..." : any drive
        }
        else
        {
            return false; // relative: not something the rules can place
        }

        foreach (var raw in rest.Split('\\'))
        {
            string part = raw.TrimEnd('.', ' ').TrimStart(' ');
            if (raw is "." or "")
            {
                continue;
            }

            if (raw == "..")
            {
                if (parts.Count > 0)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                continue;
            }

            if (part.Length == 0)
            {
                continue;
            }

            parts.Add(ShortNameAsWildcard(part));
        }

        // A trailing "*", "*.*" or "*.exe" covers its whole folder.
        while (parts.Count > 0 && parts[^1].StartsWith('*'))
        {
            parts.RemoveAt(parts.Count - 1);
        }

        return true;
    }

    /// <summary>An 8.3 short name (<c>APPDAT~1</c>, <c>PROGRA~2</c>) can be any long name with that start: read it as <c>APPDAT*</c>.</summary>
    private static string ShortNameAsWildcard(string part)
    {
        int tilde = part.IndexOf('~');
        if (tilde is < 1 or > 6 || tilde + 1 >= part.Length || !char.IsAsciiDigit(part[tilde + 1]))
        {
            return part;
        }

        int end = tilde + 1;
        while (end < part.Length && char.IsAsciiDigit(part[end]))
        {
            end++;
        }

        bool shortForm = end == part.Length || (part[end] == '.' && part.Length - end <= 4);
        return shortForm ? part[..tilde] + "*" : part;
    }

    private static string StripDevicePrefix(string s)
    {
        if (s.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + s[8..];
        }

        foreach (var prefix in (string[])[@"\\?\", @"\??\", @"\\.\"])
        {
            if (s.StartsWith(prefix, StringComparison.Ordinal))
            {
                s = s[prefix.Length..];
                break;
            }
        }

        if (s.StartsWith(@"GLOBALROOT\", StringComparison.OrdinalIgnoreCase))
        {
            s = s[11..];
        }

        // \Device\HarddiskVolume3\... or Volume{guid}\...: some local volume.
        string trimmed = s.TrimStart('\\');
        if (trimmed.StartsWith(@"Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase))
        {
            int slash = trimmed.IndexOf('\\', trimmed.StartsWith("Device", StringComparison.OrdinalIgnoreCase) ? 7 : 0);
            return "*:" + (slash < 0 ? string.Empty : trimmed[slash..]);
        }

        return s;
    }

    private static bool IsLoopback(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host is "127.0.0.1" or "::1" or "[::1]" or "." or "?";

    private static string ExpandVariables(string s, ref bool unknown)
    {
        if (!s.Contains('%'))
        {
            return s;
        }

        var sb = new StringBuilder(s.Length + 32);
        int i = 0;
        while (i < s.Length)
        {
            int open = s.IndexOf('%', i);
            int close = open < 0 ? -1 : s.IndexOf('%', open + 1);
            if (open < 0 || close < 0)
            {
                sb.Append(s, i, s.Length - i);
                break;
            }

            sb.Append(s, i, open - i);
            string name = s[(open + 1)..close];
            if (Variables.TryGetValue(name, out var value))
            {
                // A variable that names a rooted path is only a root at the start; elsewhere it stands for its last component.
                sb.Append(open == 0 || !value.Contains('\\') ? value : value[(value.LastIndexOf('\\') + 1)..]);
            }
            else
            {
                unknown = true;
                sb.Append(s, open, close - open + 1);
            }

            i = close + 1;
        }

        return sb.ToString();
    }

    /// <summary>Case-insensitive glob (<c>*</c>, <c>?</c>) of a whole string, linear-time with backtracking to the last star.</summary>
    internal static bool Glob(string pattern, string text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(text[t])))
            {
                p++;
                t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }
}
